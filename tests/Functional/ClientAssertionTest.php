<?php

namespace App\Tests\Functional;

use App\Tests\Oidc\FakeKeycloak;
use App\Tests\Oidc\OidcWebTestCase;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * The client_secret_jwt ("secretjwt") and private_key_jwt ("privatekeyjwt") firewalls: the
 * client authenticates at the token endpoint with a JWT it signs, and no secret travels.
 */
class ClientAssertionTest extends OidcWebTestCase
{
    /**
     * @return iterable<string, array{string, string, string, ?string}>
     */
    public static function assertionClientProvider(): iterable
    {
        // firewall, client_id, signature algorithm, kid of the key
        yield 'client_secret_jwt' => ['secretjwt', 'symfony-demo-jwt-test', 'HS256', null];
        yield 'private_key_jwt' => ['privatekeyjwt', 'symfony-demo-pkjwt-test', 'ES256', 'symfony-demo-client-test'];
    }

    #[DataProvider('assertionClientProvider')]
    public function testTheCodeIsExchangedWithAValidClientAssertion(
        string $firewall,
        string $clientId,
        string $algorithm,
        ?string $kid,
    ): void {
        $client = $this->createOidcClient();

        $this->logIn($client, $firewall);

        $fakeKeycloak = $this->fakeKeycloak();
        $this->assertSame([], $fakeKeycloak->tokenErrors());

        $tokenRequests = $fakeKeycloak->tokenRequests();
        $this->assertCount(1, $tokenRequests);
        $params = $tokenRequests[0]['params'];

        // the assertion replaces the secret: none travels, in the body or in a header
        $this->assertSame('authorization_code', $params['grant_type'] ?? null);
        $this->assertSame($clientId, $params['client_id'] ?? null);
        $this->assertArrayNotHasKey('client_secret', $params);
        $this->assertNull($tokenRequests[0]['authorization']);
        $this->assertSame(
            'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            $params['client_assertion_type'] ?? null,
        );

        $assertion = $params['client_assertion'] ?? '';
        $header = $this->jwtHeader($assertion);
        $claims = $this->jwtClaims($assertion);

        $this->assertSame($algorithm, $header['alg'] ?? null);
        if (null === $kid) {
            $this->assertArrayNotHasKey('kid', $header);
        } else {
            $this->assertSame($kid, $header['kid'] ?? null);
        }

        // RFC 7523, Section 3: the client is the issuer and the subject, the token endpoint the audience
        $this->assertSame($clientId, $claims['iss'] ?? null);
        $this->assertSame($clientId, $claims['sub'] ?? null);
        $this->assertSame(self::TOKEN_ENDPOINT, $claims['aud'] ?? null);
        $this->assertIsString($claims['jti'] ?? null);
        $this->assertNotSame('', $claims['jti']);

        // dated with the application clock, and valid for the "lifetime" of the firewall
        $now = $this->now();
        $this->assertSame($now, $claims['iat'] ?? null);
        $this->assertSame($now + 60, $claims['exp'] ?? null);

        // the session is open: the account page answers without going back to the provider
        $client->followRedirect();
        $this->assertResponseIsSuccessful();
        $this->assertStringContainsString(FakeKeycloak::DEFAULT_SUB, (string) $client->getResponse()->getContent());
        $this->assertSame(FakeKeycloak::DEFAULT_SUB, $this->securityToken()?->getUserIdentifier());

        // and neither the secret of client_secret_jwt nor the private key of private_key_jwt appears on it
        $content = (string) $client->getResponse()->getContent();
        $this->assertStringNotContainsString('symfony-demo-jwt-secret-test-at-least-32-bytes', $content);
        $this->assertStringNotContainsString('FBSPYCltL_mnBaVwmebaPrUajDSYyCXD5kwYrf7KJU8', $content);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function firewallProvider(): iterable
    {
        yield 'client_secret_jwt' => ['secretjwt'];
        yield 'private_key_jwt' => ['privatekeyjwt'];
    }

    /**
     * Each token request carries a new assertion: the "jti" is single use.
     */
    #[DataProvider('firewallProvider')]
    public function testEachLoginSignsANewAssertion(string $firewall): void
    {
        $client = $this->createOidcClient();

        $this->logIn($client, $firewall);
        $client->request('GET', '/' . $firewall . '/logout');
        $this->logIn($client, $firewall);

        $tokenRequests = $this->fakeKeycloak()->tokenRequests();
        $this->assertCount(2, $tokenRequests);
        $this->assertSame([], $this->fakeKeycloak()->tokenErrors());

        $first = $this->jwtClaims($tokenRequests[0]['params']['client_assertion'] ?? '');
        $second = $this->jwtClaims($tokenRequests[1]['params']['client_assertion'] ?? '');
        $this->assertIsString($first['jti'] ?? null);
        $this->assertNotSame($first['jti'], $second['jti'] ?? null);
    }

    /**
     * @return iterable<string, array{string, callable(FakeKeycloak): void, string}>
     */
    public static function rejectedAssertionProvider(): iterable
    {
        yield 'client_secret_jwt, the provider holds another secret' => [
            'secretjwt',
            static fn(FakeKeycloak $fake) => $fake->withRegisteredClientSecret(
                'another-secret-registered-at-the-provider-32-bytes',
            ),
            'invalid_client: Invalid client_assertion signature',
        ];

        yield 'private_key_jwt, the provider holds another public key' => [
            'privatekeyjwt',
            static fn(FakeKeycloak $fake) => $fake->withRegisteredClientKey(
                JWKFactory::createECKey('P-256', [
                    'kid' => 'symfony-demo-client-test',
                    'alg' => 'ES256',
                    'use' => 'sig',
                ])->toPublic(),
            ),
            'invalid_client: Invalid client_assertion signature',
        ];

        yield 'private_key_jwt, the provider knows the key under another kid' => [
            'privatekeyjwt',
            static fn(FakeKeycloak $fake) => $fake->withRegisteredClientKey(
                JWKFactory::createECKey('P-256', [
                    'kid' => 'rotated-key',
                    'alg' => 'ES256',
                    'use' => 'sig',
                ])->toPublic(),
            ),
            'invalid_client: Unknown client_assertion kid',
        ];
    }

    /**
     * An assertion the provider cannot verify fails the login: the token endpoint answers
     * "invalid_client", and the user ends on the failure path, not logged in.
     *
     * @param callable(FakeKeycloak): void $registerOtherCredentials
     */
    #[DataProvider('rejectedAssertionProvider')]
    public function testAnAssertionTheProviderCannotVerifyFailsTheLogin(
        string $firewall,
        callable $registerOtherCredentials,
        string $expectedError,
    ): void {
        $client = $this->createOidcClient();

        $registerOtherCredentials($this->fakeKeycloak());

        $client->request('GET', '/' . $firewall . '/start');
        $this->answerAuthorizationRequest($client);

        // the failure_path of the firewall
        $this->assertResponseRedirects('http://localhost/');
        $this->assertCount(1, $this->fakeKeycloak()->tokenRequests());
        $this->assertSame([$expectedError], $this->fakeKeycloak()->tokenErrors());
        $this->assertSame([], $this->fakeKeycloak()->tokenResponses());

        // no session was opened: the account page sends the user back to the provider
        $client->request('GET', '/' . $firewall . '/account');
        $this->authorizationRequest($client);
    }
}
