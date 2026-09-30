<?php

namespace App\Tests\Oidc;

use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

/**
 * Drives the login flow of an oidc_login firewall through the fake provider.
 *
 * The client runs with disableReboot(): the fake provider, the clock and the token storage
 * are then the ones of the kernel that handles every request of the test.
 */
abstract class OidcWebTestCase extends WebTestCase
{
    protected const AUTHORIZATION_ENDPOINT = 'https://keycloak.example.test/realms/demo/protocol/openid-connect/auth';
    protected const TOKEN_ENDPOINT = 'https://keycloak.example.test/realms/demo/protocol/openid-connect/token';

    protected function createOidcClient(): KernelBrowser
    {
        $client = static::createClient();
        $client->disableReboot();

        return $client;
    }

    protected function fakeKeycloak(): FakeKeycloak
    {
        $fakeKeycloak = static::getContainer()->get(FakeKeycloak::class);
        $this->assertInstanceOf(FakeKeycloak::class, $fakeKeycloak);

        return $fakeKeycloak;
    }

    /**
     * The clock of the application, frozen when the kernel booted (config/packages/test/clock.yaml).
     */
    protected function clock(): MockClock
    {
        $clock = static::getContainer()->get('clock');
        $this->assertInstanceOf(MockClock::class, $clock);

        return $clock;
    }

    protected function now(): int
    {
        return $this->clock()->now()->getTimestamp();
    }

    /**
     * The security token of the logged-in user, as the last request left it.
     */
    protected function securityToken(): ?TokenInterface
    {
        $tokenStorage = static::getContainer()->get('security.token_storage');
        $this->assertInstanceOf(TokenStorageInterface::class, $tokenStorage);

        return $tokenStorage->getToken();
    }

    protected function tokenAttribute(string $name): mixed
    {
        $token = $this->securityToken();
        $this->assertNotNull($token, 'No user is logged in.');
        $this->assertTrue($token->hasAttribute($name), sprintf('The security token has no "%s" attribute.', $name));

        return $token->getAttribute($name);
    }

    protected function idToken(): string
    {
        $attributes = $this->securityToken()?->getAttributes() ?? [];
        $this->assertIsString($attributes['oidc_id_token'] ?? null, 'The security token holds no ID token.');

        return $attributes['oidc_id_token'];
    }

    /**
     * Asserts that the last response redirects to the authorization endpoint, and returns the
     * parameters of the authorization request.
     *
     * @return array<array-key, mixed>
     */
    protected function authorizationRequest(KernelBrowser $client): array
    {
        $response = $client->getResponse();
        $this->assertTrue(
            $response->isRedirect(),
            'Expected a redirect to the provider, got ' . $response->getStatusCode(),
        );

        $location = (string) $response->headers->get('Location');
        $this->assertStringStartsWith(self::AUTHORIZATION_ENDPOINT . '?', $location);

        $params = [];
        parse_str((string) parse_url($location, \PHP_URL_QUERY), $params);

        return $params;
    }

    /**
     * Has the fake provider answer the authorization request the last response redirected to,
     * and sends the user back to the callback with the code it issued.
     */
    protected function answerAuthorizationRequest(KernelBrowser $client): void
    {
        $params = $this->authorizationRequest($client);

        $fakeKeycloak = $this->fakeKeycloak();
        $fakeKeycloak->expectAuthorization((string) $client->getResponse()->headers->get('Location'));
        $code = $fakeKeycloak->issueCode();

        $this->assertIsString($params['redirect_uri'] ?? null);
        $callbackPath = parse_url($params['redirect_uri'], \PHP_URL_PATH);
        $this->assertIsString($callbackPath);

        $client->request(
            'GET',
            $callbackPath . '?'
                . http_build_query([
                    'code' => $code,
                    'state' => $params['state'] ?? '',
                ]),
        );
    }

    /**
     * Logs in through the start route of the firewall, and lands on its default target path.
     */
    protected function logIn(KernelBrowser $client, string $firewall): void
    {
        $client->request('GET', '/' . $firewall . '/start');
        $this->answerAuthorizationRequest($client);

        $this->assertResponseRedirects('http://localhost/' . $firewall . '/account');
    }

    /**
     * The claims of a JWT, read without verifying it.
     *
     * @return array<array-key, mixed>
     */
    protected function jwtClaims(string $jwt): array
    {
        return $this->jwtPart($jwt, 1);
    }

    /**
     * The protected header of a JWT.
     *
     * @return array<array-key, mixed>
     */
    protected function jwtHeader(string $jwt): array
    {
        return $this->jwtPart($jwt, 0);
    }

    /**
     * @return array<array-key, mixed>
     */
    private function jwtPart(string $jwt, int $index): array
    {
        $parts = explode('.', $jwt);
        $this->assertCount(3, $parts, 'Not a compact JWS.');

        $json = base64_decode(strtr($parts[$index], '-_', '+/'), true);
        $this->assertIsString($json);

        /** @var array<array-key, mixed>|scalar|null $decoded */
        $decoded = json_decode($json, true, 512, \JSON_THROW_ON_ERROR);
        $this->assertIsArray($decoded);

        return $decoded;
    }
}
