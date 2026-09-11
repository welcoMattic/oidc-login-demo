<?php

namespace App\Tests\Functional;

use App\Tests\Oidc\FakeKeycloak;
use App\Tests\Oidc\TestKeys;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * Functional tests for OIDC login failure scenarios.
 */
class LoginFailureTest extends WebTestCase
{
    /**
     * Test that a tampered state parameter fails.
     */
    public function testTamperedStateParameter(): void
    {
        $client = static::createClient();
        $client->disableReboot();
        $client->disableReboot();

        /** @var FakeKeycloak $fakeKeycloak */
        $fakeKeycloak = static::getContainer()->get(FakeKeycloak::class);
        $fakeKeycloak->reset();

        // Start the login flow
        $client->request('GET', '/default/start');
        $location = $client->getResponse()->headers->get('Location');

        $parsedUrl = parse_url($location);
        parse_str($parsedUrl['query'] ?? '', $params);

        $fakeKeycloak->expectAuthorization($location);
        $authorizationCode = $fakeKeycloak->issueCode();

        // Try to complete the login with a tampered state
        $client->request('GET', '/default/callback?code=' . $authorizationCode . '&state=tampered-state');

        // Should redirect to failure path (absolute URL)
        $this->assertTrue($client->getResponse()->isRedirect());
        $this->assertStringStartsWith('http://localhost/', $client->getResponse()->headers->get('Location'));

        // Follow redirect to check error message
        $client->followRedirect();
        $content = html_entity_decode($client->getResponse()->getContent(), \ENT_QUOTES | \ENT_HTML5);

        // Should show error
        $this->assertStringContainsString('Invalid OIDC state parameter', $content);

        // Check that /default/account still redirects to provider (session is not authenticated)
        $client->request('GET', '/default/account');
        $this->assertTrue($client->getResponse()->isRedirect());
        $this->assertStringStartsWith(
            'https://keycloak.example.test/realms/demo/protocol/openid-connect/auth',
            $client->getResponse()->headers->get('Location'),
        );
    }

    /**
     * Test that a replayed callback fails.
     */
    public function testReplayedCallback(): void
    {
        $client = static::createClient();
        $client->disableReboot();

        /** @var FakeKeycloak $fakeKeycloak */
        $fakeKeycloak = static::getContainer()->get(FakeKeycloak::class);
        $fakeKeycloak->reset();

        // Start the login flow
        $client->request('GET', '/default/start');
        $location = $client->getResponse()->headers->get('Location');

        $parsedUrl = parse_url($location);
        parse_str($parsedUrl['query'] ?? '', $params);

        $fakeKeycloak->expectAuthorization($location);
        $authorizationCode = $fakeKeycloak->issueCode();

        // First login should succeed
        $client->request('GET', '/default/callback?code=' . $authorizationCode . '&state=' . $params['state']);
        $this->assertTrue($client->getResponse()->isRedirect());

        // Try the same code and state again - should fail
        $client->request('GET', '/default/callback?code=' . $authorizationCode . '&state=' . $params['state']);

        // Should redirect to failure path (absolute URL)
        $this->assertTrue($client->getResponse()->isRedirect());
        $this->assertStringStartsWith('http://localhost/', $client->getResponse()->headers->get('Location'));

        // Follow redirect to check error message
        $client->followRedirect();
        $content = html_entity_decode($client->getResponse()->getContent(), \ENT_QUOTES | \ENT_HTML5);

        // Should show state error (the state was already consumed)
        $this->assertStringContainsString('Invalid OIDC state parameter', $content);
    }

    /**
     * Test that an ID token signed with impostor key is rejected.
     */
    public function testImpostorSignatureRejection(): void
    {
        $client = static::createClient();
        $client->disableReboot();

        /** @var FakeKeycloak $fakeKeycloak */
        $fakeKeycloak = static::getContainer()->get(FakeKeycloak::class);
        $fakeKeycloak->reset();

        // Use impostor key for signing
        $impostorKey = TestKeys::impostorRsaKey()['private_key'];
        $fakeKeycloak->signWith($impostorKey);

        // Start the login flow
        $client->request('GET', '/default/start');
        $location = $client->getResponse()->headers->get('Location');

        $parsedUrl = parse_url($location);
        parse_str($parsedUrl['query'] ?? '', $params);

        $fakeKeycloak->expectAuthorization($location);
        $authorizationCode = $fakeKeycloak->issueCode();

        // Try to complete the login with impostor-signed token
        $client->request('GET', '/default/callback?code=' . $authorizationCode . '&state=' . $params['state']);

        // Should redirect to failure path (absolute URL)
        $this->assertTrue($client->getResponse()->isRedirect());
        $this->assertStringStartsWith('http://localhost/', $client->getResponse()->headers->get('Location'));

        // Follow redirect to check error message
        $client->followRedirect();
        $content = html_entity_decode($client->getResponse()->getContent(), \ENT_QUOTES | \ENT_HTML5);

        // Should show signature verification error
        $this->assertStringContainsString('The ID token signature is invalid', $content);
    }

    /**
     * Test that a nonce mismatch fails.
     */
    public function testNonceMismatch(): void
    {
        $client = static::createClient();
        $client->disableReboot();

        /** @var FakeKeycloak $fakeKeycloak */
        $fakeKeycloak = static::getContainer()->get(FakeKeycloak::class);
        $fakeKeycloak->reset();

        // Start the login flow
        $client->request('GET', '/default/start');
        $location = $client->getResponse()->headers->get('Location');

        $parsedUrl = parse_url($location);
        parse_str($parsedUrl['query'] ?? '', $params);

        $originalNonce = $params['nonce'];

        $fakeKeycloak->expectAuthorization($location);

        // Issue a code but set a different nonce for the token
        $authorizationCode = $fakeKeycloak->issueCode();
        $fakeKeycloak->withNonce('different-nonce-' . bin2hex(random_bytes(8)));

        // Try to complete the login - nonce should mismatch
        $client->request('GET', '/default/callback?code=' . $authorizationCode . '&state=' . $params['state']);

        // Should redirect to failure path (absolute URL)
        $this->assertTrue($client->getResponse()->isRedirect());
        $this->assertStringStartsWith('http://localhost/', $client->getResponse()->headers->get('Location'));

        // Follow redirect to check error message
        $client->followRedirect();
        $content = html_entity_decode($client->getResponse()->getContent(), \ENT_QUOTES | \ENT_HTML5);

        // Should show nonce error
        $this->assertStringContainsString('ID token nonce does not match', $content);
    }

    /**
     * Test that a provider error callback is handled correctly.
     */
    public function testProviderErrorCallback(): void
    {
        $client = static::createClient();
        $client->disableReboot();

        // the state is checked before the provider error is read, so that an attacker cannot
        // plant an error_description in the session: the error has to come back with a real state
        $client->request('GET', '/default/start');
        parse_str(parse_url($client->getResponse()->headers->get('Location'), \PHP_URL_QUERY) ?? '', $params);

        $client->request(
            'GET',
            '/default/callback?error=access_denied&error_description=User+denied+access&state=' . $params['state'],
        );

        // Should redirect to failure path (absolute URL)
        $this->assertTrue($client->getResponse()->isRedirect());
        $this->assertStringStartsWith('http://localhost/', $client->getResponse()->headers->get('Location'));

        // Follow redirect to check error message
        $client->followRedirect();
        $content = html_entity_decode($client->getResponse()->getContent(), \ENT_QUOTES | \ENT_HTML5);

        // Should show provider error
        $this->assertStringContainsString('OIDC provider returned an error', $content);
        $this->assertStringContainsString('User denied access', $content);
    }

    /**
     * Test that UserInfo sub mismatch fails.
     */
    public function testUserInfoSubMismatch(): void
    {
        $client = static::createClient();
        $client->disableReboot();

        /** @var FakeKeycloak $fakeKeycloak */
        $fakeKeycloak = static::getContainer()->get(FakeKeycloak::class);
        $fakeKeycloak->reset();

        // Start the login flow
        $client->request('GET', '/default/start');
        $location = $client->getResponse()->headers->get('Location');

        $parsedUrl = parse_url($location);
        parse_str($parsedUrl['query'] ?? '', $params);

        $fakeKeycloak->expectAuthorization($location);
        $authorizationCode = $fakeKeycloak->issueCode();

        // Set different sub for UserInfo than what's in ID token
        $fakeKeycloak->withUserInfoSub('22222222-2222-4222-8222-222222222222');

        // Complete the login
        $client->request('GET', '/default/callback?code=' . $authorizationCode . '&state=' . $params['state']);

        // Should redirect to failure path (absolute URL)
        $this->assertTrue($client->getResponse()->isRedirect());
        $this->assertStringStartsWith('http://localhost/', $client->getResponse()->headers->get('Location'));

        // Follow redirect to check error message
        $client->followRedirect();
        $content = html_entity_decode($client->getResponse()->getContent(), \ENT_QUOTES | \ENT_HTML5);

        // Should show sub mismatch error
        $this->assertStringContainsString(
            'The "sub" claim from the UserInfo endpoint does not match the ID token',
            $content,
        );
    }

    /**
     * Test that strict scenario fails without auth_time when max_age is set.
     */
    public function testStrictScenarioMissingAuthTime(): void
    {
        $client = static::createClient();
        $client->disableReboot();

        /** @var FakeKeycloak $fakeKeycloak */
        $fakeKeycloak = static::getContainer()->get(FakeKeycloak::class);
        $fakeKeycloak->reset();

        // Start the login flow for strict scenario
        $client->request('GET', '/strict/start');
        $location = $client->getResponse()->headers->get('Location');

        $parsedUrl = parse_url($location);
        parse_str($parsedUrl['query'] ?? '', $params);

        $fakeKeycloak->expectAuthorization($location);
        $authorizationCode = $fakeKeycloak->issueCode();

        // Set to omit auth_time from ID token
        $fakeKeycloak->withoutAuthTime();

        // Complete the login
        $client->request('GET', '/strict/callback?code=' . $authorizationCode . '&state=' . $params['state']);

        // Should redirect to failure path (absolute URL)
        $this->assertTrue($client->getResponse()->isRedirect());
        $this->assertStringStartsWith('http://localhost/', $client->getResponse()->headers->get('Location'));

        // Follow redirect to check error message
        $client->followRedirect();
        $content = html_entity_decode($client->getResponse()->getContent(), \ENT_QUOTES | \ENT_HTML5);

        // Should show missing auth_time error
        $this->assertStringContainsString(
            'ID token is missing the "auth_time" claim required when "max_age" is requested',
            $content,
        );
    }

    /**
     * Test that email scenario fails when email claim is missing.
     */
    public function testEmailScenarioMissingEmailClaim(): void
    {
        $client = static::createClient();
        $client->disableReboot();

        /** @var FakeKeycloak $fakeKeycloak */
        $fakeKeycloak = static::getContainer()->get(FakeKeycloak::class);
        $fakeKeycloak->reset();

        // Start the login flow for email scenario
        $client->request('GET', '/email/start');
        $location = $client->getResponse()->headers->get('Location');

        $parsedUrl = parse_url($location);
        parse_str($parsedUrl['query'] ?? '', $params);

        $fakeKeycloak->expectAuthorization($location);
        $authorizationCode = $fakeKeycloak->issueCode();

        // Remove email claim from ID token and UserInfo
        $fakeKeycloak->withoutClaimInIdToken('email');
        $fakeKeycloak->asUser('11111111-1111-4111-8111-111111111111', 'alice', '', []);

        // Complete the login
        $client->request('GET', '/email/callback?code=' . $authorizationCode . '&state=' . $params['state']);

        // Should redirect to failure path (absolute URL)
        $this->assertTrue($client->getResponse()->isRedirect());
        $this->assertStringStartsWith('http://localhost/', $client->getResponse()->headers->get('Location'));

        // Follow redirect to check error message
        $client->followRedirect();
        $content = html_entity_decode($client->getResponse()->getContent(), \ENT_QUOTES | \ENT_HTML5);

        // Should show missing identifier claim error
        $this->assertStringContainsString('The "email" claim is missing or invalid in the OIDC response', $content);
    }
}
