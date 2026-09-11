<?php

namespace App\Tests\Functional;

use App\Tests\Oidc\FakeKeycloak;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Security\Core\User\OidcUser;

/**
 * Functional tests for OIDC logout scenarios.
 */
class LogoutTest extends WebTestCase
{
    /**
     * Test that RP-Initiated Logout works with OidcEndSessionListener.
     */
    public function testRpInitiatedLogout(): void
    {
        $client = static::createClient();
        $client->disableReboot();

        /** @var FakeKeycloak $fakeKeycloak */
        $fakeKeycloak = static::getContainer()->get(FakeKeycloak::class);
        $fakeKeycloak->reset();

        // First, log in the user
        $client->request('GET', '/default/start');
        $location = $client->getResponse()->headers->get('Location');

        $parsedUrl = parse_url($location);
        parse_str($parsedUrl['query'] ?? '', $params);

        $fakeKeycloak->expectAuthorization($location);
        $authorizationCode = $fakeKeycloak->issueCode();

        $client->request('GET', '/default/callback?code=' . $authorizationCode . '&state=' . $params['state']);
        $client->followRedirect();

        // Now logout
        $client->request('GET', '/default/logout');

        // Should redirect to the end_session_endpoint
        $this->assertTrue($client->getResponse()->isRedirect());
        $logoutLocation = $client->getResponse()->headers->get('Location');

        $this->assertStringStartsWith(
            'https://keycloak.example.test/realms/demo/protocol/openid-connect/logout',
            $logoutLocation,
        );

        // Check that the URL contains the expected parameters
        $parsedLogoutUrl = parse_url($logoutLocation);
        parse_str($parsedLogoutUrl['query'] ?? '', $logoutParams);

        $this->assertArrayHasKey('id_token_hint', $logoutParams);
        $this->assertNotSame('', $logoutParams['id_token_hint']);

        $this->assertArrayHasKey('post_logout_redirect_uri', $logoutParams);
        $this->assertEquals('http://localhost/', $logoutParams['post_logout_redirect_uri']);

        // Now check that /default/account redirects to provider again (session is gone)
        $client->request('GET', '/default/account');
        $this->assertTrue($client->getResponse()->isRedirect());
        $this->assertStringStartsWith(
            'https://keycloak.example.test/realms/demo/protocol/openid-connect/auth',
            $client->getResponse()->headers->get('Location'),
        );
    }

    /**
     * Test that a user logged in without oidc_id_token attribute is logged out locally.
     */
    public function testLocalLogoutWithoutIdToken(): void
    {
        $client = static::createClient();
        $client->disableReboot();

        // Create a mock OidcUser without the id_token attribute
        $user = new OidcUser(
            userIdentifier: '11111111-1111-4111-8111-111111111111',
            sub: '11111111-1111-4111-8111-111111111111',
            preferredUsername: 'alice',
            email: 'alice@example.com',
        );

        // Manually login the user without the oidc_id_token attribute
        $client->loginUser($user, 'default', []);

        // Now logout
        $client->request('GET', '/default/logout');

        // Should redirect to / (local logout, no RP-Initiated Logout)
        $this->assertTrue($client->getResponse()->isRedirect());
        $this->assertStringStartsWith('http://localhost/', $client->getResponse()->headers->get('Location'));
    }

    /**
     * Test logout for a different firewall (basic).
     */
    public function testRpInitiatedLogoutForBasicFirewall(): void
    {
        $client = static::createClient();
        $client->disableReboot();

        /** @var FakeKeycloak $fakeKeycloak */
        $fakeKeycloak = static::getContainer()->get(FakeKeycloak::class);
        $fakeKeycloak->reset();

        // Log in with basic firewall
        $client->request('GET', '/basic/start');
        $location = $client->getResponse()->headers->get('Location');

        $parsedUrl = parse_url($location);
        parse_str($parsedUrl['query'] ?? '', $params);

        $fakeKeycloak->expectAuthorization($location);
        $authorizationCode = $fakeKeycloak->issueCode();

        $client->request('GET', '/basic/callback?code=' . $authorizationCode . '&state=' . $params['state']);
        $client->followRedirect();

        // Now logout
        $client->request('GET', '/basic/logout');

        // Should redirect to the end_session_endpoint
        $this->assertTrue($client->getResponse()->isRedirect());
        $logoutLocation = $client->getResponse()->headers->get('Location');

        $this->assertStringStartsWith(
            'https://keycloak.example.test/realms/demo/protocol/openid-connect/logout',
            $logoutLocation,
        );

        // Check that the URL contains the expected parameters
        $parsedLogoutUrl = parse_url($logoutLocation);
        parse_str($parsedLogoutUrl['query'] ?? '', $logoutParams);

        $this->assertArrayHasKey('id_token_hint', $logoutParams);
        $this->assertNotSame('', $logoutParams['id_token_hint']);

        $this->assertArrayHasKey('post_logout_redirect_uri', $logoutParams);
        $this->assertEquals('http://localhost/', $logoutParams['post_logout_redirect_uri']);
    }

    /**
     * Test that all firewalls support RP-Initiated Logout.
     */
    public function testAllFirewallsSupportRpInitiatedLogout(): void
    {
        $firewalls = [
            'default',
            'basic',
            'public',
            'strict',
            'es256',
            'plain',
            'roles',
            'email',
            'idtoken',
            'callback',
        ];

        foreach ($firewalls as $firewall) {
            // one kernel per firewall: WebTestCase refuses to boot a second kernel otherwise
            static::ensureKernelShutdown();
            $client = static::createClient();
            $client->disableReboot();

            /** @var FakeKeycloak $fakeKeycloak */
            $fakeKeycloak = static::getContainer()->get(FakeKeycloak::class);
            $fakeKeycloak->reset();

            // Log in
            $client->request('GET', '/' . $firewall . '/start');
            $location = $client->getResponse()->headers->get('Location');

            $parsedUrl = parse_url($location);
            parse_str($parsedUrl['query'] ?? '', $params);

            $fakeKeycloak->expectAuthorization($location);
            $authorizationCode = $fakeKeycloak->issueCode();

            $callbackPath = parse_url($params['redirect_uri'], PHP_URL_PATH);
            $client->request('GET', $callbackPath . '?code=' . $authorizationCode . '&state=' . $params['state']);
            $client->followRedirect();

            // Now logout
            $client->request('GET', '/' . $firewall . '/logout');

            // Should redirect to the end_session_endpoint
            $this->assertTrue(
                $client->getResponse()->isRedirect(),
                "Firewall {$firewall} should redirect to end_session_endpoint",
            );
            $logoutLocation = $client->getResponse()->headers->get('Location');

            $this->assertStringStartsWith(
                'https://keycloak.example.test/realms/demo/protocol/openid-connect/logout',
                $logoutLocation,
                "Firewall {$firewall} should redirect to end_session_endpoint",
            );

            // Check that the URL contains the expected parameters
            $parsedLogoutUrl = parse_url($logoutLocation);
            parse_str($parsedLogoutUrl['query'] ?? '', $logoutParams);

            $this->assertArrayHasKey(
                'id_token_hint',
                $logoutParams,
                "Firewall {$firewall} should include id_token_hint",
            );
            $this->assertNotSame(
                '',
                $logoutParams['id_token_hint'],
                "Firewall {$firewall} should include non-empty id_token_hint",
            );

            $this->assertArrayHasKey(
                'post_logout_redirect_uri',
                $logoutParams,
                "Firewall {$firewall} should include post_logout_redirect_uri",
            );
            $this->assertEquals(
                'http://localhost/',
                $logoutParams['post_logout_redirect_uri'],
                "Firewall {$firewall} should include correct post_logout_redirect_uri",
            );
        }
    }
}
