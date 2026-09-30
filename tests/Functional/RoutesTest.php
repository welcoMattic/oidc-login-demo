<?php

namespace App\Tests\Functional;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * Functional tests for route configuration.
 */
class RoutesTest extends WebTestCase
{
    /**
     * Test that all OIDC callback and start routes are properly defined.
     */
    public function testOidcRoutesAreDefined(): void
    {
        $client = static::createClient();
        $client->disableReboot();

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
            'refresh',
            'secretjwt',
            'privatekeyjwt',
            'reauth',
            'hint',
        ];

        foreach ($firewalls as $firewall) {
            // Test callback route
            $client->request('GET', '/' . $firewall . '/callback');

            // Should not be a 404 - the route exists
            $statusCode = $client->getResponse()->getStatusCode();
            $this->assertNotEquals(404, $statusCode, "Callback route for {$firewall} should exist");
        }

        // Test callback scenario's custom route
        $client->request('GET', '/callback/return-from-keycloak');
        $statusCode = $client->getResponse()->getStatusCode();
        $this->assertNotEquals(404, $statusCode, 'Custom callback route for callback scenario should exist');
    }

    /**
     * Test that the home page lists all ten "Log in" links pointing to the start routes.
     */
    public function testHomePageListsAllLoginLinks(): void
    {
        $client = static::createClient();
        $client->disableReboot();
        $client->request('GET', '/');

        $this->assertEquals(200, $client->getResponse()->getStatusCode());

        $content = $client->getResponse()->getContent();

        // Check that all ten login links are present
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
            $startPath = '/' . $firewall . '/start';
            $this->assertStringContainsString(
                $startPath,
                $content,
                "Home page should contain login link for {$firewall}",
            );

            // Also check that the link text contains the scenario title
            $scenarioTitles = [
                'default' => 'Default',
                'basic' => 'Basic Auth',
                'public' => 'Public Client',
                'strict' => 'Strict Validation',
                'es256' => 'ES256 Signature',
                'plain' => 'Plain PKCE',
                'roles' => 'Role Mapping',
                'email' => 'Identifier from another claim',
                'idtoken' => 'Claims from the ID token',
                'callback' => 'Custom callback route',
            ];

            $title = $scenarioTitles[$firewall];
            $this->assertStringContainsString($title, $content, "Home page should contain title for {$firewall}");
        }
    }

    /**
     * Test that account routes are protected and require authentication.
     */
    public function testAccountRoutesAreProtected(): void
    {
        $client = static::createClient();
        $client->disableReboot();

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
            'refresh',
            'secretjwt',
            'privatekeyjwt',
            'reauth',
            'hint',
        ];

        foreach ($firewalls as $firewall) {
            $client->request('GET', '/' . $firewall . '/account');

            // Should redirect to authorization endpoint (not 200)
            $this->assertTrue(
                $client->getResponse()->isRedirect(),
                "Account route for {$firewall} should require authentication",
            );
            $location = $client->getResponse()->headers->get('Location');
            $this->assertStringStartsWith(
                'https://keycloak.example.test/realms/demo/protocol/openid-connect/auth',
                $location,
                "Unauthenticated access to {$firewall} account should redirect to auth",
            );
        }
    }

    /**
     * Test that the routes for start and callback are correctly named.
     */
    public function testRouteNames(): void
    {
        $client = static::createClient();
        $client->disableReboot();

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
            'refresh',
            'secretjwt',
            'privatekeyjwt',
            'reauth',
            'hint',
        ];

        $router = static::getContainer()->get('router');

        foreach ($firewalls as $firewall) {
            // Check callback route
            $callbackRouteName = '_oidc_login_callback_' . $firewall;
            $callbackRoute = $router->getRouteCollection()->get($callbackRouteName);

            $this->assertNotNull($callbackRoute, "Callback route {$callbackRouteName} should exist");
            $this->assertEquals(
                '/' . $firewall . '/callback',
                $callbackRoute->getPath(),
                "Callback route {$callbackRouteName} should have path /{$firewall}/callback",
            );

            // Check start route
            $startRouteName = '_oidc_login_start_' . $firewall;
            $startRoute = $router->getRouteCollection()->get($startRouteName);

            $this->assertNotNull($startRoute, "Start route {$startRouteName} should exist");
            $this->assertEquals(
                '/' . $firewall . '/start',
                $startRoute->getPath(),
                "Start route {$startRouteName} should have path /{$firewall}/start",
            );
        }

        // For callback scenario, the loader should NOT declare a callback route (check_path is a route name)
        $callbackCallbackRoute = $router->getRouteCollection()->get('_oidc_login_callback_callback');
        $this->assertNull(
            $callbackCallbackRoute,
            'Callback route _oidc_login_callback_callback should NOT exist (check_path is a route name)',
        );

        // But it should have a start route
        $callbackStartRoute = $router->getRouteCollection()->get('_oidc_login_start_callback');
        $this->assertNotNull($callbackStartRoute, 'Start route _oidc_login_start_callback should exist');
        $this->assertEquals(
            '/callback/start',
            $callbackStartRoute->getPath(),
            'Start route _oidc_login_start_callback should have path /callback/start',
        );

        // Check that the custom app_callback_return route exists
        $customCallbackRoute = $router->getRouteCollection()->get('app_callback_return');
        $this->assertNotNull($customCallbackRoute, 'Custom route app_callback_return should exist');
        $this->assertEquals(
            '/callback/return-from-keycloak',
            $customCallbackRoute->getPath(),
            'Custom route app_callback_return should have path /callback/return-from-keycloak',
        );

        // Check that it has no _controller default
        $defaults = $customCallbackRoute->getDefaults();
        $this->assertArrayNotHasKey(
            '_controller',
            $defaults,
            'Custom route app_callback_return should have no _controller default',
        );
    }

    /**
     * Test that the home page route exists and is accessible.
     */
    public function testHomePageRoute(): void
    {
        $client = static::createClient();
        $client->disableReboot();
        $client->request('GET', '/');

        $this->assertEquals(200, $client->getResponse()->getStatusCode());
    }
}
