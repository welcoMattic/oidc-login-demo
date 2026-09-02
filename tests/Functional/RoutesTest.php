<?php

namespace App\Tests\Functional;

use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
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
        
        $firewalls = ['default', 'basic', 'public', 'strict', 'es256', 'plain', 'roles', 'email', 'idtoken'];
        
        foreach ($firewalls as $firewall) {
            // Test callback route
            $client->request('GET', '/' . $firewall . '/callback');
            
            // Should not be a 404 - the route exists
            $statusCode = $client->getResponse()->getStatusCode();
            $this->assertNotEquals(404, $statusCode, "Callback route for $firewall should exist");
        }
    }

    /**
     * Test that the home page lists all nine "Log in" links pointing to the start routes.
     */
    public function testHomePageListsAllLoginLinks(): void
    {
        $client = static::createClient();
        $client->disableReboot();
        $client->request('GET', '/');
        
        $this->assertEquals(200, $client->getResponse()->getStatusCode());
        
        $content = $client->getResponse()->getContent();
        
        // Check that all nine login links are present
        $firewalls = ['default', 'basic', 'public', 'strict', 'es256', 'plain', 'roles', 'email', 'idtoken'];
        
        foreach ($firewalls as $firewall) {
            $startPath = '/' . $firewall . '/start';
            $this->assertStringContainsString($startPath, $content, "Home page should contain login link for $firewall");
            
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
            ];
            
            $title = $scenarioTitles[$firewall];
            $this->assertStringContainsString($title, $content, "Home page should contain title for $firewall");
        }
    }

    /**
     * Test that account routes are protected and require authentication.
     */
    public function testAccountRoutesAreProtected(): void
    {
        $client = static::createClient();
        $client->disableReboot();
        
        $firewalls = ['default', 'basic', 'public', 'strict', 'es256', 'plain', 'roles', 'email', 'idtoken'];
        
        foreach ($firewalls as $firewall) {
            $client->request('GET', '/' . $firewall . '/account');
            
            // Should redirect to authorization endpoint (not 200)
            $this->assertTrue($client->getResponse()->isRedirect(), "Account route for $firewall should require authentication");
            $location = $client->getResponse()->headers->get('Location');
            $this->assertStringStartsWith('https://keycloak.example.test/realms/demo/protocol/openid-connect/auth', $location, "Unauthenticated access to $firewall account should redirect to auth");
        }
    }

    /**
     * Test that the routes for start and callback are correctly named.
     */
    public function testRouteNames(): void
    {
        $client = static::createClient();
        $client->disableReboot();
        
        $firewalls = ['default', 'basic', 'public', 'strict', 'es256', 'plain', 'roles', 'email', 'idtoken'];
        
        $router = static::getContainer()->get('router');
        
        foreach ($firewalls as $firewall) {
            // Check callback route
            $callbackRouteName = '_oidc_login_callback_' . $firewall;
            $callbackRoute = $router->getRouteCollection()->get($callbackRouteName);
            
            $this->assertNotNull($callbackRoute, "Callback route $callbackRouteName should exist");
            $this->assertEquals('/' . $firewall . '/callback', $callbackRoute->getPath(), "Callback route $callbackRouteName should have path /$firewall/callback");
            
            // Check start route
            $startRouteName = '_oidc_login_start_' . $firewall;
            $startRoute = $router->getRouteCollection()->get($startRouteName);
            
            $this->assertNotNull($startRoute, "Start route $startRouteName should exist");
            $this->assertEquals('/' . $firewall . '/start', $startRoute->getPath(), "Start route $startRouteName should have path /$firewall/start");
        }
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
