<?php

namespace App\Tests\Functional;

use App\Tests\Oidc\FakeKeycloak;
use App\Tests\Oidc\TestKeys;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * Functional tests for the OIDC login flow across all scenarios.
 */
class LoginFlowTest extends WebTestCase
{
    /**
     * Data provider for all ten scenarios.
     */
    public static function scenarioProvider(): array
    {
        return [
            ['default'],
            ['basic'],
            ['public'],
            ['strict'],
            ['es256'],
            ['plain'],
            ['roles'],
            ['email'],
            ['idtoken'],
            ['callback'],
        ];
    }

    /**
     * Test the login flow for each scenario.
     */
    #[DataProvider('scenarioProvider')]
    public function testLoginFlowForScenario(string $firewall): void
    {
        $client = static::createClient();
        $client->disableReboot();
        
        // Get the fake Keycloak service
        /** @var FakeKeycloak $fakeKeycloak */
        $fakeKeycloak = static::getContainer()->get(FakeKeycloak::class);
        
        // Reset the fake for each test
        $fakeKeycloak->reset();

        // Step 1: Start the login flow - should redirect to authorization endpoint
        $client->request('GET', '/' . $firewall . '/start');
        
        $this->assertTrue($client->getResponse()->isRedirect());
        $location = $client->getResponse()->headers->get('Location');
        
        // Check that the redirect URL has the expected parameters
        $this->assertStringStartsWith('https://keycloak.example.test/realms/demo/protocol/openid-connect/auth', $location);
        
        $parsedUrl = parse_url($location);
        parse_str($parsedUrl['query'] ?? '', $params);
        
        // Common parameters that should be present in all scenarios
        $this->assertArrayHasKey('response_type', $params);
        $this->assertEquals('code', $params['response_type']);
        
        $this->assertArrayHasKey('client_id', $params);
        $this->assertStringEndsWith('-test', $params['client_id']);
        
        $this->assertArrayHasKey('redirect_uri', $params);
        
        if ($firewall === 'callback') {
            $this->assertEquals('http://localhost/callback/return-from-keycloak', $params['redirect_uri']);
        } else {
            $this->assertStringStartsWith('http://localhost/' . $firewall . '/callback', $params['redirect_uri']);
        }
        
        $this->assertArrayHasKey('scope', $params);
        $this->assertStringContainsString('openid', $params['scope']);
        
        $this->assertArrayHasKey('state', $params);
        $this->assertArrayHasKey('nonce', $params);
        
        // Check scenario-specific parameters
        switch ($firewall) {
            case 'default':
            case 'basic':
            case 'public':
            case 'es256':
            case 'roles':
            case 'email':
            case 'idtoken':
                // These should have S256 PKCE by default
                $this->assertArrayHasKey('code_challenge', $params);
                $this->assertArrayHasKey('code_challenge_method', $params);
                $this->assertEquals('S256', $params['code_challenge_method']);
                break;
            case 'plain':
                // Plain should have PKCE with plain method
                $this->assertArrayHasKey('code_challenge', $params);
                $this->assertArrayHasKey('code_challenge_method', $params);
                $this->assertEquals('plain', $params['code_challenge_method']);
                break;
            case 'strict':
                // Strict should have additional authorization parameters
                $this->assertArrayHasKey('max_age', $params);
                $this->assertEquals('60', $params['max_age']);
                $this->assertArrayHasKey('prompt', $params);
                $this->assertEquals('login', $params['prompt']);
                $this->assertArrayHasKey('login_hint', $params);
                $this->assertEquals('alice', $params['login_hint']);
                $this->assertArrayHasKey('ui_locales', $params);
                $this->assertEquals('fr', $params['ui_locales']);
                break;
        }

        // Set up the fake Keycloak with the authorization request
        $fakeKeycloak->expectAuthorization($location);
        
        // Issue an authorization code
        $authorizationCode = $fakeKeycloak->issueCode();
        
        // Step 2: Callback with the authorization code
        $state = $params['state'];
        
        // Derive callback path from redirect_uri
        $callbackPath = parse_url($params['redirect_uri'], PHP_URL_PATH);
        $client->request('GET', $callbackPath . '?code=' . $authorizationCode . '&state=' . $state);
        
        // Should redirect to the account page after successful authentication
        $this->assertTrue($client->getResponse()->isRedirect());
        $accountLocation = $client->getResponse()->headers->get('Location');
        $this->assertSame('http://localhost/' . $firewall . '/account', $accountLocation);
        
        // Follow the redirect to the account page
        $client->followRedirect();
        
        $this->assertEquals(200, $client->getResponse()->getStatusCode());
        
        // Get the response content
        $content = $client->getResponse()->getContent();
        
        // Check that the user is authenticated and the identity is correct
        $this->assertStringContainsString('alice', $content);
        
        // Check the user identifier based on the scenario
        switch ($firewall) {
            case 'email':
                // For email scenario, the identifier should be the email
                $this->assertStringContainsString('alice@example.com', $content);
                break;
            default:
                // For other scenarios, the identifier should be the sub UUID
                $this->assertStringContainsString('11111111-1111-4111-8111-111111111111', $content);
                break;
        }
        
        // Check roles based on the scenario
        switch ($firewall) {
            case 'roles':
                // Roles scenario should have admin and editor roles
                $this->assertStringContainsString('ROLE_ADMIN', $content);
                $this->assertStringContainsString('ROLE_EDITOR', $content);
                // fall through to check ROLE_USER
            default:
                // All scenarios should have ROLE_USER
                $this->assertStringContainsString('ROLE_USER', $content);
                break;
        }
        
        // Check that no client secret appears in the page (should be redacted)
        $this->assertStringNotContainsString('symfony-demo-secret-test', $content);
        $this->assertStringNotContainsString('symfony-demo-es256-secret-test', $content);
        $this->assertStringNotContainsString('symfony-demo-plain-secret-test', $content);
        
        // Check for the seven trace steps by their titles
        $traceSteps = [
            'You clicked Log in',
            'Keycloak authenticated you and sent you back',
            'The code was exchanged for tokens',
            'The ID token was verified',
            'Your claims were',
            'The user was built',
            'A session was opened'
        ];
        
        foreach ($traceSteps as $step) {
            if ($firewall === 'idtoken') {
                // For idtoken scenario, the claims step has different wording
                if ($step === 'Your claims were') {
                    $this->assertStringContainsString('Your claims were read from the ID token', $content);
                    continue;
                }
            } elseif ($step === 'Your claims were') {
                $this->assertStringContainsString('Your claims were fetched from UserInfo', $content);
                continue;
            }
            
            $this->assertStringContainsString($step, $content, 'Missing trace step: ' . $step);
        }
        
        // Check that the client authentication method is correct
        $requests = $fakeKeycloak->requests();
        $tokenRequests = array_filter($requests, function ($request) {
            return str_contains($request['url'], '/token');
        });
        
        $this->assertCount(1, $tokenRequests, 'Expected exactly one token request');
        
        $tokenRequest = reset($tokenRequests);
        $tokenOptions = $tokenRequest['options'];
        
        // Check client authentication based on scenario
        switch ($firewall) {
            case 'basic':
                // the mock transport turns the auth_basic option into the Authorization header
                $this->assertStringStartsWith('Authorization: Basic ', $tokenOptions['normalized_headers']['authorization'][0] ?? '');
                break;
            case 'public':
                // Public client should have no authentication
                $this->assertArrayNotHasKey('auth_basic', $tokenOptions);
                $this->assertArrayNotHasKey('auth_bearer', $tokenOptions);
                if (isset($tokenOptions['body']) && is_array($tokenOptions['body'])) {
                    $this->assertArrayNotHasKey('client_secret', $tokenOptions['body']);
                }
                break;
            default:
                // Default, strict, es256, plain, roles, email, idtoken should use client_secret in body
                if (isset($tokenOptions['body']) && is_array($tokenOptions['body'])) {
                    $this->assertArrayHasKey('client_secret', $tokenOptions['body']);
                }
                break;
        }
        
        // For idtoken scenario, check that no UserInfo request was made
        if ($firewall === 'idtoken') {
            $userInfoRequests = array_filter($requests, function ($request) {
                return str_contains($request['url'], '/userinfo');
            });
            
            $this->assertCount(0, $userInfoRequests, 'Expected no UserInfo requests for idtoken scenario');
            $this->assertStringContainsString('claims were read from the ID token', $content);
        }
        
        // Check ID token algorithm
        switch ($firewall) {
            case 'es256':
                $this->assertStringContainsString('ES256', $content);
                break;
            default:
                $this->assertStringContainsString('RS256', $content);
                break;
        }
        
        // For strict scenario, check auth_time check
        if ($firewall === 'strict') {
            $this->assertStringContainsString('auth_time', $content);
        }
    }

    /**
     * Test the entry point - accessing a protected page without authentication should redirect to provider.
     */
    public function testEntryPointRedirect(): void
    {
        $client = static::createClient();
        $client->disableReboot();
        
        // Access a protected account page without authentication
        $client->request('GET', '/default/account');
        
        // Should redirect to the authorization endpoint
        $this->assertTrue($client->getResponse()->isRedirect());
        $location = $client->getResponse()->headers->get('Location');
        
        $this->assertStringStartsWith('https://keycloak.example.test/realms/demo/protocol/openid-connect/auth', $location);
        
        // Now follow through with a login to get the trace
        /** @var FakeKeycloak $fakeKeycloak */
        $fakeKeycloak = static::getContainer()->get(FakeKeycloak::class);
        $fakeKeycloak->reset();
        
        $fakeKeycloak->expectAuthorization($location);
        $authorizationCode = $fakeKeycloak->issueCode();
        
        $parsedUrl = parse_url($location);
        parse_str($parsedUrl['query'] ?? '', $params);
        
        $client->request('GET', '/default/callback?code=' . $authorizationCode . '&state=' . $params['state']);
        $client->followRedirect();
        
        $content = $client->getResponse()->getContent();
        
        // Check that the trace says it started from a protected page
        $this->assertStringContainsString('You asked for a protected page', $content);
    }

    /**
     * Data provider for testing specific client authentication methods.
     */
    public static function clientAuthProvider(): array
    {
        return [
            ['basic', 'basic'],
            ['public', 'none'],
            ['default', 'post'],
        ];
    }

    /**
     * Test that the code_verifier in the trace matches what was sent to the token endpoint.
     */
    public function testPkceVerification(): void
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
        
        // Complete the login
        $callbackPath = parse_url($params['redirect_uri'], PHP_URL_PATH);
        $client->request('GET', $callbackPath . '?code=' . $authorizationCode . '&state=' . $params['state']);
        $client->followRedirect();
        
        $content = $client->getResponse()->getContent();
        
        // Get the requests made to the fake
        $requests = $fakeKeycloak->requests();
        $tokenRequests = array_filter($requests, function ($request) {
            return str_contains($request['url'], '/token');
        });
        
        $tokenRequest = reset($tokenRequests);
        $tokenOptions = $tokenRequest['options'];
        
        // Extract the code_verifier from the token request
        $codeVerifier = null;
        if (isset($tokenOptions['body']['code_verifier'])) {
            $codeVerifier = $tokenOptions['body']['code_verifier'];
        } elseif (isset($tokenOptions['body']) && is_string($tokenOptions['body'])) {
            parse_str($tokenOptions['body'], $bodyParams);
            $codeVerifier = $bodyParams['code_verifier'] ?? null;
        }
        
        $this->assertNotNull($codeVerifier, 'code_verifier should be present in token request');
        
        // Check that the code_verifier appears in the trace
        $this->assertStringContainsString($codeVerifier, $content);
    }

    /**
     * Test client authentication methods are correctly recorded in the trace.
     */
    #[DataProvider('clientAuthProvider')]
    public function testClientAuthenticationMethod(string $firewall, string $expectedMethod): void
    {
        $client = static::createClient();
        $client->disableReboot();
        
        /** @var FakeKeycloak $fakeKeycloak */
        $fakeKeycloak = static::getContainer()->get(FakeKeycloak::class);
        $fakeKeycloak->reset();

        // Start the login flow
        $client->request('GET', '/' . $firewall . '/start');
        $location = $client->getResponse()->headers->get('Location');
        
        $parsedUrl = parse_url($location);
        parse_str($parsedUrl['query'] ?? '', $params);
        
        // Get the fake after disableReboot to ensure we have the right instance
        $fakeKeycloak->expectAuthorization($location);
        $authorizationCode = $fakeKeycloak->issueCode();
        
        // Complete the login
        $callbackPath = parse_url($params['redirect_uri'], PHP_URL_PATH);
        $client->request('GET', $callbackPath . '?code=' . $authorizationCode . '&state=' . $params['state']);
        $client->followRedirect();
        
        $content = $client->getResponse()->getContent();
        
        // Check the expected authentication method appears in the trace
        switch ($expectedMethod) {
            case 'basic':
                $this->assertStringContainsString('Authorization: Basic', $content);
                break;
            case 'none':
                $this->assertStringContainsString('none: a public client sends no credentials', $content);
                break;
            case 'post':
                $this->assertStringContainsString('client_secret in the request body', $content);
                break;
        }
    }
}
