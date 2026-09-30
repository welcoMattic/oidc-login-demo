<?php

namespace App\Tests\Functional;

use App\Tests\Oidc\FakeKeycloak;
use App\Tests\Oidc\OidcWebTestCase;

/**
 * The "reauth" firewall: /reauth/sensitive requires IS_AUTHENTICATED_VERY_RECENTLY, granted
 * for 60 seconds (very_recent_authentication_lifetime) after the "auth_time" of the ID token.
 * Past that, the authenticator sends the user back to the provider with prompt=login.
 */
class ReauthTest extends OidcWebTestCase
{
    public function testTheSensitivePageAsksForAFreshLoginOnceTheLastOneIsStale(): void
    {
        $client = $this->createOidcClient();

        $this->logIn($client, 'reauth');

        $clock = $this->clock();
        $loggedInAt = $clock->now()->getTimestamp();

        // the proof is the auth_time of the ID token, and the method its amr claim names
        $this->assertSame(['pwd' => $loggedInAt], $this->securityToken()?->getAuthenticationProofs());
        $this->assertSame('1', $this->tokenAttribute('oidc_acr'));

        $client->request('GET', '/reauth/sensitive');
        $this->assertResponseIsSuccessful();

        // still very recent 60 seconds later
        $clock->sleep(60);
        $client->request('GET', '/reauth/sensitive');
        $this->assertResponseIsSuccessful();

        // one more second, and the denial turns into a re-authentication request, not a 403
        $clock->sleep(1);
        $idToken = $this->idToken();
        $client->request('GET', '/reauth/sensitive');

        $params = $this->authorizationRequest($client);
        $this->assertSame('login', $params['prompt'] ?? null);
        $this->assertSame($idToken, $params['id_token_hint'] ?? null);
        $this->assertSame('symfony-demo-test', $params['client_id'] ?? null);
        $this->assertSame('http://localhost/reauth/callback', $params['redirect_uri'] ?? null);

        // the provider checks the password again, and the user lands back on the page denied
        $this->answerAuthorizationRequest($client);
        $this->assertResponseRedirects('http://localhost/reauth/sensitive');

        $reauthenticatedAt = $clock->now()->getTimestamp();
        $this->assertSame($loggedInAt + 61, $reauthenticatedAt);
        $this->assertSame(['pwd' => $reauthenticatedAt], $this->securityToken()?->getAuthenticationProofs());
        $this->assertNotSame($idToken, $this->idToken());

        $client->followRedirect();
        $this->assertResponseIsSuccessful();
        $this->assertSame(FakeKeycloak::DEFAULT_SUB, $this->securityToken()?->getUserIdentifier());
    }

    /**
     * A login answered from an old Keycloak SSO session carries the old auth_time: the user
     * just logged in to the application, yet the sensitive page asks for the password right
     * away, because what counts is when the provider last checked it.
     */
    public function testALoginAnsweredFromAnOldSsoSessionIsNotRecentEnough(): void
    {
        $client = $this->createOidcClient();

        $now = $this->now();
        $this->fakeKeycloak()->withSsoSession($now - 120);

        $this->logIn($client, 'reauth');

        $this->assertSame(['pwd' => $now - 120], $this->securityToken()?->getAuthenticationProofs());
        $this->assertSame('0', $this->tokenAttribute('oidc_acr'));

        $client->request('GET', '/reauth/account');
        $this->assertResponseIsSuccessful();

        $client->request('GET', '/reauth/sensitive');

        $params = $this->authorizationRequest($client);
        $this->assertSame('login', $params['prompt'] ?? null);

        // prompt=login makes the provider check the password, whatever session it holds
        $this->answerAuthorizationRequest($client);
        $this->assertResponseRedirects('http://localhost/reauth/sensitive');
        $this->assertSame(['pwd' => $now], $this->securityToken()?->getAuthenticationProofs());
        $this->assertSame('1', $this->tokenAttribute('oidc_acr'));

        $client->followRedirect();
        $this->assertResponseIsSuccessful();
    }
}
