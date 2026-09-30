<?php

namespace App\Tests\Functional;

use App\Tests\Oidc\FakeKeycloak;
use App\Tests\Oidc\OidcWebTestCase;

/**
 * The "refresh" firewall: the access token is renewed with the refresh token grant once it
 * is less than "leeway" (30 seconds) away from expiring; the provider gives it 60 seconds.
 */
class RefreshTokenTest extends OidcWebTestCase
{
    public function testTheLoginKeepsTheRefreshTokenAndTheAccessTokenExpiry(): void
    {
        $client = $this->createOidcClient();

        $this->logIn($client, 'refresh');

        $issued = $this->fakeKeycloak()->tokenResponses();
        $this->assertCount(1, $issued);
        $this->assertSame(60, $issued[0]['expires_in']);

        $this->assertSame($issued[0]['refresh_token'], $this->tokenAttribute('oidc_refresh_token'));
        $this->assertSame($issued[0]['access_token'], $this->tokenAttribute('oidc_access_token'));
        $this->assertSame($this->now() + 60, $this->tokenAttribute('oidc_access_token_expires_at'));
    }

    public function testTheAccessTokenIsRenewedOnceItIsAboutToExpire(): void
    {
        $client = $this->createOidcClient();

        $this->logIn($client, 'refresh');

        $fakeKeycloak = $this->fakeKeycloak();
        $clock = $this->clock();
        $loggedInAt = $clock->now()->getTimestamp();
        $login = $fakeKeycloak->tokenResponses()[0];

        // 31 seconds left, one more than the leeway: nothing to renew yet
        $clock->sleep(29);
        $client->request('GET', '/refresh/account');

        $this->assertResponseIsSuccessful();
        $this->assertSame([], $fakeKeycloak->tokenRequestsFor('refresh_token'));
        $this->assertSame($login['access_token'], $this->tokenAttribute('oidc_access_token'));

        // 30 seconds left: the first request renews the access token before anything else runs
        $clock->sleep(1);
        $client->request('GET', '/refresh/account');

        $this->assertResponseIsSuccessful();
        $content = (string) $client->getResponse()->getContent();
        $this->assertStringContainsString(FakeKeycloak::DEFAULT_SUB, $content);
        $this->assertStringNotContainsString('symfony-demo-refresh-secret-test', $content);

        $refreshRequests = $fakeKeycloak->tokenRequestsFor('refresh_token');
        $this->assertCount(1, $refreshRequests);
        $this->assertSame($login['refresh_token'], $refreshRequests[0]['refresh_token'] ?? null);

        // client_secret_post, like the code exchange of this firewall
        $this->assertSame('symfony-demo-refresh-test', $refreshRequests[0]['client_id'] ?? null);
        $this->assertSame('symfony-demo-refresh-secret-test', $refreshRequests[0]['client_secret'] ?? null);
        $this->assertNull($fakeKeycloak->tokenRequests()[1]['authorization']);
        $this->assertSame([], $fakeKeycloak->tokenErrors());

        // the security token holds what the provider answered, the rotated refresh token included
        $refreshed = $fakeKeycloak->tokenResponses()[1];
        $this->assertNotSame($login['access_token'], $refreshed['access_token']);
        $this->assertSame($refreshed['access_token'], $this->tokenAttribute('oidc_access_token'));
        $this->assertSame($refreshed['refresh_token'], $this->tokenAttribute('oidc_refresh_token'));
        $this->assertSame($refreshed['id_token'], $this->tokenAttribute('oidc_id_token'));
        $this->assertSame($loggedInAt + 30 + 60, $this->tokenAttribute('oidc_access_token_expires_at'));

        // the refreshed ID token describes the same authentication, and has no nonce
        $claims = $this->jwtClaims($refreshed['id_token']);
        $this->assertSame(FakeKeycloak::DEFAULT_SUB, $claims['sub'] ?? null);
        $this->assertSame($loggedInAt, $claims['auth_time'] ?? null);
        $this->assertArrayNotHasKey('nonce', $claims);
        $this->assertSame(FakeKeycloak::DEFAULT_SUB, $this->securityToken()?->getUserIdentifier());

        // the renewed tokens were kept in the session: the next request has nothing to renew
        $clock->sleep(5);
        $client->request('GET', '/refresh/account');

        $this->assertResponseIsSuccessful();
        $this->assertCount(1, $fakeKeycloak->tokenRequestsFor('refresh_token'));
    }

    /**
     * "invalid_grant" says the refresh token itself is gone: the user is logged out.
     */
    public function testARefreshTokenTheProviderNoLongerHonorsLogsTheUserOut(): void
    {
        $client = $this->createOidcClient();

        $this->logIn($client, 'refresh');

        $fakeKeycloak = $this->fakeKeycloak();
        $fakeKeycloak->rejectRefreshTokens();
        $this->clock()->sleep(31);

        // the request that tried to renew the access token is already an anonymous one
        $client->request('GET', '/refresh/account');

        $this->authorizationRequest($client);
        $this->assertCount(1, $fakeKeycloak->tokenRequestsFor('refresh_token'));
        $this->assertSame(['invalid_grant: The refresh token is no longer honored'], $fakeKeycloak->tokenErrors());
        $this->assertNull($this->securityToken());

        // and so is the next one: the session no longer holds the user
        $client->request('GET', '/refresh/account');

        $this->authorizationRequest($client);
        $this->assertCount(1, $fakeKeycloak->tokenRequestsFor('refresh_token'));
    }

    /**
     * Any other failure keeps the user logged in, with the tokens untouched, and the renewal
     * is tried again on the next request: a provider that is down must not log everyone out.
     */
    public function testARefreshThatFailsForAnotherReasonIsRetriedOnTheNextRequest(): void
    {
        $client = $this->createOidcClient();

        $this->logIn($client, 'refresh');

        $fakeKeycloak = $this->fakeKeycloak();
        $login = $fakeKeycloak->tokenResponses()[0];
        $fakeKeycloak->rejectRefreshTokens('temporarily_unavailable', 503);
        $this->clock()->sleep(31);

        $client->request('GET', '/refresh/account');

        $this->assertResponseIsSuccessful();
        $this->assertCount(1, $fakeKeycloak->tokenRequestsFor('refresh_token'));
        $this->assertSame($login['access_token'], $this->tokenAttribute('oidc_access_token'));
        $this->assertSame($login['refresh_token'], $this->tokenAttribute('oidc_refresh_token'));

        $client->request('GET', '/refresh/account');

        $this->assertResponseIsSuccessful();
        $this->assertCount(2, $fakeKeycloak->tokenRequestsFor('refresh_token'));
    }
}
