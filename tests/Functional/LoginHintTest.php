<?php

namespace App\Tests\Functional;

use App\Tests\Oidc\OidcWebTestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * The "hint" firewall: App\Security\LoginHintListener tailors its authorization request to the
 * request that starts it, through OidcAuthorizationRequestEvent.
 */
class LoginHintTest extends OidcWebTestCase
{
    public function testTheLoginHintAndTheBrowserLanguageAreForwarded(): void
    {
        $client = $this->createOidcClient();

        $client->request('GET', '/hint/start?login_hint=bob', server: [
            'HTTP_ACCEPT_LANGUAGE' => 'fr-FR,fr;q=0.9,en;q=0.8',
        ]);

        $params = $this->authorizationRequest($client);
        $this->assertSame('bob', $params['login_hint'] ?? null);
        $this->assertSame('fr', $params['ui_locales'] ?? null);

        // the static authorization_params the listener received, and kept
        $this->assertSame('login', $params['prompt'] ?? null);

        // the protocol parameters stay the authenticator's own
        $this->assertSame('code', $params['response_type'] ?? null);
        $this->assertSame('http://localhost/hint/callback', $params['redirect_uri'] ?? null);
        $this->assertSame('S256', $params['code_challenge_method'] ?? null);

        // the parameters are only the start of the flow, which completes as usual
        $this->answerAuthorizationRequest($client);
        $this->assertResponseRedirects('http://localhost/hint/account');
    }

    /**
     * The entry point dispatches the same event: a protected page tailors the request too.
     */
    public function testTheEntryPointTailorsTheAuthorizationRequestToo(): void
    {
        $client = $this->createOidcClient();

        $client->request('GET', '/hint/account?login_hint=carol@example.com', server: [
            'HTTP_ACCEPT_LANGUAGE' => 'en-GB,en;q=0.9',
        ]);

        $params = $this->authorizationRequest($client);
        $this->assertSame('carol@example.com', $params['login_hint'] ?? null);
        $this->assertSame('en', $params['ui_locales'] ?? null);
        $this->assertSame('login', $params['prompt'] ?? null);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function invalidLoginHintProvider(): iterable
    {
        yield 'a space' => ['bob smith'];
        yield 'markup' => ['<script>alert(1)</script>'];
        yield 'a line break' => ["bob\r\nX-Injected: 1"];
        yield '65 characters' => [str_repeat('a', 65)];
        yield '200 characters' => [str_repeat('b', 200)];
        yield 'empty' => [''];
        yield 'a trailing newline' => ["bob\n"];
    }

    #[DataProvider('invalidLoginHintProvider')]
    public function testALoginHintOutsideTheAllowedPatternIsNotForwarded(string $loginHint): void
    {
        $client = $this->createOidcClient();

        // a language the realm does not offer falls back to the first one it does
        $client->request('GET', '/hint/start?' . http_build_query(['login_hint' => $loginHint]), server: [
            'HTTP_ACCEPT_LANGUAGE' => 'de-DE,de;q=0.9',
        ]);

        $params = $this->authorizationRequest($client);
        $this->assertArrayNotHasKey('login_hint', $params);
        $this->assertSame('en', $params['ui_locales'] ?? null);
        $this->assertSame('login', $params['prompt'] ?? null);
    }

    public function testTheLongestAllowedLoginHintIsForwarded(): void
    {
        $client = $this->createOidcClient();

        $loginHint = str_repeat('a', 64);
        $client->request('GET', '/hint/start?login_hint=' . $loginHint);

        $params = $this->authorizationRequest($client);
        $this->assertSame($loginHint, $params['login_hint'] ?? null);
    }

    /**
     * The listener only answers the event of the "hint" firewall: the others send the request
     * their configuration describes, whatever the query string or the browser language.
     */
    public function testOtherFirewallsAreLeftAlone(): void
    {
        $client = $this->createOidcClient();

        $client->request('GET', '/default/start?login_hint=bob', server: [
            'HTTP_ACCEPT_LANGUAGE' => 'fr-FR,fr;q=0.9',
        ]);

        $params = $this->authorizationRequest($client);
        $this->assertArrayNotHasKey('login_hint', $params);
        $this->assertArrayNotHasKey('ui_locales', $params);
        $this->assertArrayNotHasKey('prompt', $params);

        // "strict" keeps its static login_hint and ui_locales
        $client->request('GET', '/strict/start?login_hint=bob', server: [
            'HTTP_ACCEPT_LANGUAGE' => 'en-US,en;q=0.9',
        ]);

        $params = $this->authorizationRequest($client);
        $this->assertSame('alice', $params['login_hint'] ?? null);
        $this->assertSame('fr', $params['ui_locales'] ?? null);
    }
}
