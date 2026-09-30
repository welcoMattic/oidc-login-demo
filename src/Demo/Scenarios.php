<?php

namespace App\Demo;

/**
 * Scenario catalogue for the OIDC login demo.
 *
 * This class contains the configuration and metadata for each scenario/firewall
 * in the demo, so templates and tests can reuse it.
 */
final class Scenarios
{
    /**
     * @return array<string, array{title: string, summary: string, client_id: string, provider: string, user_data_source: string, user_identifier_claim: string, allowed_time_drift: int, max_age: ?int, options: array<array{name: string, value: string}>}>
     */
    public static function all(): array
    {
        return [
            'default' => [
                'title' => 'Default',
                'summary' => 'Baseline configuration: required options only, all defaults inherited.',
                'client_id' => 'symfony-demo',
                'provider' => 'Symfony\Component\Security\Core\User\OidcUserProvider',
                'user_data_source' => 'userinfo',
                'user_identifier_claim' => 'sub',
                'allowed_time_drift' => 0,
                'max_age' => null,
                'options' => [
                    ['name' => 'scope', 'value' => '[profile, email]'],
                    ['name' => 'client_authentication', 'value' => 'client_secret_post'],
                    ['name' => 'pkce', 'value' => 'enabled: true, method: S256 (default)'],
                    [
                        'name' => 'id_token_signature',
                        'value' => 'required: true, algorithms: [RS256], enforce_key_usage_verification: true (default)',
                    ],
                    ['name' => 'enable_end_session', 'value' => 'true'],
                ],
            ],
            'basic' => [
                'title' => 'Basic Auth',
                'summary' => 'Client secret sent via HTTP Basic instead of request body.',
                'client_id' => 'symfony-demo',
                'provider' => 'Symfony\Component\Security\Core\User\OidcUserProvider',
                'user_data_source' => 'userinfo',
                'user_identifier_claim' => 'sub',
                'allowed_time_drift' => 0,
                'max_age' => null,
                'options' => [
                    ['name' => 'client_authentication', 'value' => 'client_secret_basic'],
                    ['name' => 'enable_end_session', 'value' => 'true'],
                ],
            ],
            'public' => [
                'title' => 'Public Client',
                'summary' => 'No client secret: PKCE is the only thing binding the code to the client.',
                'client_id' => 'symfony-demo-public',
                'provider' => 'Symfony\Component\Security\Core\User\OidcUserProvider',
                'user_data_source' => 'userinfo',
                'user_identifier_claim' => 'sub',
                'allowed_time_drift' => 0,
                'max_age' => null,
                'options' => [
                    ['name' => 'client_authentication', 'value' => 'none (public client, no secret)'],
                    ['name' => 'enable_end_session', 'value' => 'true'],
                ],
            ],
            'strict' => [
                'title' => 'Strict Validation',
                'summary' => 'Re-authentication with max_age, extra authorization parameters (prompt, login_hint, ui_locales), a clock skew tolerance and the signature settings spelled out.',
                'client_id' => 'symfony-demo',
                'provider' => 'Symfony\Component\Security\Core\User\OidcUserProvider',
                'user_data_source' => 'userinfo',
                'user_identifier_claim' => 'sub',
                'allowed_time_drift' => 5,
                'max_age' => 60,
                'options' => [
                    ['name' => 'max_age', 'value' => '60'],
                    ['name' => 'allowed_time_drift', 'value' => '5'],
                    ['name' => 'discovery_cache_ttl', 'value' => '60'],
                    ['name' => 'authorization_params', 'value' => 'prompt: login, login_hint: alice, ui_locales: fr'],
                    [
                        'name' => 'id_token_signature',
                        'value' => 'required: true, algorithms: [RS256], enforce_key_usage_verification: true',
                    ],
                    ['name' => 'enable_end_session', 'value' => 'true'],
                ],
            ],
            'es256' => [
                'title' => 'ES256 Signature',
                'summary' => 'Client signs ID tokens with ES256 instead of RS256.',
                'client_id' => 'symfony-demo-es256',
                'provider' => 'Symfony\Component\Security\Core\User\OidcUserProvider',
                'user_data_source' => 'userinfo',
                'user_identifier_claim' => 'sub',
                'allowed_time_drift' => 0,
                'max_age' => null,
                'options' => [
                    ['name' => 'id_token_signature.algorithms', 'value' => '[ES256]'],
                    ['name' => 'enable_end_session', 'value' => 'true'],
                ],
            ],
            'plain' => [
                'title' => 'Plain PKCE',
                'summary' => 'PKCE with plain method (RFC 7636 Section 4.2 mandates S256 otherwise).',
                'client_id' => 'symfony-demo-plain',
                'provider' => 'Symfony\Component\Security\Core\User\OidcUserProvider',
                'user_data_source' => 'userinfo',
                'user_identifier_claim' => 'sub',
                'allowed_time_drift' => 0,
                'max_age' => null,
                'options' => [
                    ['name' => 'pkce', 'value' => 'enabled: true, method: plain'],
                    ['name' => 'enable_end_session', 'value' => 'true'],
                ],
            ],
            'roles' => [
                'title' => 'Role Mapping',
                'summary' => 'Custom user provider maps Keycloak realm roles onto Symfony roles.',
                'client_id' => 'symfony-demo',
                'provider' => 'App\Security\KeycloakUserProvider',
                'user_data_source' => 'userinfo',
                'user_identifier_claim' => 'sub',
                'allowed_time_drift' => 0,
                'max_age' => null,
                'options' => [
                    ['name' => 'provider', 'value' => 'keycloak_roles'],
                    ['name' => 'scope', 'value' => '[profile, email, roles]'],
                    ['name' => 'enable_end_session', 'value' => 'true'],
                ],
            ],
            'email' => [
                'title' => 'Identifier from another claim',
                'summary' => 'The identity becomes the email claim instead of the sub UUID.',
                'client_id' => 'symfony-demo',
                'provider' => 'Symfony\Component\Security\Core\User\OidcUserProvider',
                'user_data_source' => 'userinfo',
                'user_identifier_claim' => 'email',
                'allowed_time_drift' => 0,
                'max_age' => null,
                'options' => [
                    ['name' => 'user_identifier_claim', 'value' => 'email'],
                    ['name' => 'enable_end_session', 'value' => 'true'],
                ],
            ],
            'idtoken' => [
                'title' => 'Claims from the ID token',
                'summary' => 'The claims are read from the validated ID token, no UserInfo request.',
                'client_id' => 'symfony-demo',
                'provider' => 'Symfony\Component\Security\Core\User\OidcUserProvider',
                'user_data_source' => 'id_token',
                'user_identifier_claim' => 'sub',
                'allowed_time_drift' => 0,
                'max_age' => null,
                'options' => [
                    ['name' => 'user_data_source', 'value' => 'id_token'],
                    ['name' => 'enable_end_session', 'value' => 'true'],
                ],
            ],
            'callback' => [
                'title' => 'Custom callback route',
                'summary' => 'check_path holds a route name, app_callback_return, so the provider sends the browser back to /callback/return-from-keycloak (the route the application declares) instead of the /callback/callback the loader would have registered: the callback lives wherever the application wants it.',
                'client_id' => 'symfony-demo',
                'provider' => 'Symfony\Component\Security\Core\User\OidcUserProvider',
                'user_data_source' => 'userinfo',
                'user_identifier_claim' => 'sub',
                'allowed_time_drift' => 0,
                'max_age' => null,
                'options' => [
                    ['name' => 'check_path', 'value' => 'app_callback_return (a route name)'],
                    [
                        'name' => 'redirect_uri',
                        'value' => 'http://localhost:8001/callback/return-from-keycloak (the URL of that route)',
                    ],
                    ['name' => 'enable_end_session', 'value' => 'true'],
                ],
            ],
            'refresh' => [
                'title' => 'Refresh token grant',
                'summary' => 'The access token lives 60 seconds; half a minute after the login, the next request renews it with the refresh token, before the application ever holds an expired one.',
                'client_id' => 'symfony-demo-refresh',
                'provider' => 'Symfony\Component\Security\Core\User\OidcUserProvider',
                'user_data_source' => 'userinfo',
                'user_identifier_claim' => 'sub',
                'allowed_time_drift' => 0,
                'max_age' => null,
                'options' => [
                    ['name' => 'refresh_access_token', 'value' => 'enabled: true, leeway: 30'],
                    ['name' => 'client_authentication', 'value' => 'client_secret_post'],
                    ['name' => 'enable_end_session', 'value' => 'true'],
                ],
            ],
            'secretjwt' => [
                'title' => 'client_secret_jwt',
                'summary' => 'The client proves it holds the secret with a JWT it signs with HS256: the secret itself never travels to the token endpoint.',
                'client_id' => 'symfony-demo-jwt',
                'provider' => 'Symfony\Component\Security\Core\User\OidcUserProvider',
                'user_data_source' => 'userinfo',
                'user_identifier_claim' => 'sub',
                'allowed_time_drift' => 0,
                'max_age' => null,
                'options' => [
                    ['name' => 'client_authentication', 'value' => 'client_secret_jwt: { algorithm: HS256, lifetime: 60 }'],
                    ['name' => 'enable_end_session', 'value' => 'true'],
                ],
            ],
            'privatekeyjwt' => [
                'title' => 'private_key_jwt',
                'summary' => 'The client signs its JWT assertion with its own ES256 private key; Keycloak only holds the public key, so nothing it stores can impersonate the client.',
                'client_id' => 'symfony-demo-pkjwt',
                'provider' => 'Symfony\Component\Security\Core\User\OidcUserProvider',
                'user_data_source' => 'userinfo',
                'user_identifier_claim' => 'sub',
                'allowed_time_drift' => 0,
                'max_age' => null,
                'options' => [
                    ['name' => 'client_authentication', 'value' => 'private_key_jwt: { algorithm: ES256 }'],
                    ['name' => 'enable_end_session', 'value' => 'true'],
                ],
            ],
            'reauth' => [
                'title' => 'Re-authentication',
                'summary' => 'A sensitive page requires IS_AUTHENTICATED_VERY_RECENTLY: past 60 seconds, the authenticator sends you back to Keycloak with prompt=login and id_token_hint, then back to the page.',
                'client_id' => 'symfony-demo',
                'provider' => 'Symfony\Component\Security\Core\User\OidcUserProvider',
                'user_data_source' => 'userinfo',
                'user_identifier_claim' => 'sub',
                'allowed_time_drift' => 0,
                'max_age' => null,
                'options' => [
                    ['name' => 'very_recent_authentication_lifetime', 'value' => '60 (root security option)'],
                    ['name' => "#[IsGranted('IS_AUTHENTICATED_VERY_RECENTLY')]", 'value' => '/reauth/sensitive'],
                    ['name' => 're_authentication_entry_point', 'value' => 'the oidc_login authenticator (default)'],
                    ['name' => 'enable_end_session', 'value' => 'true'],
                ],
            ],
            'hint' => [
                'title' => 'Per-request parameters',
                'summary' => 'A listener of OidcAuthorizationRequestEvent adds the login_hint of the query string and the ui_locales of the browser to the authorization request.',
                'client_id' => 'symfony-demo',
                'provider' => 'Symfony\Component\Security\Core\User\OidcUserProvider',
                'user_data_source' => 'userinfo',
                'user_identifier_claim' => 'sub',
                'allowed_time_drift' => 0,
                'max_age' => null,
                'options' => [
                    ['name' => 'authorization_params', 'value' => 'prompt: login'],
                    ['name' => 'OidcAuthorizationRequestEvent', 'value' => 'login_hint from ?login_hint=, ui_locales from Accept-Language'],
                    ['name' => 'enable_end_session', 'value' => 'true'],
                ],
            ],
        ];
    }

    /**
     * Get a single scenario by firewall name.
     *
     * @return array{title: string, summary: string, client_id: string, provider: string, user_data_source: string, user_identifier_claim: string, allowed_time_drift: int, max_age: ?int, options: array<array{name: string, value: string}>}
     */
    public static function get(string $firewall): ?array
    {
        return self::all()[$firewall] ?? null;
    }

    /**
     * Get all firewall names.
     *
     * @return list<string>
     */
    public static function names(): array
    {
        return array_keys(self::all());
    }
}
