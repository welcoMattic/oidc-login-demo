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
                    ['name' => 'token_endpoint_auth_method', 'value' => 'client_secret_post (default)'],
                    ['name' => 'pkce', 'value' => 'enabled: true, method: S256 (default)'],
                    ['name' => 'id_token_signature', 'value' => 'required: true, algorithms: [RS256], enforce_key_usage_verification: true (default)'],
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
                    ['name' => 'token_endpoint_auth_method', 'value' => 'client_secret_basic'],
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
                    ['name' => 'token_endpoint_auth_method', 'value' => 'none'],
                    ['name' => 'client_secret', 'value' => 'not set'],
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
                    ['name' => 'id_token_signature', 'value' => 'required: true, algorithms: [RS256], enforce_key_usage_verification: true'],
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