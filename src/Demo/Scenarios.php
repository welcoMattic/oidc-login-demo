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
     * @return array<string, array{title: string, summary: string, client_id: string, options: array<array{name: string, value: string}>}>
     */
    public static function all(): array
    {
        return [
            'default' => [
                'title' => 'Default',
                'summary' => 'Baseline configuration: required options only, all defaults inherited.',
                'client_id' => 'symfony-demo',
                'options' => [
                    ['name' => 'scope', 'value' => '[profile, email]'],
                    ['name' => 'token_endpoint_auth_method', 'value' => 'client_secret_post (default)'],
                    ['name' => 'pkce', 'value' => 'enabled: true, method: S256 (default)'],
                    ['name' => 'id_token_signature', 'value' => 'required: true, algorithms: [RS256], enforce_key_usage_verification: true (default)'],
                ],
            ],
            'basic' => [
                'title' => 'Basic Auth',
                'summary' => 'Client secret sent via HTTP Basic instead of request body.',
                'client_id' => 'symfony-demo',
                'options' => [
                    ['name' => 'token_endpoint_auth_method', 'value' => 'client_secret_basic'],
                ],
            ],
            'public' => [
                'title' => 'Public Client',
                'summary' => 'No client secret: PKCE is the only thing binding the code to the client.',
                'client_id' => 'symfony-demo-public',
                'options' => [
                    ['name' => 'token_endpoint_auth_method', 'value' => 'none'],
                    ['name' => 'client_secret', 'value' => 'not set'],
                ],
            ],
            'strict' => [
                'title' => 'Strict Validation',
                'summary' => 'Every option set: re-authentication, clock drift, cache TTL, auth params, signature algs.',
                'client_id' => 'symfony-demo',
                'options' => [
                    ['name' => 'max_age', 'value' => '60'],
                    ['name' => 'allowed_time_drift', 'value' => '5'],
                    ['name' => 'discovery_cache_ttl', 'value' => '60'],
                    ['name' => 'authorization_params', 'value' => 'prompt: login, login_hint: alice, ui_locales: fr'],
                    ['name' => 'id_token_signature', 'value' => 'required: true, algorithms: [RS256], enforce_key_usage_verification: true'],
                ],
            ],
            'es256' => [
                'title' => 'ES256 Signature',
                'summary' => 'Client signs ID tokens with ES256 instead of RS256.',
                'client_id' => 'symfony-demo-es256',
                'options' => [
                    ['name' => 'id_token_signature.algorithms', 'value' => '[ES256]'],
                ],
            ],
            'plain' => [
                'title' => 'Plain PKCE',
                'summary' => 'PKCE with plain method (RFC 7636 Section 4.2 mandates S256 otherwise).',
                'client_id' => 'symfony-demo-plain',
                'options' => [
                    ['name' => 'pkce', 'value' => 'enabled: true, method: plain'],
                ],
            ],
            'roles' => [
                'title' => 'Role Mapping',
                'summary' => 'Custom user provider maps Keycloak realm roles onto Symfony roles.',
                'client_id' => 'symfony-demo',
                'options' => [
                    ['name' => 'provider', 'value' => 'keycloak_roles'],
                    ['name' => 'scope', 'value' => '[profile, email, roles]'],
                ],
            ],
        ];
    }

    /**
     * Get a single scenario by firewall name.
     *
     * @return array{title: string, summary: string, client_id: string, options: array<array{name: string, value: string}>}
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