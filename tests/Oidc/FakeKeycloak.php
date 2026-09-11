<?php

namespace App\Tests\Oidc;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Contracts\HttpClient\ResponseInterface;

/**
 * Mock response factory for testing OIDC authentication.
 *
 * This class intercepts HTTP requests to the fake Keycloak provider and returns
 * appropriate mock responses based on the request type and parameters.
 */
final class FakeKeycloak
{
    private const ISSUER = 'https://keycloak.example.test/realms/demo';
    private const ISSUER_NO_TRAILING_SLASH = 'https://keycloak.example.test/realms/demo';

    private string $issuer;
    private ?array $lastAuthorizationRequest = null;
    private array $issuedCodes = [];
    private ?string $signingKeyId = null;
    private ?string $signingKeyAlg = null;
    private array $withoutClaims = [];
    private ?string $customNonce = null;
    private ?string $customSub = null;
    private ?string $userInfoSub = null;
    private ?string $customUsername = null;
    private ?string $customEmail = null;
    private array $customRealmRoles = [];
    private bool $withoutAuthTime = false;
    private ?\Jose\Component\Core\JWK $customSigningKey = null;

    /** @var list<array{method: string, url: string, options: array}> */
    private array $requests = [];

    private int $codeCounter = 0;

    public function __construct()
    {
        $this->issuer = self::ISSUER;
        $this->reset();
    }

    /**
     * Reset the state of the fake Keycloak.
     */
    public function reset(): void
    {
        $this->lastAuthorizationRequest = null;
        $this->issuedCodes = [];
        $this->signingKeyId = null;
        $this->signingKeyAlg = null;
        $this->withoutClaims = [];
        $this->customNonce = null;
        $this->customSub = null;
        $this->userInfoSub = null;
        $this->customUsername = null;
        $this->customEmail = null;
        $this->customRealmRoles = [];
        $this->withoutAuthTime = false;
        $this->customSigningKey = null;
        $this->requests = [];
        $this->codeCounter = 0;
    }

    /**
     * Invokable method to create mock responses.
     */
    public function __invoke(string $method, string $url, array $options = []): ResponseInterface
    {
        // Record the request
        $this->requests[] = [
            'method' => $method,
            'url' => $url,
            'options' => $options,
        ];

        // Parse the URL to determine what we're being asked for
        $parsedUrl = parse_url($url);
        $path = $parsedUrl['path'] ?? '/';
        $query = $parsedUrl['query'] ?? '';

        // Handle discovery document
        if (str_contains($path, '.well-known/openid-configuration')) {
            return $this->createDiscoveryResponse();
        }

        // Handle JWKS
        if (str_contains($path, 'protocol/openid-connect/certs') || $this->isJwksUri($url)) {
            return $this->createJwksResponse();
        }

        // Handle token endpoint
        if (str_contains($path, 'protocol/openid-connect/token') || $this->isTokenEndpoint($url)) {
            return $this->createTokenResponse($method, $options);
        }

        // Handle userinfo endpoint
        if (str_contains($path, 'protocol/openid-connect/userinfo') || $this->isUserInfoEndpoint($url)) {
            return $this->createUserInfoResponse($method, $options);
        }

        // Handle end_session_endpoint
        if (str_contains($path, 'protocol/openid-connect/logout') || $this->isEndSessionEndpoint($url)) {
            return new MockResponse('', ['http_code' => 204]);
        }

        // Handle authorization endpoint (should not be called directly by the app)
        if (str_contains($path, 'protocol/openid-connect/auth') || $this->isAuthorizationEndpoint($url)) {
            return new MockResponse('', [
                'http_code' => 501,
                'reason_phrase' => 'Authorization endpoint should not be called directly',
            ]);
        }

        // Default: return 501 with the URL in the body
        return new MockResponse($url, ['http_code' => 501, 'reason_phrase' => 'Unexpected request to ' . $url]);
    }

    /**
     * Set the expected authorization URL from the app's redirect.
     */
    public function expectAuthorization(string $url): void
    {
        $parsedUrl = parse_url($url);
        $query = $parsedUrl['query'] ?? '';

        parse_str($query, $params);

        $this->lastAuthorizationRequest = [
            'url' => $url,
            'params' => $params,
            'client_id' => $params['client_id'] ?? null,
            'redirect_uri' => $params['redirect_uri'] ?? null,
            'scope' => $params['scope'] ?? null,
            'state' => $params['state'] ?? null,
            'nonce' => $params['nonce'] ?? null,
            'code_challenge' => $params['code_challenge'] ?? null,
            'code_challenge_method' => $params['code_challenge_method'] ?? null,
            'max_age' => $params['max_age'] ?? null,
            'prompt' => $params['prompt'] ?? null,
            'login_hint' => $params['login_hint'] ?? null,
            'ui_locales' => $params['ui_locales'] ?? null,
        ];
    }

    /**
     * Issue a fresh authorization code bound to the expected request.
     */
    public function issueCode(): string
    {
        if (null === $this->lastAuthorizationRequest) {
            throw new \LogicException(
                'Authorization request must be set via expectAuthorization() before issuing a code.',
            );
        }

        $code = 'auth-code-' . ++$this->codeCounter . '-' . bin2hex(random_bytes(8));

        $this->issuedCodes[$code] = $this->lastAuthorizationRequest;

        return $code;
    }

    /**
     * Set the signing key to use for ID tokens (for testing different keys).
     */
    public function signWith(\Jose\Component\Core\JWK $key): void
    {
        $this->customSigningKey = $key;
    }

    /**
     * Set a claim to omit from the ID token.
     */
    public function withoutClaimInIdToken(string $claim): void
    {
        $this->withoutClaims[] = $claim;
    }

    /**
     * Set a custom nonce for the ID token.
     */
    public function withNonce(string $nonce): void
    {
        $this->customNonce = $nonce;
    }

    /**
     * Set to omit auth_time from ID token.
     */
    public function withoutAuthTime(): void
    {
        $this->withoutAuthTime = true;
    }

    /**
     * Set custom user info for the UserInfo endpoint.
     */
    public function asUser(string $sub, string $username, string $email, array $realmRoles): void
    {
        $this->customSub = $sub;
        $this->customUsername = $username;
        $this->customEmail = $email;
        $this->customRealmRoles = $realmRoles;
    }

    /**
     * Set the UserInfo sub to differ from ID token sub (for failure testing).
     */
    public function withUserInfoSub(string $sub): void
    {
        // only the UserInfo response changes: the ID token keeps the real sub, so the two disagree
        $this->userInfoSub = $sub;
    }

    /**
     * Get all recorded requests.
     */
    public function requests(): array
    {
        return $this->requests;
    }

    /**
     * Create the discovery document response.
     */
    private function createDiscoveryResponse(): MockResponse
    {
        $discovery = [
            'issuer' => $this->issuer,
            'authorization_endpoint' => $this->issuer . '/protocol/openid-connect/auth',
            'token_endpoint' => $this->issuer . '/protocol/openid-connect/token',
            'userinfo_endpoint' => $this->issuer . '/protocol/openid-connect/userinfo',
            'jwks_uri' => $this->issuer . '/protocol/openid-connect/certs',
            'end_session_endpoint' => $this->issuer . '/protocol/openid-connect/logout',
            'id_token_signing_alg_values_supported' => ['RS256', 'ES256'],
        ];

        return new MockResponse(json_encode($discovery), [
            'http_code' => 200,
            'header' => ['Content-Type: application/json'],
        ]);
    }

    /**
     * Create the JWKS response.
     */
    private function createJwksResponse(): MockResponse
    {
        $jwks = TestKeys::jwks();

        return new MockResponse(json_encode($jwks), [
            'http_code' => 200,
            'header' => ['Content-Type: application/json'],
        ]);
    }

    /**
     * Create the token endpoint response.
     */
    private function createTokenResponse(string $method, array $options): MockResponse
    {
        if ($method !== 'POST') {
            return new MockResponse(
                json_encode(['error' => 'invalid_request', 'error_description' => 'Method must be POST']),
                [
                    'http_code' => 400,
                    'header' => ['Content-Type: application/json'],
                ],
            );
        }

        // Parse the request body
        $body = $options['body'] ?? '';

        if (is_array($body)) {
            $params = $body;
        } else {
            $params = [];
            if (is_string($body)) {
                parse_str($body, $params);
            }
        }

        // Extract authorization header
        $authHeader = $options['normalized_headers']['authorization'][0] ?? null;
        $authBasic = $options['auth_basic'] ?? null;

        // Check grant type
        if (($params['grant_type'] ?? null) !== 'authorization_code') {
            return new MockResponse(
                json_encode([
                    'error' => 'unsupported_grant_type',
                    'error_description' => 'Only authorization_code is supported',
                ]),
                [
                    'http_code' => 400,
                    'header' => ['Content-Type: application/json'],
                ],
            );
        }

        $code = $params['code'] ?? null;
        $redirectUri = $params['redirect_uri'] ?? null;
        $clientId = $params['client_id'] ?? null;
        $codeVerifier = $params['code_verifier'] ?? null;

        // Validate the authorization code
        if (!isset($this->issuedCodes[$code])) {
            return new MockResponse(
                json_encode(['error' => 'invalid_grant', 'error_description' => 'Invalid authorization code']),
                [
                    'http_code' => 400,
                    'header' => ['Content-Type: application/json'],
                ],
            );
        }

        $authorizationRequest = $this->issuedCodes[$code];

        // Validate redirect URI matches the authorization request
        if ($redirectUri !== $authorizationRequest['redirect_uri']) {
            return new MockResponse(
                json_encode(['error' => 'invalid_grant', 'error_description' => 'redirect_uri mismatch']),
                [
                    'http_code' => 400,
                    'header' => ['Content-Type: application/json'],
                ],
            );
        }

        // Validate client authentication
        $expectedClientId = $authorizationRequest['client_id'];
        $isPublicClient = false;

        if (str_ends_with($expectedClientId, '-test')) {
            $baseClientId = substr($expectedClientId, 0, -5); // Remove '-test'

            // Check for public client (no secret)
            if ($baseClientId === 'symfony-demo-public') {
                $isPublicClient = true;

                // Public clients must not send any authentication
                if (($params['client_secret'] ?? null) !== null || $authBasic !== null || $authHeader !== null) {
                    return new MockResponse(
                        json_encode([
                            'error' => 'invalid_client',
                            'error_description' => 'Public client must not send client_secret',
                        ]),
                        [
                            'http_code' => 400,
                            'header' => ['Content-Type: application/json'],
                        ],
                    );
                }
            } else {
                // Confidential clients must authenticate
                $hasValidAuth = false;

                // Check for client_secret in body
                if (isset($params['client_secret'])) {
                    $clientSecret = $params['client_secret'];
                    $expectedSecret = $this->getExpectedClientSecret($expectedClientId);
                    if ($clientSecret === $expectedSecret) {
                        $hasValidAuth = true;
                    }
                }

                // Check for HTTP Basic
                if ($authBasic !== null) {
                    // auth_basic is passed as ['username' => 'client_id', 'password' => 'client_secret']
                    if (is_array($authBasic)) {
                        $username = $authBasic['username'] ?? null;
                        $password = $authBasic['password'] ?? null;
                        if ($username === $expectedClientId) {
                            $expectedSecret = $this->getExpectedClientSecret($expectedClientId);
                            if ($password === $expectedSecret) {
                                $hasValidAuth = true;
                            }
                        }
                    }
                }

                // Check Authorization header
                $basicCredentials = self::authorizationCredentials($options, 'Basic');
                if ($basicCredentials !== null) {
                    $decoded = base64_decode($basicCredentials);
                    if ($decoded !== false) {
                        $parts = explode(':', $decoded, 2);
                        if (count($parts) === 2) {
                            $username = $parts[0];
                            $password = $parts[1] ?? '';
                            if ($username === $expectedClientId) {
                                $expectedSecret = $this->getExpectedClientSecret($expectedClientId);
                                if ($password === $expectedSecret) {
                                    $hasValidAuth = true;
                                }
                            }
                        }
                    }
                }

                if (!$hasValidAuth) {
                    return new MockResponse(
                        json_encode([
                            'error' => 'invalid_client',
                            'error_description' => 'Invalid client authentication',
                        ]),
                        [
                            'http_code' => 401,
                            'header' => ['Content-Type: application/json'],
                        ],
                    );
                }
            }
        }

        // Validate PKCE
        $codeChallengeMethod = $authorizationRequest['code_challenge_method'] ?? null;
        $codeChallenge = $authorizationRequest['code_challenge'] ?? null;

        if ($codeChallengeMethod !== null && $codeChallenge !== null) {
            if ($codeVerifier === null) {
                return new MockResponse(
                    json_encode(['error' => 'invalid_grant', 'error_description' => 'Missing code_verifier']),
                    [
                        'http_code' => 400,
                        'header' => ['Content-Type: application/json'],
                    ],
                );
            }

            if ($codeChallengeMethod === 'S256') {
                // RFC 7636, Section 4.2: BASE64URL(SHA256(code_verifier)) without padding
                $expectedChallenge = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');
                if (!hash_equals($expectedChallenge, $codeChallenge)) {
                    return new MockResponse(
                        json_encode([
                            'error' => 'invalid_grant',
                            'error_description' => 'PKCE code_verifier does not match code_challenge',
                        ]),
                        [
                            'http_code' => 400,
                            'header' => ['Content-Type: application/json'],
                        ],
                    );
                }
            } elseif ($codeChallengeMethod === 'plain') {
                if (!hash_equals($codeVerifier, $codeChallenge)) {
                    return new MockResponse(
                        json_encode([
                            'error' => 'invalid_grant',
                            'error_description' => 'PKCE code_verifier does not match code_challenge',
                        ]),
                        [
                            'http_code' => 400,
                            'header' => ['Content-Type: application/json'],
                        ],
                    );
                }
            }
        }

        // All validations passed - issue tokens
        $nonce = $authorizationRequest['nonce'] ?? bin2hex(random_bytes(16));
        if ($this->customNonce !== null) {
            $nonce = $this->customNonce;
        }

        // Determine which key to sign with based on client_id
        $signingKeyPair = $this->getSigningKeyForClient($expectedClientId);

        if ($this->customSigningKey !== null) {
            $signingKeyPair = [
                'private_key' => $this->customSigningKey,
                'public_key' => null, // We don't need the public key for signing
            ];
        }

        // Create ID token claims
        $idTokenClaims = [
            'iss' => $this->issuer,
            'aud' => $expectedClientId,
            'azp' => $expectedClientId,
            'sub' => $this->customSub ?? '11111111-1111-4111-8111-111111111111',
            'exp' => time() + 300,
            'iat' => time(),
            'nonce' => $nonce,
            'auth_time' => $this->withoutAuthTime ? null : time(),
            'preferred_username' => $this->customUsername ?? 'alice',
            'email' => $this->customEmail ?? 'alice@example.com',
            'email_verified' => true,
            'name' => 'Alice User',
            'given_name' => 'Alice',
            'family_name' => 'User',
        ];

        // Remove claims that should be omitted
        foreach ($this->withoutClaims as $claim) {
            unset($idTokenClaims[$claim]);
        }

        // Filter out null values
        $idTokenClaims = array_filter($idTokenClaims, function ($value) {
            return $value !== null;
        });

        // Create ID token
        $idToken = $this->createIdToken($idTokenClaims, $signingKeyPair['private_key']);

        // Create access token (opaque)
        $accessToken = 'access-token-' . bin2hex(random_bytes(16));

        // Create refresh token
        $refreshToken = 'refresh-token-' . bin2hex(random_bytes(16));

        // Determine scope
        $scope = $authorizationRequest['scope'] ?? 'openid';

        // Create response
        $response = [
            'token_type' => 'Bearer',
            'expires_in' => 300,
            'scope' => $scope,
            'session_state' => 'session-state-' . bin2hex(random_bytes(8)),
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken,
            'id_token' => $idToken,
        ];

        // Clean up the used code
        unset($this->issuedCodes[$code]);

        return new MockResponse(json_encode($response), [
            'http_code' => 200,
            'header' => ['Content-Type: application/json'],
        ]);
    }

    /**
     * Create the UserInfo response.
     */
    private function createUserInfoResponse(string $method, array $options): MockResponse
    {
        if ($method !== 'GET') {
            return new MockResponse(
                json_encode(['error' => 'invalid_request', 'error_description' => 'Method must be GET']),
                [
                    'http_code' => 400,
                    'header' => ['Content-Type: application/json'],
                ],
            );
        }

        // Check for Authorization header
        $authHeader = $options['normalized_headers']['authorization'][0] ?? null;
        $authBearer = $options['auth_bearer'] ?? null;

        if ($authBearer === null && $authHeader === null) {
            return new MockResponse(
                json_encode(['error' => 'invalid_request', 'error_description' => 'Missing Authorization header']),
                [
                    'http_code' => 401,
                    'header' => ['Content-Type: application/json'],
                ],
            );
        }

        // Extract the access token from the Authorization header
        $accessToken =
            self::authorizationCredentials($options, 'Bearer') ?? (is_string($authBearer) ? $authBearer : null);

        // Check if this access token was issued by us
        // For simplicity, we accept any token that starts with 'access-token-'
        if ($accessToken === null || !str_starts_with($accessToken, 'access-token-')) {
            return new MockResponse(
                json_encode(['error' => 'invalid_token', 'error_description' => 'Invalid access token']),
                [
                    'http_code' => 401,
                    'header' => ['Content-Type: application/json'],
                ],
            );
        }

        // Return user info
        $userInfo = [
            'sub' => $this->userInfoSub ?? $this->customSub ?? '11111111-1111-4111-8111-111111111111',
            'preferred_username' => $this->customUsername ?? 'alice',
            'email' => $this->customEmail ?? 'alice@example.com',
            'email_verified' => true,
            'name' => 'Alice User',
            'given_name' => 'Alice',
            'family_name' => 'User',
            'realm_access' => [
                'roles' => $this->customRealmRoles !== [] ? $this->customRealmRoles : ['admin', 'editor'],
            ],
        ];

        return new MockResponse(json_encode($userInfo), [
            'http_code' => 200,
            'header' => ['Content-Type: application/json'],
        ]);
    }

    /**
     * Create a signed ID token JWT.
     */
    private function createIdToken(array $claims, \Jose\Component\Core\JWK $privateKey): string
    {
        // Create algorithm manager with the appropriate algorithm
        $algorithmManager = new AlgorithmManager([
            new RS256(),
            new ES256(),
            new PS256(),
        ]);

        // Determine the algorithm based on the key
        $alg = $privateKey->get('alg', 'RS256');

        $jwsBuilder = new JWSBuilder($algorithmManager);

        // Build the JWS with the claims as payload
        $jws = $jwsBuilder
            ->create()
            ->withPayload(JsonConverter::encode($claims))
            ->addSignature($privateKey, [
                'alg' => $alg,
                'kid' => $privateKey->get('kid', 'unknown'),
                'typ' => 'JWT',
            ])
            ->build();

        // Serialize to compact form
        $serializer = new CompactSerializer();
        return $serializer->serialize($jws);
    }

    /**
     * Get the expected client secret for a given client ID.
     */
    private function getExpectedClientSecret(string $clientId): string
    {
        $mapping = [
            'symfony-demo-test' => 'symfony-demo-secret-test',
            'symfony-demo-es256-test' => 'symfony-demo-es256-secret-test',
            'symfony-demo-plain-test' => 'symfony-demo-plain-secret-test',
            'symfony-demo-public-test' => '', // Public client has no secret
            'symfony-demo' => 'symfony-demo-secret-test', // fallback for non-test env
            'symfony-demo-es256' => 'symfony-demo-es256-secret-test',
            'symfony-demo-plain' => 'symfony-demo-plain-secret-test',
            'symfony-demo-public' => '',
        ];

        return $mapping[$clientId] ?? 'test-secret';
    }

    /**
     * Get the signing key pair for a given client ID.
     */
    private function getSigningKeyForClient(string $clientId): array
    {
        // ES256 clients use the EC key
        if (str_contains($clientId, 'es256') || str_contains($clientId, 'es256-test')) {
            return TestKeys::providerEcKey();
        }

        // Default to RSA key
        return TestKeys::providerRsaKey();
    }

    /**
     * Check if URL is a JWKS URI.
     */
    private function isJwksUri(string $url): bool
    {
        return str_contains($url, '/protocol/openid-connect/certs');
    }

    /**
     * Check if URL is a token endpoint.
     */
    private function isTokenEndpoint(string $url): bool
    {
        return str_contains($url, '/protocol/openid-connect/token');
    }

    /**
     * Check if URL is a UserInfo endpoint.
     */
    private function isUserInfoEndpoint(string $url): bool
    {
        return str_contains($url, '/protocol/openid-connect/userinfo');
    }

    /**
     * Check if URL is an end session endpoint.
     */
    private function isEndSessionEndpoint(string $url): bool
    {
        return str_contains($url, '/protocol/openid-connect/logout');
    }

    /**
     * Check if URL is an authorization endpoint.
     */
    private function isAuthorizationEndpoint(string $url): bool
    {
        return str_contains($url, '/protocol/openid-connect/auth');
    }

    /**
     * Create a mock client for testing purposes.
     */
    public static function createMockClient(): MockHttpClient
    {
        return new MockHttpClient(new self());
    }

    /**
     * The mock transport hands the request headers as "Name: value" lines: this returns the
     * credentials of the Authorization header for the given scheme, or null.
     */
    private static function authorizationCredentials(array $options, string $scheme): ?string
    {
        foreach ($options['normalized_headers']['authorization'] ?? [] as $line) {
            if (preg_match('/^Authorization:\s*' . $scheme . '\s+(\S+)$/i', (string) $line, $m)) {
                return $m[1];
            }
        }

        return null;
    }
}
