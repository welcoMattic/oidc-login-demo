<?php

namespace App\Tests\Oidc;

use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Psr\Clock\ClockInterface;
use Symfony\Component\Clock\NativeClock;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Contracts\HttpClient\ResponseInterface;

/**
 * Mock response factory for testing OIDC authentication.
 *
 * This class intercepts HTTP requests to the fake Keycloak provider and returns
 * appropriate mock responses based on the request type and parameters.
 *
 * Every token it issues is dated with the clock it is given, which in tests is the
 * MockClock the application checks the tokens against: moving that clock forward
 * moves both sides together.
 */
final class FakeKeycloak
{
    private const ISSUER = 'https://keycloak.example.test/realms/demo';
    private const ISSUER_NO_TRAILING_SLASH = 'https://keycloak.example.test/realms/demo';

    public const DEFAULT_SUB = '11111111-1111-4111-8111-111111111111';

    // the access token lifespan of the realm, and the shorter one of the clients that set their own
    private const ACCESS_TOKEN_LIFESPAN = 300;
    private const CLIENT_ACCESS_TOKEN_LIFESPANS = ['symfony-demo-refresh-test' => 60];

    // RFC 7523, Section 2.2
    private const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

    // how long the assertions of the demo clients live, the "lifetime" of their firewalls
    private const CLIENT_ASSERTION_LIFETIME = 60;

    // client_secret_jwt: the provider holds the shared secret the client keys its HMAC with
    private const JWT_CLIENT_ID = 'symfony-demo-jwt-test';

    // private_key_jwt: the provider only holds the public half of the key OIDC_PKJWT_CLIENT_KEY holds
    private const PKJWT_CLIENT_ID = 'symfony-demo-pkjwt-test';
    private const PKJWT_CLIENT_PUBLIC_KEY = [
        'kid' => 'symfony-demo-client-test',
        'use' => 'sig',
        'alg' => 'ES256',
        'kty' => 'EC',
        'crv' => 'P-256',
        'x' => '0jwwqqatKthIo8uJPPgFBXAZiQutSbUmLvJtL-nB1GY',
        'y' => 'lv386AYdUeK3tfGeoirTqoVmB02PENy_UIT-HyzFb78',
    ];

    private string $issuer;
    private ?array $lastAuthorizationRequest = null;

    /**
     * The pending authorization codes, with what the fake knows about the request behind each one.
     *
     * @var array<string, array{client_id: string, redirect_uri: ?string, scope: string, nonce: ?string, code_challenge: ?string, code_challenge_method: ?string, authentication: array{auth_time: int, acr: string, amr: list<string>}}>
     */
    private array $issuedCodes = [];

    /**
     * The live refresh tokens, each one used once: a refresh grant replaces it with a new one.
     *
     * @var array<string, array{client_id: string, sub: string, scope: string, authentication: array{auth_time: int, acr: string, amr: list<string>}}>
     */
    private array $refreshTokens = [];

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
    private ?JWK $customSigningKey = null;
    private ?int $ssoAuthenticatedAt = null;
    private ?string $refreshRejectionError = null;
    private int $refreshRejectionStatus = 400;
    private ?string $registeredJwtClientSecret = null;
    private ?JWK $registeredPkjwtClientKey = null;

    /** @var array<string, true> */
    private array $usedAssertionIds = [];

    /** @var list<string> */
    private array $tokenErrors = [];

    /** @var list<array{token_type: string, expires_in: int, scope: string, session_state: string, access_token: string, refresh_token: string, id_token: string}> */
    private array $tokenResponses = [];

    /** @var list<array{method: string, url: string, options: array}> */
    private array $requests = [];

    private int $codeCounter = 0;

    private readonly ClockInterface $clock;

    /**
     * @param ClockInterface|null $clock The clock the tokens are dated with, which must be the one the
     *                                   application checks them against (the "clock" service in tests)
     */
    public function __construct(?ClockInterface $clock = null)
    {
        $this->clock = $clock ?? new NativeClock();
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
        $this->refreshTokens = [];
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
        $this->ssoAuthenticatedAt = null;
        $this->refreshRejectionError = null;
        $this->refreshRejectionStatus = 400;
        $this->registeredJwtClientSecret = null;
        $this->registeredPkjwtClientKey = null;
        $this->usedAssertionIds = [];
        $this->tokenErrors = [];
        $this->tokenResponses = [];
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
            return $this->createTokenResponse($method, $this->issuer . '/protocol/openid-connect/token', $options);
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
     *
     * This is the moment the fake "authenticates" the user: with the password right now, or
     * from the SSO session withSsoSession() opened, unless the request asks for prompt=login,
     * which Keycloak always answers with a fresh password check.
     */
    public function issueCode(): string
    {
        $request = $this->lastAuthorizationRequest;

        if (null === $request) {
            throw new \LogicException(
                'Authorization request must be set via expectAuthorization() before issuing a code.',
            );
        }

        $code = 'auth-code-' . ++$this->codeCounter . '-' . bin2hex(random_bytes(8));

        $this->issuedCodes[$code] = [
            'client_id' => self::stringOrNull($request['client_id'] ?? null) ?? '',
            'redirect_uri' => self::stringOrNull($request['redirect_uri'] ?? null),
            'scope' => self::stringOrNull($request['scope'] ?? null) ?? 'openid',
            'nonce' => self::stringOrNull($request['nonce'] ?? null),
            'code_challenge' => self::stringOrNull($request['code_challenge'] ?? null),
            'code_challenge_method' => self::stringOrNull($request['code_challenge_method'] ?? null),
            'authentication' => $this->authenticate(self::stringOrNull($request['prompt'] ?? null)),
        ];

        return $code;
    }

    /**
     * Set the signing key to use for ID tokens (for testing different keys).
     */
    public function signWith(JWK $key): void
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
     * Opens a Keycloak SSO session, as if the user had typed their password at $authenticatedAt.
     *
     * An authorization request without prompt=login is then answered from that session, without
     * any password: the ID token carries the old "auth_time" and the "acr" Keycloak gives an SSO
     * login, "0" (a password typed in this very flow gets "1"). A prompt=login request checks the
     * password again, which moves the session forward to that new authentication.
     */
    public function withSsoSession(int $authenticatedAt): void
    {
        $this->ssoAuthenticatedAt = $authenticatedAt;
    }

    /**
     * Makes the token endpoint refuse every refresh grant from now on, with this error.
     *
     * "invalid_grant" is what a revoked refresh token or an expired SSO session gets; any other
     * error (e.g. "temporarily_unavailable" with a 503) is a failure the client may retry.
     */
    public function rejectRefreshTokens(string $error = 'invalid_grant', int $status = 400): void
    {
        $this->refreshRejectionError = $error;
        $this->refreshRejectionStatus = $status;
    }

    /**
     * Replaces the secret the provider holds for the client_secret_jwt client.
     */
    public function withRegisteredClientSecret(#[\SensitiveParameter] string $secret): void
    {
        $this->registeredJwtClientSecret = $secret;
    }

    /**
     * Replaces the public key the provider holds for the private_key_jwt client.
     */
    public function withRegisteredClientKey(JWK $publicKey): void
    {
        $this->registeredPkjwtClientKey = $publicKey;
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
     * The token endpoint requests, oldest first: their form parameters, and the Authorization
     * header when one was sent.
     *
     * @return list<array{params: array<array-key, string>, authorization: ?string}>
     */
    public function tokenRequests(): array
    {
        $tokenRequests = [];

        foreach ($this->requests as $request) {
            if ('POST' === $request['method'] && $this->isTokenEndpoint($request['url'])) {
                $tokenRequests[] = [
                    'params' => self::formParameters($request['options']),
                    'authorization' => self::authorizationHeader($request['options']),
                ];
            }
        }

        return $tokenRequests;
    }

    /**
     * The form parameters of the token endpoint requests made with this grant type, oldest first.
     *
     * @return list<array<array-key, string>>
     */
    public function tokenRequestsFor(string $grantType): array
    {
        $params = [];

        foreach ($this->tokenRequests() as $request) {
            if ($grantType === ($request['params']['grant_type'] ?? null)) {
                $params[] = $request['params'];
            }
        }

        return $params;
    }

    /**
     * The successful token endpoint responses, oldest first.
     *
     * @return list<array{token_type: string, expires_in: int, scope: string, session_state: string, access_token: string, refresh_token: string, id_token: string}>
     */
    public function tokenResponses(): array
    {
        return $this->tokenResponses;
    }

    /**
     * Why the token endpoint turned requests down, oldest first, as "error: description".
     *
     * @return list<string>
     */
    public function tokenErrors(): array
    {
        return $this->tokenErrors;
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
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'token_endpoint_auth_methods_supported' => [
                'client_secret_basic',
                'client_secret_post',
                'client_secret_jwt',
                'private_key_jwt',
            ],
            'token_endpoint_auth_signing_alg_values_supported' => ['HS256', 'ES256', 'RS256', 'PS256'],
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
    private function createTokenResponse(string $method, string $tokenEndpoint, array $options): MockResponse
    {
        if ($method !== 'POST') {
            return $this->tokenError('invalid_request', 'Method must be POST');
        }

        $params = self::formParameters($options);

        return match ($params['grant_type'] ?? null) {
            'authorization_code' => $this->grantAuthorizationCode($tokenEndpoint, $params, $options),
            'refresh_token' => $this->grantRefreshToken($tokenEndpoint, $params, $options),
            default => $this->tokenError(
                'unsupported_grant_type',
                'Only authorization_code and refresh_token are supported',
            ),
        };
    }

    /**
     * The authorization code grant of RFC 6749, Section 4.1.3.
     *
     * @param array<array-key, string> $params
     */
    private function grantAuthorizationCode(string $tokenEndpoint, array $params, array $options): MockResponse
    {
        $code = $params['code'] ?? '';

        // Validate the authorization code
        if (!isset($this->issuedCodes[$code])) {
            return $this->tokenError('invalid_grant', 'Invalid authorization code');
        }

        $authorizationRequest = $this->issuedCodes[$code];

        // Validate redirect URI matches the authorization request
        if (($params['redirect_uri'] ?? null) !== $authorizationRequest['redirect_uri']) {
            return $this->tokenError('invalid_grant', 'redirect_uri mismatch');
        }

        $clientId = $authorizationRequest['client_id'];

        $rejection = $this->authenticateClient($clientId, $tokenEndpoint, $params, $options);
        if (null !== $rejection) {
            return $rejection;
        }

        // Validate PKCE
        $codeChallengeMethod = $authorizationRequest['code_challenge_method'];
        $codeChallenge = $authorizationRequest['code_challenge'];

        if ($codeChallengeMethod !== null && $codeChallenge !== null) {
            $codeVerifier = $params['code_verifier'] ?? null;

            if ($codeVerifier === null) {
                return $this->tokenError('invalid_grant', 'Missing code_verifier');
            }

            // RFC 7636, Section 4.2: BASE64URL(SHA256(code_verifier)) without padding for S256
            $expectedChallenge = match ($codeChallengeMethod) {
                'S256' => rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '='),
                default => $codeVerifier,
            };

            if (!hash_equals($expectedChallenge, $codeChallenge)) {
                return $this->tokenError('invalid_grant', 'PKCE code_verifier does not match code_challenge');
            }
        }

        // All validations passed: the code is used up, and the tokens are issued
        unset($this->issuedCodes[$code]);

        $nonce = $this->customNonce ?? $authorizationRequest['nonce'] ?? bin2hex(random_bytes(16));

        return $this->issueTokens(
            $clientId,
            $this->customSub ?? self::DEFAULT_SUB,
            $authorizationRequest['scope'],
            $authorizationRequest['authentication'],
            $nonce,
        );
    }

    /**
     * The refresh token grant of RFC 6749, Section 6.
     *
     * The refresh token is rotated, as Keycloak does: the one presented is used up, and the
     * response carries its replacement, a new access token and a new ID token, which describes
     * the same authentication (same "sub", same "auth_time") and carries no "nonce".
     *
     * @param array<array-key, string> $params
     */
    private function grantRefreshToken(string $tokenEndpoint, array $params, array $options): MockResponse
    {
        $refreshToken = $params['refresh_token'] ?? '';

        if (!isset($this->refreshTokens[$refreshToken])) {
            return $this->tokenError('invalid_grant', 'Invalid refresh token');
        }

        $session = $this->refreshTokens[$refreshToken];

        $rejection = $this->authenticateClient($session['client_id'], $tokenEndpoint, $params, $options);
        if (null !== $rejection) {
            return $rejection;
        }

        if (null !== $this->refreshRejectionError) {
            return $this->tokenError(
                $this->refreshRejectionError,
                'The refresh token is no longer honored',
                $this->refreshRejectionStatus,
            );
        }

        unset($this->refreshTokens[$refreshToken]);

        return $this->issueTokens(
            $session['client_id'],
            $session['sub'],
            $session['scope'],
            $session['authentication'],
        );
    }

    /**
     * Checks how the client authenticates at the token endpoint, the way its registration says.
     *
     * Returns the error response, or null once the client is authenticated.
     *
     * @param array<array-key, string> $params
     */
    private function authenticateClient(
        string $clientId,
        string $tokenEndpoint,
        array $params,
        array $options,
    ): ?MockResponse {
        // only the clients of the test environment are registered here
        if (!str_ends_with($clientId, '-test')) {
            return null;
        }

        // the client_id of the body, which OidcClient always sends, must name the client itself
        if (isset($params['client_id']) && $params['client_id'] !== $clientId) {
            return $this->tokenError('invalid_client', 'client_id does not match the grant');
        }

        $authorization = self::authorizationHeader($options);

        // Public clients must not send any authentication
        if ($clientId === 'symfony-demo-public-test') {
            if (isset($params['client_secret']) || $authorization !== null) {
                return $this->tokenError('invalid_client', 'Public client must not send client_secret');
            }

            return null;
        }

        if ($clientId === self::JWT_CLIENT_ID || $clientId === self::PKJWT_CLIENT_ID) {
            return $this->authenticateClientAssertion($clientId, $tokenEndpoint, $params, $authorization);
        }

        // client_secret_post: the secret in the body
        $expectedSecret = $this->getExpectedClientSecret($clientId);
        if (isset($params['client_secret']) && hash_equals($expectedSecret, $params['client_secret'])) {
            return null;
        }

        // client_secret_basic: the mock transport turns auth_basic into the Authorization header
        $basicCredentials = self::authorizationCredentials($options, 'Basic');
        if ($basicCredentials !== null) {
            $decoded = base64_decode($basicCredentials, true);
            $parts = false !== $decoded ? explode(':', $decoded, 2) : [];

            if (count($parts) === 2 && hash_equals($clientId, $parts[0]) && hash_equals($expectedSecret, $parts[1])) {
                return null;
            }
        }

        return $this->tokenError('invalid_client', 'Invalid client authentication', 401);
    }

    /**
     * Checks the JWT a client_secret_jwt or private_key_jwt client authenticates with.
     *
     * The checks are the ones of RFC 7523, Section 3, and of OIDC Core 1.0, Section 9: the
     * signature with the credential registered for the client, the client as both issuer and
     * subject, the token endpoint as audience, a single use "jti", and the lifetime.
     *
     * @param array<array-key, string> $params
     */
    private function authenticateClientAssertion(
        string $clientId,
        string $tokenEndpoint,
        array $params,
        ?string $authorization,
    ): ?MockResponse {
        // the assertion replaces the secret: nothing else authenticates the client
        if (isset($params['client_secret']) || $authorization !== null) {
            return $this->tokenError('invalid_client', 'A client_secret must not travel with a client assertion');
        }

        if (self::CLIENT_ASSERTION_TYPE !== ($params['client_assertion_type'] ?? null)) {
            return $this->tokenError('invalid_client', 'Missing or unsupported client_assertion_type');
        }

        $assertion = $params['client_assertion'] ?? '';
        if ($assertion === '') {
            return $this->tokenError('invalid_client', 'Missing client_assertion');
        }

        $jws = self::parseJws($assertion);
        if (null === $jws) {
            return $this->tokenError('invalid_client', 'Malformed client_assertion');
        }

        if (self::JWT_CLIENT_ID === $clientId) {
            $algorithm = new HS256();
            $key = self::secretKey(
                $this->registeredJwtClientSecret ?? $this->getExpectedClientSecret(self::JWT_CLIENT_ID),
            );
        } else {
            $algorithm = new ES256();
            $key = $this->registeredPkjwtClientKey ?? new JWK(self::PKJWT_CLIENT_PUBLIC_KEY);
        }

        $header = $jws->getSignature(0)->getProtectedHeader();

        if ($algorithm->name() !== ($header['alg'] ?? null)) {
            return $this->tokenError('invalid_client', 'Unexpected client_assertion algorithm');
        }

        // the kid names the registered public key the assertion is verified with
        if ($key->has('kid') && $key->get('kid') !== ($header['kid'] ?? null)) {
            return $this->tokenError('invalid_client', 'Unknown client_assertion kid');
        }

        if (!self::verifySignature($jws, $algorithm, $key)) {
            return $this->tokenError('invalid_client', 'Invalid client_assertion signature');
        }

        $claims = self::jsonObject($jws->getPayload() ?? '');
        $now = $this->now();

        $problem = match (true) {
            ($claims['iss'] ?? null) !== $clientId => 'iss is not the client_id',
            ($claims['sub'] ?? null) !== $clientId => 'sub is not the client_id',
            !self::hasAudience($claims['aud'] ?? null, $tokenEndpoint) => 'aud is not the token endpoint',
            !is_string($claims['jti'] ?? null) || '' === $claims['jti'] => 'jti is missing',
            isset($this->usedAssertionIds[$claims['jti']]) => 'jti was already used',
            !is_int($claims['iat'] ?? null) || !is_int($claims['exp'] ?? null) => 'iat or exp is missing',
            $claims['exp'] <= $claims['iat'] => 'exp is not after iat',
            ($claims['exp'] - $claims['iat']) !== self::CLIENT_ASSERTION_LIFETIME => 'unexpected lifetime',
            $claims['iat'] > $now => 'iat is in the future',
            $claims['exp'] <= $now => 'the assertion expired',
            default => null,
        };

        if (null !== $problem) {
            return $this->tokenError('invalid_client', 'Invalid client_assertion: ' . $problem);
        }

        if (is_string($claims['jti'] ?? null)) {
            $this->usedAssertionIds[$claims['jti']] = true;
        }

        return null;
    }

    /**
     * Decides how the user is authenticated for an authorization request, as Keycloak does.
     *
     * @return array{auth_time: int, acr: string, amr: list<string>}
     */
    private function authenticate(?string $prompt): array
    {
        // answered from the SSO session: no password was typed in this flow
        if ('login' !== $prompt && null !== $this->ssoAuthenticatedAt) {
            return ['auth_time' => $this->ssoAuthenticatedAt, 'acr' => '0', 'amr' => ['pwd']];
        }

        $now = $this->now();

        // the password check refreshes the SSO session, when there is one
        if (null !== $this->ssoAuthenticatedAt) {
            $this->ssoAuthenticatedAt = $now;
        }

        return ['auth_time' => $now, 'acr' => '1', 'amr' => ['pwd']];
    }

    /**
     * Issues an access token, a refresh token and an ID token, and records the refresh token.
     *
     * @param array{auth_time: int, acr: string, amr: list<string>} $authentication
     */
    private function issueTokens(
        string $clientId,
        string $sub,
        string $scope,
        array $authentication,
        ?string $nonce = null,
    ): MockResponse {
        $now = $this->now();
        $lifespan = self::CLIENT_ACCESS_TOKEN_LIFESPANS[$clientId] ?? self::ACCESS_TOKEN_LIFESPAN;

        // Create ID token claims; a refreshed one has no nonce, no authorization request being involved
        $idTokenClaims = [
            'iss' => $this->issuer,
            'aud' => $clientId,
            'azp' => $clientId,
            'sub' => $sub,
            'exp' => $now + 300,
            'iat' => $now,
            'nonce' => $nonce,
            'auth_time' => $this->withoutAuthTime ? null : $authentication['auth_time'],
            'acr' => $authentication['acr'],
            'amr' => $authentication['amr'],
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
        $idTokenClaims = array_filter($idTokenClaims, static fn(mixed $value): bool => $value !== null);

        $accessToken = 'access-token-' . bin2hex(random_bytes(16));
        $refreshToken = 'refresh-token-' . bin2hex(random_bytes(16));

        $this->refreshTokens[$refreshToken] = [
            'client_id' => $clientId,
            'sub' => $sub,
            'scope' => $scope,
            'authentication' => $authentication,
        ];

        $response = [
            'token_type' => 'Bearer',
            'expires_in' => $lifespan,
            'scope' => $scope,
            'session_state' => 'session-state-' . bin2hex(random_bytes(8)),
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken,
            'id_token' => $this->createIdToken($idTokenClaims, $this->signingKeyFor($clientId)),
        ];

        $this->tokenResponses[] = $response;

        return self::json($response, 200);
    }

    /**
     * Records why a token request was turned down, and answers with the error of RFC 6749, Section 5.2.
     */
    private function tokenError(string $error, string $description, int $status = 400): MockResponse
    {
        $this->tokenErrors[] = $error . ': ' . $description;

        return self::json(['error' => $error, 'error_description' => $description], $status);
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
            'sub' => $this->userInfoSub ?? $this->customSub ?? self::DEFAULT_SUB,
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
    private function createIdToken(array $claims, JWK $privateKey): string
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
            'symfony-demo-refresh-test' => 'symfony-demo-refresh-secret-test',
            // client_secret_jwt: the secret never travels, it keys the HMAC of the client assertion
            'symfony-demo-jwt-test' => 'symfony-demo-jwt-secret-test-at-least-32-bytes',
            'symfony-demo-public-test' => '', // Public client has no secret
            'symfony-demo' => 'symfony-demo-secret-test', // fallback for non-test env
            'symfony-demo-es256' => 'symfony-demo-es256-secret-test',
            'symfony-demo-plain' => 'symfony-demo-plain-secret-test',
            'symfony-demo-public' => '',
        ];

        return $mapping[$clientId] ?? 'test-secret';
    }

    /**
     * The key the ID tokens of a client are signed with: ES256 clients get the EC key.
     */
    private function signingKeyFor(string $clientId): JWK
    {
        if (null !== $this->customSigningKey) {
            return $this->customSigningKey;
        }

        return str_contains($clientId, 'es256')
            ? TestKeys::providerEcKey()['private_key']
            : TestKeys::providerRsaKey()['private_key'];
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

    private function now(): int
    {
        return $this->clock->now()->getTimestamp();
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

    /**
     * The value of the Authorization header of a request, whatever its scheme, or null.
     */
    private static function authorizationHeader(array $options): ?string
    {
        $headers = $options['normalized_headers'] ?? null;
        if (!is_array($headers) || !isset($headers['authorization']) || !is_array($headers['authorization'])) {
            return null;
        }

        $line = $headers['authorization'][0] ?? null;

        return is_string($line) ? substr($line, strlen('Authorization: ')) : null;
    }

    /**
     * The form parameters of a request, which the mock transport hands as a url-encoded body.
     *
     * @return array<array-key, string>
     */
    private static function formParameters(array $options): array
    {
        $params = [];

        if (isset($options['body']) && is_string($options['body'])) {
            parse_str($options['body'], $params);
        } elseif (isset($options['body']) && is_array($options['body'])) {
            $params = $options['body'];
        }

        return array_filter($params, is_string(...));
    }

    private static function stringOrNull(mixed $value): ?string
    {
        return is_string($value) ? $value : null;
    }

    private static function parseJws(#[\SensitiveParameter] string $token): ?JWS
    {
        try {
            return new CompactSerializer()->unserialize($token);
        } catch (\InvalidArgumentException) {
            return null;
        }
    }

    private static function verifySignature(JWS $jws, Algorithm $algorithm, JWK $key): bool
    {
        try {
            return new JWSVerifier(new AlgorithmManager([$algorithm]))->verifyWithKey($jws, $key, 0);
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * The key an HMAC is keyed with, from the octets of the secret (OIDC Core 1.0, Section 10.1).
     */
    private static function secretKey(#[\SensitiveParameter] string $secret): JWK
    {
        return new JWK(['kty' => 'oct', 'k' => rtrim(strtr(base64_encode($secret), '+/', '-_'), '=')]);
    }

    /**
     * RFC 7519, Section 4.1.3: the audience is a string or an array of strings.
     */
    private static function hasAudience(mixed $audience, string $expected): bool
    {
        return $audience === $expected || is_array($audience) && in_array($expected, $audience, true);
    }

    /**
     * @return array<array-key, mixed>
     */
    private static function jsonObject(string $json): array
    {
        try {
            $decoded = json_decode($json, true, 512, \JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return [];
        }

        return is_array($decoded) ? $decoded : [];
    }

    /**
     * @param array<string, mixed> $payload
     */
    private static function json(array $payload, int $status): MockResponse
    {
        return new MockResponse(json_encode($payload, \JSON_THROW_ON_ERROR), [
            'http_code' => $status,
            'header' => ['Content-Type: application/json'],
        ]);
    }
}
