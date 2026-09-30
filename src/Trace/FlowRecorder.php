<?php

namespace App\Trace;

use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;
use Symfony\Component\Security\Http\Oidc\OidcDiscovery;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Builds the complete login flow trace when authentication succeeds.
 *
 * This listener runs on LoginSuccessEvent and captures all the details of
 * the OIDC authentication flow that just completed, storing them in the
 * session for display on the account page.
 */
#[AsEventListener(event: LoginSuccessEvent::class, priority: 0)]
final class FlowRecorder
{
    private const SESSION_TRACE_PREFIX = 'oidc_demo.trace.';
    private const SESSION_PENDING_PREFIX = 'oidc_demo.pending.';

    public function __construct(
        private OidcHttpRecorder $httpRecorder,
        #[Autowire(service: 'app.oidc_discovery')]
        private OidcDiscovery $discovery,
        private RequestStack $requestStack,
        private HttpClientInterface $httpClient,
        private \App\Oidc\JwtDecoder $jwtDecoder,
    ) {}

    public function __invoke(LoginSuccessEvent $event): void
    {
        $request = $this->requestStack->getCurrentRequest();

        // Only proceed if we have a request with a session
        if (null === $request || !$request->hasSession()) {
            return;
        }

        $session = $request->getSession();
        $firewall = $event->getFirewallName();
        $token = $event->getAuthenticatedToken();
        $passport = $event->getPassport();

        // Get the callback request query parameters
        $callbackQuery = $request->query->all();
        $callbackState = $callbackQuery['state'] ?? null;

        if (!is_string($callbackState)) {
            return;
        }

        // Find and remove the matching pending entry
        $pendingKey = self::SESSION_PENDING_PREFIX . $callbackState;
        $pendingEntry = $session->get($pendingKey);
        $session->remove($pendingKey);

        if (!is_array($pendingEntry)) {
            return;
        }

        // Get discovery configuration
        try {
            $discoveryConfig = $this->discovery->getConfiguration();
        } catch (\Exception) {
            $discoveryConfig = [];
        }

        // Classify HTTP exchanges
        $classifiedExchanges = $this->classifyExchanges($discoveryConfig);

        // Get scenario info
        $scenario = \App\Demo\Scenarios::get($firewall) ?? [];
        $providerClass = $scenario['provider'] ?? 'Symfony\Component\Security\Core\User\OidcUserProvider';
        $allowedTimeDrift = $scenario['allowed_time_drift'] ?? 0;
        $maxAge = $scenario['max_age'] ?? null;
        $userDataSource = $scenario['user_data_source'] ?? 'userinfo';
        $userIdentifierClaim = $scenario['user_identifier_claim'] ?? 'sub';

        // Build the trace
        $trace = $this->buildTrace(
            $pendingEntry,
            $callbackQuery,
            $classifiedExchanges,
            $discoveryConfig,
            $passport,
            $event,
            $firewall,
            $providerClass,
            $allowedTimeDrift,
            $maxAge,
            $userDataSource,
            $userIdentifierClaim,
            $request,
        );

        // Store in session
        $session->set(self::SESSION_TRACE_PREFIX . $firewall, $trace);
    }

    /**
     * Classify HTTP exchanges by endpoint type.
     *
     * @return array<string, array> Map of kind -> list of exchange data
     */
    private function classifyExchanges(array $discoveryConfig): array
    {
        $classified = [
            'discovery' => [],
            'token' => [],
            'jwks' => [],
            'userinfo' => [],
            'other' => [],
        ];

        $tokenEndpoint = $discoveryConfig['token_endpoint'] ?? null;
        $userinfoEndpoint = $discoveryConfig['userinfo_endpoint'] ?? null;
        $jwksUri = $discoveryConfig['jwks_uri'] ?? null;
        $discoveryUrl = $discoveryConfig['issuer'] ?? null;
        if (null !== $discoveryUrl) {
            $discoveryUrl = rtrim($discoveryUrl, '/') . '/.well-known/openid-configuration';
        }

        foreach ($this->httpRecorder->getExchanges() as $exchange) {
            $url = $exchange['url'];

            $kind = 'other';

            if ($discoveryUrl !== null && str_contains($url, $discoveryUrl)) {
                $kind = 'discovery';
            } elseif ($tokenEndpoint !== null && str_contains($url, $tokenEndpoint)) {
                $kind = 'token';
            } elseif ($userinfoEndpoint !== null && str_contains($url, $userinfoEndpoint)) {
                $kind = 'userinfo';
            } elseif ($jwksUri !== null && str_contains($url, $jwksUri)) {
                $kind = 'jwks';
            }

            $classified[$kind][] = $this->buildExchangeData($exchange, $kind, $discoveryConfig);
        }

        return $classified;
    }

    /**
     * Build exchange data for the trace.
     */
    private function buildExchangeData(array $exchange, string $kind, array $discoveryConfig): array
    {
        $url = $exchange['url'];
        $method = $exchange['method'];
        $options = $exchange['options'];
        $response = $exchange['response'];

        $data = [
            'method' => $method,
            'url' => $url,
        ];

        // Determine request auth method
        $requestAuth = $this->getRequestAuth($options);
        if (null !== $requestAuth) {
            $data['request_auth'] = $requestAuth;
        }

        // Request headers
        $headers = $options['headers'] ?? [];
        $requestHeaders = [];
        foreach ($headers as $name => $value) {
            if (is_array($value)) {
                $value = implode(', ', $value);
            }
            $requestHeaders[$name] = $value;
        }
        $data['request_headers'] = $requestHeaders;

        // Request body
        $body = $options['body'] ?? null;
        if (null !== $body) {
            if (is_array($body)) {
                $bodyData = $body;
            } elseif (is_string($body)) {
                // Parse form data
                parse_str($body, $bodyData);
                if (!is_array($bodyData) || count($bodyData) === 0) {
                    $bodyData = $body;
                }
            } else {
                $bodyData = $body;
            }

            if (is_array($bodyData)) {
                // Keep important fields, redact client_secret
                $filteredBody = [];
                foreach ($bodyData as $key => $value) {
                    if ($key === 'client_secret') {
                        $filteredBody[$key] = '***';
                    } elseif ($key === 'client_assertion' && is_string($value)) {
                        // the assertion is a credential for its short lifetime: shown decoded, never whole
                        $filteredBody[$key] = '<jwt, ' . strlen($value) . ' chars, decoded below>';
                        try {
                            $data['client_assertion'] = $this->jwtDecoder::decode($value);
                        } catch (\InvalidArgumentException) {
                            $filteredBody[$key] = '<' . strlen($value) . ' chars, not a JWT>';
                        }
                    } else {
                        $filteredBody[$key] = $value;
                    }
                }
                $data['request_body'] = $filteredBody;
            } else {
                $data['request_body'] = $bodyData;
            }
        }

        // Response status
        try {
            $statusCode = $response->getStatusCode();
            $data['response_status'] = $statusCode;
        } catch (\Exception) {
            $data['response_status'] = null;
        }

        // Summarized response content based on kind
        try {
            $content = $response->getContent(false);
            $data['response_summary'] = $this->summarizeResponse($content, $kind, $discoveryConfig);
        } catch (\Exception) {
            $data['response_summary'] = null;
        }

        return $data;
    }

    /**
     * Determine request authentication method from options.
     */
    private function getRequestAuth(array $options): ?string
    {
        if (isset($options['auth_bearer'])) {
            $token = $options['auth_bearer'];
            if (is_string($token)) {
                $truncated = substr($token, 0, 24) . (strlen($token) > 24 ? '...' : '');
                return 'Authorization: Bearer ' . $truncated;
            }
        }

        if (isset($options['auth_basic'])) {
            return 'Authorization: Basic <client_id>:***';
        }

        $body = isset($options['body']) && is_array($options['body']) ? $options['body'] : [];

        // Check if client_secret is in body
        if (isset($body['client_secret'])) {
            return 'client_secret in the request body (redacted)';
        }

        // A JWT assertion the client signed itself (RFC 7523): with its secret for
        // client_secret_jwt, with its private key for private_key_jwt
        if (isset($body['client_assertion']) && is_string($body['client_assertion'])) {
            try {
                $header = $this->jwtDecoder::decode($body['client_assertion'])['header'];
            } catch (\InvalidArgumentException) {
                return 'client_assertion: a JWT the client signed';
            }

            $alg = is_string($header['alg'] ?? null) ? $header['alg'] : 'unknown';
            $method = str_starts_with($alg, 'HS')
                ? 'client_secret_jwt, keyed with the client secret, which is not sent'
                : 'private_key_jwt, signed with the private key of the client';

            return sprintf(
                'client_assertion: a JWT signed with %s%s (%s)',
                $alg,
                is_string($header['kid'] ?? null) ? ', kid ' . $header['kid'] : '',
                $method,
            );
        }

        // Public client
        return 'none: a public client sends no credentials';
    }

    /**
     * Summarize response content based on the exchange kind.
     */
    private function summarizeResponse(string $content, string $kind, array $discoveryConfig): array
    {
        if ($content === '') {
            return [];
        }

        try {
            $json = json_decode($content, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return ['raw' => $content];
        }

        if (!is_array($json)) {
            return ['raw' => $content];
        }

        switch ($kind) {
            case 'discovery':
                // Only include issuer and endpoint URLs
                $result = [];
                foreach ($json as $key => $value) {
                    if ($key === 'issuer' || str_ends_with($key, '_endpoint') || $key === 'jwks_uri') {
                        $result[$key] = $value;
                    }
                }
                return $result;

            case 'token':
                // Hide token values, show metadata
                $result = [];
                foreach ($json as $key => $value) {
                    switch ($key) {
                        case 'id_token':
                            $result[$key] = '<jwt, ' . strlen($value) . ' chars>';
                            break;
                        case 'access_token':
                            $result[$key] = '<jwt, ' . strlen($value) . ' chars>';
                            break;
                        case 'refresh_token':
                            $result[$key] = '<present>';
                            break;
                        default:
                            $result[$key] = $value;
                            break;
                    }
                }
                return $result;

            case 'jwks':
                // Reduce keys to essential fields
                if (isset($json['keys']) && is_array($json['keys'])) {
                    $simplifiedKeys = [];
                    foreach ($json['keys'] as $key) {
                        $simplified = [];
                        foreach (['kid', 'kty', 'alg', 'use', 'crv'] as $field) {
                            if (isset($key[$field])) {
                                $simplified[$field] = $key[$field];
                            }
                        }
                        $simplifiedKeys[] = $simplified;
                    }
                    return ['keys' => $simplifiedKeys];
                }
                return $json;

            case 'userinfo':
                // Return claims as-is (these are the user's claims)
                return $json;

            default:
                return $json;
        }
    }

    /**
     * Build the complete trace array.
     */
    private function buildTrace(
        array $pendingEntry,
        array $callbackQuery,
        array $classifiedExchanges,
        array $discoveryConfig,
        object $passport,
        LoginSuccessEvent $event,
        string $firewall,
        string $providerClass,
        int $allowedTimeDrift,
        ?int $maxAge,
        string $userDataSource,
        string $userIdentifierClaim,
        \Symfony\Component\HttpFoundation\Request $request,
    ): array {
        $token = $event->getAuthenticatedToken();
        $user = $token->getUser();

        // Get token data and user badge attributes using public API
        $tokenData = $passport->getAttribute('oidc_token_data');

        /** @var \Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge|null $userBadge */
        $userBadge = $passport->getBadge(\Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge::class);
        $userBadgeAttributes = $userBadge?->getAttributes() ?? [];

        // Decode ID token if available
        $idTokenDecoded = null;
        $signatureKey = null;
        $keySource = null;

        if (isset($tokenData['id_token']) && is_string($tokenData['id_token'])) {
            try {
                $idTokenDecoded = $this->jwtDecoder::decode($tokenData['id_token']);

                // Try to find the matching JWKS key
                if (isset($idTokenDecoded['header']['kid'])) {
                    $keyData = $this->findMatchingJwksKey(
                        $idTokenDecoded['header']['kid'],
                        $classifiedExchanges,
                        $discoveryConfig,
                    );
                    if ($keyData !== null) {
                        $signatureKey = $keyData;
                        $keySource = $keyData['source'];
                    }
                }
            } catch (\Exception) {
                // Keep null if decoding fails
            }
        }

        // Parse timestamps
        $startedAtStr = $pendingEntry['started_at'];
        $finishedAt = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));

        try {
            $startedAt = new \DateTimeImmutable($startedAtStr, new \DateTimeZone('UTC'));
        } catch (\Exception) {
            $startedAt = $finishedAt;
        }

        $durationMs = (int) round(((float) $finishedAt->format('U.u') - (float) $startedAt->format('U.u')) * 1000);
        if ($durationMs < 0) {
            $durationMs = 0;
        }

        // Build checks
        $checks = $this->buildChecks(
            $callbackQuery,
            $tokenData,
            $idTokenDecoded,
            $userBadgeAttributes,
            $discoveryConfig,
            $firewall,
            $allowedTimeDrift,
            $maxAge,
            $signatureKey,
            $keySource,
            $userDataSource,
            $userIdentifierClaim,
        );

        // Get client_id for this firewall
        $clientId = $this->getClientIdForFirewall($firewall);

        // Build token attributes stored on security token
        $tokenAttributes = array_keys($token->getAttributes());

        // Build trace
        return [
            'started_at' => $startedAt->format('Y-m-d\TH:i:s.u\Z'),
            'finished_at' => $finishedAt->format('Y-m-d\TH:i:s.u\Z'),
            'duration_ms' => $durationMs,
            'firewall' => $firewall,
            'trigger' => $pendingEntry['trigger'],
            're_authentication_attribute' => $pendingEntry['re_authentication_attribute'] ?? null,
            'requested_path' => $pendingEntry['requested_path'],
            'provider' => $providerClass,
            'client_id' => $clientId,
            'user_data_source' => $userDataSource,
            'user_identifier_claim' => $userIdentifierClaim,
            'auth_request' => [
                'endpoint' => $pendingEntry['endpoint'],
                'params' => $pendingEntry['params'],
            ],
            'callback' => [
                'path' => $request->getPathInfo(),
                'query' => [
                    'code' => substr($callbackQuery['code'] ?? '', 0, 16) . '...',
                    'state' => $callbackQuery['state'] ?? null,
                    'session_state' => $callbackQuery['session_state'] ?? null,
                    'iss' => $callbackQuery['iss'] ?? null,
                ],
            ],
            'exchanges' => $classifiedExchanges,
            'token_data' => $this->summarizeTokenData($tokenData),
            'user_badge' => $userBadgeAttributes,
            'id_token_decoded' => $idTokenDecoded,
            'signature_key' => $signatureKey,
            'authenticated_token' => [
                'user_class' => $user::class,
                'identifier' => $user->getUserIdentifier(),
                'roles' => $user->getRoles(),
                'attributes' => $tokenAttributes,
            ],
            'user' => [
                'class' => $user::class,
                'identifier' => $user->getUserIdentifier(),
                'roles' => $user->getRoles(),
            ],
            'checks' => $checks,
        ];
    }

    /**
     * Find the matching JWKS key for the given kid.
     */
    private function findMatchingJwksKey(string $kid, array $classifiedExchanges, array $discoveryConfig): ?array
    {
        // First, check if we have JWKS exchanges from this login
        if (!empty($classifiedExchanges['jwks'])) {
            foreach ($classifiedExchanges['jwks'] as $exchange) {
                if (isset($exchange['response_summary']['keys']) && is_array($exchange['response_summary']['keys'])) {
                    foreach ($exchange['response_summary']['keys'] as $key) {
                        if (isset($key['kid']) && $key['kid'] === $kid) {
                            $key['source'] = 'fetched from jwks_uri during this login';
                            return $key;
                        }
                    }
                }
            }
        }

        // If no JWKS exchange was recorded, fetch it now
        $jwksUri = null;
        try {
            $jwksUri = $this->discovery->getSecureEndpoint('jwks_uri');
        } catch (\Exception) {
            return null;
        }

        if (null === $jwksUri) {
            return null;
        }

        try {
            // Use the recorder-decorated http client
            $response = $this->httpClient->request('GET', $jwksUri);
            $content = $response->getContent(false);

            try {
                $json = json_decode($content, true, 512, JSON_THROW_ON_ERROR);
            } catch (\JsonException) {
                return null;
            }

            if (isset($json['keys']) && is_array($json['keys'])) {
                foreach ($json['keys'] as $key) {
                    if (isset($key['kid']) && $key['kid'] === $kid) {
                        // Reduce to essential fields
                        $simplified = [];
                        foreach (['kid', 'kty', 'alg', 'use', 'crv'] as $field) {
                            if (isset($key[$field])) {
                                $simplified[$field] = $key[$field];
                            }
                        }
                        $simplified['source'] = 'cached from an earlier login, refetched here for display';
                        return $simplified;
                    }
                }
            }
        } catch (\Exception) {
            return null;
        }

        return null;
    }

    /**
     * Build the checks list.
     */
    private function buildChecks(
        array $callbackQuery,
        ?array $tokenData,
        ?array $idTokenDecoded,
        ?array $userBadgeAttributes,
        array $discoveryConfig,
        string $firewall,
        int $allowedTimeDrift,
        ?int $maxAge,
        ?array $signatureKey,
        ?string $keySource,
        string $userDataSource,
        string $userIdentifierClaim,
    ): array {
        $checks = [];

        // state check
        $checks[] = [
            'label' => 'state',
            'detail' => 'Callback state matched the pending attempt, compared in constant time, then consumed',
            'ok' => true,
        ];

        // signature check
        if ($signatureKey !== null && $idTokenDecoded !== null) {
            $header = $idTokenDecoded['header'] ?? [];
            $alg = $header['alg'] ?? 'unknown';
            $kid = $header['kid'] ?? 'unknown';
            $kty = $signatureKey['kty'] ?? 'unknown';

            $checks[] = [
                'label' => 'signature',
                'detail' => sprintf('alg: %s, kid: %s, key type: %s, %s', $alg, $kid, $kty, $keySource ?? 'unknown'),
                'ok' => true,
            ];
        } else {
            $header = $idTokenDecoded['header'] ?? [];
            $alg = $header['alg'] ?? 'unknown';
            $kid = $header['kid'] ?? 'unknown';

            $checks[] = [
                'label' => 'signature',
                'detail' => sprintf('alg: %s, kid: %s, key type: unknown', $alg, $kid),
                'ok' => true,
            ];
        }

        // iss check
        $issuer = $discoveryConfig['issuer'] ?? '';
        $idTokenIss = $idTokenDecoded !== null && isset($idTokenDecoded['payload']['iss'])
            ? $idTokenDecoded['payload']['iss']
            : '';
        $checks[] = [
            'label' => 'iss',
            'detail' => sprintf('iss: %s, expected: %s', $idTokenIss, $issuer),
            'ok' => true,
        ];

        // aud check
        $clientId = $this->getClientIdForFirewall($firewall);
        $aud = $idTokenDecoded !== null && isset($idTokenDecoded['payload']['aud'])
            ? $idTokenDecoded['payload']['aud']
            : '';
        $checks[] = [
            'label' => 'aud',
            'detail' => sprintf('aud: %s, contains: %s', is_array($aud) ? implode(', ', $aud) : $aud, $clientId),
            'ok' => true,
        ];

        // azp check
        $azp = $idTokenDecoded !== null && isset($idTokenDecoded['payload']['azp'])
            ? $idTokenDecoded['payload']['azp']
            : '';
        if ($azp !== '') {
            $checks[] = [
                'label' => 'azp',
                'detail' => sprintf('azp: %s, expected: %s', $azp, $clientId),
                'ok' => true,
            ];
        }

        // Time-based checks
        $timeFields = ['exp', 'iat', 'nbf'];
        foreach ($timeFields as $field) {
            $value = $idTokenDecoded !== null && isset($idTokenDecoded['payload'][$field])
                ? $idTokenDecoded['payload'][$field]
                : null;
            if (is_int($value)) {
                $checks[] = [
                    'label' => $field,
                    'detail' => sprintf(
                        '%s: %s, now: %s, allowed drift: %d seconds',
                        $field,
                        date('c', $value),
                        date('c'),
                        $allowedTimeDrift,
                    ),
                    'ok' => true,
                ];
            }
        }

        // nonce check
        $nonce = $idTokenDecoded !== null && isset($idTokenDecoded['payload']['nonce'])
            ? $idTokenDecoded['payload']['nonce']
            : '';
        $checks[] = [
            'label' => 'nonce',
            'detail' => sprintf('ID token nonce: %s, matched the one sent in the authorization request', $nonce),
            'ok' => true,
        ];

        // auth_time: checked against max_age when the scenario sets it, and recorded in any case
        // as the time of the authentication proof that IS_AUTHENTICATED_RECENTLY reads
        $authTime = $idTokenDecoded !== null && isset($idTokenDecoded['payload']['auth_time'])
            ? $idTokenDecoded['payload']['auth_time']
            : null;
        if (is_int($authTime)) {
            $checks[] = [
                'label' => 'auth_time',
                'detail' => $maxAge !== null
                    ? sprintf(
                        'auth_time: %s, max_age: %d seconds, age: %d seconds',
                        date('c', $authTime),
                        $maxAge,
                        time() - $authTime,
                    )
                    : sprintf(
                        'auth_time: %s, %d seconds ago: when Keycloak last checked your credentials, kept as the time of the authentication proof (no max_age to check it against)',
                        date('c', $authTime),
                        time() - $authTime,
                    ),
                'ok' => true,
            ];
        }

        // sub check
        $idTokenSub = $idTokenDecoded !== null && isset($idTokenDecoded['payload']['sub'])
            ? $idTokenDecoded['payload']['sub']
            : '';
        $userInfoSub = $userBadgeAttributes !== null && isset($userBadgeAttributes['sub'])
            ? $userBadgeAttributes['sub']
            : '';

        if ('id_token' === $userDataSource) {
            $checks[] = [
                'label' => 'sub',
                'detail' => 'sub taken from the validated ID token (no UserInfo cross-check)',
                'ok' => true,
            ];
        } else {
            $checks[] = [
                'label' => 'sub',
                'detail' => sprintf('UserInfo sub matches the ID token sub: %s', $idTokenSub),
                'ok' => true,
            ];
        }

        return $checks;
    }

    /**
     * Get client ID for a firewall.
     */
    private function getClientIdForFirewall(string $firewall): string
    {
        $scenarios = \App\Demo\Scenarios::get($firewall);
        return $scenarios['client_id'] ?? 'unknown';
    }

    /**
     * Summarize token data for the trace.
     */
    private function summarizeTokenData(?array $tokenData): array
    {
        if (null === $tokenData) {
            return [];
        }

        return [
            'token_type' => $tokenData['token_type'] ?? null,
            'expires_in' => $tokenData['expires_in'] ?? null,
            'scope' => $tokenData['scope'] ?? null,
            'refresh_token_present' => isset($tokenData['refresh_token']),
            'raw_id_token' =>
                substr($tokenData['id_token'] ?? '', 0, 50)
                    . (isset($tokenData['id_token']) && strlen($tokenData['id_token']) > 50 ? '...' : ''),
            'access_token_length' => isset($tokenData['access_token']) ? strlen($tokenData['access_token']) : 0,
        ];
    }
}
