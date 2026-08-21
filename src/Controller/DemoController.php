<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\OidcUser;

class DemoController extends AbstractController
{
    /**
     * What each firewall of config/packages/security.yaml is set up to show, so the
     * result on screen can be read against the options that produced it.
     */
    private const PROVIDERS = [
        'keycloak' => [
            'label' => 'Keycloak 26.7',
            'credentials' => 'alice / password',
            'issuer' => 'https://localhost:8443/realms/demo',
            'admin' => 'https://localhost:8443/admin/ (admin / admin)',
            'options' => [
                'scope: [openid, profile, email]' => 'asks the provider for a name and an email',
                'user_identifier_claim: email' => 'the identity is the "email" claim, not "sub"',
                'user_data_source: userinfo' => 'the claims below come from the UserInfo endpoint',
                'token_endpoint_auth_method: client_secret_basic' => 'the secret went in an HTTP Basic header',
                'pkce: { enabled: true, method: S256 }' => 'the code was bound to a one-time verifier',
                'enable_end_session: true' => 'logging out ends the session at Keycloak too',
                'direct_redirect: true' => 'reaching this page redirected straight to the provider',
            ],
        ],
        'gravitee' => [
            'label' => 'Gravitee AM 4',
            'credentials' => 'carol / Gravitee!2026',
            'issuer' => 'https://localhost:9443/demo/oidc',
            'admin' => 'http://localhost:8084/ (admin / adminadmin)',
            'options' => [
                'user_data_source: id_token' => 'the claims below were decoded from the ID token, with no UserInfo request',
                'user_identifier_claim: sub' => 'the identity is the "sub" claim (the default)',
                'token_endpoint_auth_method: client_secret_post' => 'the secret went in the request body (the default)',
                'enable_end_session: true' => 'logging out ends the session at Gravitee too',
                'direct_redirect: true' => 'reaching this page redirected straight to the provider',
            ],
        ],
        'public' => [
            'label' => 'Keycloak 26.7, as a public client',
            'credentials' => 'alice / password',
            'issuer' => 'https://localhost:8443/realms/demo',
            'admin' => 'https://localhost:8443/admin/ (admin / admin)',
            'options' => [
                'token_endpoint_auth_method: none' => 'no client secret was sent at the token endpoint',
                'client_secret: not set' => 'this firewall has none, the client_id is the whole identification',
                'pkce: enabled' => 'the only thing binding the authorization code to this client',
                'id_token_signature: verified' => 'cannot be turned off for a public client',
            ],
        ],
    ];

    public function __construct(
        private readonly TokenStorageInterface $tokenStorage,
    ) {
    }

    #[Route('/', name: 'app_home')]
    public function home(): Response
    {
        return $this->render('home.html.twig', ['providers' => self::PROVIDERS]);
    }

    #[Route('/keycloak', name: 'app_keycloak')]
    public function keycloak(): Response
    {
        return $this->profile('keycloak');
    }

    #[Route('/gravitee', name: 'app_gravitee')]
    public function gravitee(): Response
    {
        return $this->profile('gravitee');
    }

    #[Route('/public', name: 'app_public')]
    public function publicClient(): Response
    {
        return $this->profile('public');
    }

    private function profile(string $key): Response
    {
        $token = $this->tokenStorage->getToken();
        $user = $token?->getUser();

        // the ID token the authenticator received is kept on the security token; it is
        // decoded here for display only, its claims were validated at login
        $idTokenClaims = $this->decodePayload($token?->hasAttribute('oidc_id_token') ? $token->getAttribute('oidc_id_token') : null);

        return $this->render('profile.html.twig', [
            'firewall' => $key,
            'provider' => self::PROVIDERS[$key],
            'user' => $user,
            'userClass' => null === $user ? null : $user::class,
            'standardClaims' => $user instanceof OidcUser ? $this->standardClaims($user) : [],
            'additionalClaims' => $user instanceof OidcUser ? $this->prettyJson($user->getAdditionalClaims()) : null,
            'idTokenClaims' => null === $idTokenClaims ? null : $this->prettyJson($idTokenClaims),
            'hasAccessToken' => (bool) ($token?->hasAttribute('oidc_access_token') ? $token->getAttribute('oidc_access_token') : null),
        ]);
    }

    /**
     * The OIDC standard claims the user object carries, in their protocol spelling.
     *
     * @return array<string, string>
     */
    private function standardClaims(OidcUser $user): array
    {
        $claims = [
            'sub' => $user->getSub(),
            'name' => $user->getName(),
            'given_name' => $user->getGivenName(),
            'family_name' => $user->getFamilyName(),
            'nickname' => $user->getNickname(),
            'preferred_username' => $user->getPreferredUsername(),
            'email' => $user->getEmail(),
            'email_verified' => $user->getEmailVerified(),
            'locale' => $user->getLocale(),
            'zoneinfo' => $user->getZoneinfo(),
            'picture' => $user->getPicture(),
            'website' => $user->getWebsite(),
            'phone_number' => $user->getPhoneNumber(),
            'birthdate' => $user->getBirthdate(),
            'gender' => $user->getGender(),
            'updated_at' => $user->getUpdatedAt()?->format(\DATE_ATOM),
        ];

        $claims = array_filter($claims, static fn ($value) => null !== $value);

        return array_map(static fn ($value) => \is_bool($value) ? ($value ? 'true' : 'false') : (string) $value, $claims);
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function prettyJson(array $claims): ?string
    {
        return [] === $claims ? null : json_encode($claims, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE);
    }

    /**
     * @return array<string, mixed>|null
     */
    private function decodePayload(mixed $jwt): ?array
    {
        if (!\is_string($jwt) || 3 !== \count($parts = explode('.', $jwt))) {
            return null;
        }

        $payload = base64_decode(str_pad(strtr($parts[1], '-_', '+/'), 4 * (int) ceil(\strlen($parts[1]) / 4), '='), true);
        if (!\is_string($payload) || !\is_array($claims = json_decode($payload, true))) {
            return null;
        }

        return $claims;
    }
}
