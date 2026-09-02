<?php

namespace App\Security;

use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken;
use Symfony\Component\Security\Http\Event\LogoutEvent;
use Symfony\Component\Security\Http\Oidc\OidcDiscovery;

/**
 * RP-Initiated Logout (OpenID Connect RP-Initiated Logout 1.0) is not part of the
 * core feature in Symfony 8.2: the core logout only ends the Symfony session.
 *
 * This listener is application code showing how to end the provider session too.
 * It runs before the default logout listener (priority 65 vs the default 0) so
 * it can set the redirect response first.
 *
 * When the security token carries the "oidc_id_token" attribute (set by the
 * OidcLoginAuthenticator on successful authentication), this listener builds
 * a redirect to the provider's end_session_endpoint with the ID token as
 * id_token_hint and the home page URL as post_logout_redirect_uri.
 *
 * Keycloak then sends the browser back to post_logout_redirect_uri, which must
 * be registered on the client.
 */
#[AsEventListener(event: LogoutEvent::class, priority: 65)]
final class RpInitiatedLogoutListener
{
    public function __construct(
        #[Autowire(service: 'app.oidc_discovery')]
        private OidcDiscovery $discovery,
    ) {
    }

    public function __invoke(LogoutEvent $event): void
    {
        $token = $event->getToken();

        // Only act if this is a token created by the OIDC authenticator
        // (which sets the oidc_id_token and oidc_access_token attributes).
        if (!$token instanceof PostAuthenticationToken) {
            return;
        }

        if (!$token->hasAttribute('oidc_id_token')) {
            return;
        }

        $idToken = $token->getAttribute('oidc_id_token');
        if (!is_string($idToken) || '' === $idToken) {
            return;
        }

        try {
            $endSessionEndpoint = $this->discovery->getSecureEndpoint('end_session_endpoint');
        } catch (AuthenticationException) {
            // Provider does not support RP-Initiated Logout
            return;
        }

        // Build the post_logout_redirect_uri: absolute URL of the app home route
        $postLogoutRedirectUri = $event->getRequest()->getSchemeAndHttpHost() . '/';

        $url = $endSessionEndpoint . '?' . http_build_query([
            'id_token_hint' => $idToken,
            'post_logout_redirect_uri' => $postLogoutRedirectUri,
        ], '', '&', PHP_QUERY_RFC3986);

        $event->setResponse(new RedirectResponse($url));
    }
}