<?php

namespace App\Security;

use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\Security\Http\Event\OidcAuthorizationRequestEvent;

/**
 * Tailors the authorization request of the "hint" firewall to the request that starts it.
 *
 * OidcAuthorizationRequestEvent is dispatched on the event dispatcher of the firewall every
 * time the authenticator is about to redirect the user to the provider, from the start route
 * as well as from the entry point, with the parameters "authorization_params" configures. A
 * listener may add, change or remove any of them, except the protocol parameters the
 * authenticator manages itself (state, nonce, redirect_uri, code_challenge...), which it
 * refuses. A global listener is enough: the bundle copies it onto every firewall dispatcher.
 */
#[AsEventListener]
final class LoginHintListener
{
    private const FIREWALL = 'hint';

    // the locales the Keycloak realm offers
    private const LOCALES = ['en', 'fr'];

    public function __invoke(OidcAuthorizationRequestEvent $event): void
    {
        // the event is dispatched for every oidc_login firewall
        if (self::FIREWALL !== $event->getFirewallName()) {
            return;
        }

        $request = $event->getRequest();

        // login_hint prefills the username field of the Keycloak login page. It comes from
        // the query string, so it is only a hint: the user can still type another username,
        // and nothing is trusted from it once the provider has authenticated the user.
        $loginHint = $request->query->getString('login_hint');
        if (1 === preg_match('/^[\w.@+-]{1,64}$/', $loginHint)) {
            $event->setParam('login_hint', $loginHint);
        }

        // ui_locales asks the provider to display its pages in the language the browser prefers
        $event->setParam('ui_locales', $request->getPreferredLanguage(self::LOCALES) ?? self::LOCALES[0]);
    }
}
