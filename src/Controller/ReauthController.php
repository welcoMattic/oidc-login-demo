<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Http\Attribute\IsGranted;

/**
 * The sensitive page of the "reauth" scenario.
 *
 * Its #[IsGranted] attribute is what triggers the re-authentication: once the last proof of
 * the user's identity is older than very_recent_authentication_lifetime, AuthenticatedVoter
 * denies IS_AUTHENTICATED_VERY_RECENTLY and asks for a re-authentication, and the firewall
 * hands the request to its re-authentication entry point, the oidc_login authenticator,
 * instead of answering 403. After the new login, the user lands back here.
 */
final class ReauthController extends AbstractController
{
    #[Route('/reauth/sensitive', name: 'app_reauth_sensitive')]
    #[IsGranted('IS_AUTHENTICATED_VERY_RECENTLY')]
    public function sensitive(
        TokenStorageInterface $tokenStorage,
        #[Autowire(param: 'security.very_recent_authentication_lifetime')]
        int $lifetime,
    ): Response {
        $token = $tokenStorage->getToken();

        return $this->render('sensitive.html.twig', [
            'user' => $token?->getUser(),
            'proofs' => $token?->getAuthenticationProofs() ?? [],
            'acr' => $token?->hasAttribute('oidc_acr') ? $token->getAttribute('oidc_acr') : null,
            'lifetime' => $lifetime,
            'now' => time(),
        ]);
    }
}
