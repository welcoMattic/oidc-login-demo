<?php

namespace App\Controller;

use App\Demo\Scenarios;
use App\Oidc\JwtDecoder;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

class DemoController extends AbstractController
{
    public function __construct(
        private readonly TokenStorageInterface $tokenStorage,
    ) {
    }

    #[Route('/', name: 'app_home')]
    public function home(AuthenticationUtils $authenticationUtils): Response
    {
        // Get the last authentication error for display on the home page
        // (useful when failure_path redirects back to /)
        $error = $authenticationUtils->getLastAuthenticationError();

        return $this->render('home.html.twig', [
            'scenarios' => Scenarios::all(),
            'error' => $error,
        ]);
    }

    #[Route('/{firewall}/account', name: 'app_account', requirements: ['firewall' => 'default|basic|public|strict|es256|plain|roles'])]
    public function account(string $firewall): Response
    {
        $token = $this->tokenStorage->getToken();
        $user = $token?->getUser();
        $scenario = Scenarios::get($firewall);

        if (!$scenario) {
            throw $this->createNotFoundException("Unknown firewall: {$firewall}");
        }

        // Decode the ID token for display if present
        $idTokenData = null;
        if ($token?->hasAttribute('oidc_id_token')) {
            $idToken = $token->getAttribute('oidc_id_token');
            if (is_string($idToken) && $idToken !== '') {
                try {
                    $idTokenData = JwtDecoder::decode($idToken);
                } catch (\Exception) {
                    // Keep $idTokenData null if decoding fails
                }
            }
        }

        // Check for access token attribute
        $hasAccessToken = $token?->hasAttribute('oidc_access_token') && is_string($token->getAttribute('oidc_access_token'));

        return $this->render('account.html.twig', [
            'firewall' => $firewall,
            'scenario' => $scenario,
            'user' => $user,
            'userClass' => $user ? $user::class : null,
            'idTokenData' => $idTokenData,
            'hasAccessToken' => $hasAccessToken,
        ]);
    }
}