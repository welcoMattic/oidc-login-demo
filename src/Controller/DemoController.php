<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Core\User\OidcUser;
use Symfony\Component\Security\Http\Attribute\CurrentUser;

class DemoController extends AbstractController
{
    private const PROVIDERS = [
        ['key' => 'keycloak', 'label' => 'Keycloak', 'user' => 'alice / password', 'ready' => true],
        ['key' => 'authentik', 'label' => 'Authentik', 'user' => 'bob / password', 'ready' => true],
        // The Gravitee AM stack boots but its domain/application/user are not provisioned
        // yet (management API login unresolved), see the README.
        ['key' => 'gravitee', 'label' => 'Gravitee AM', 'user' => 'carol / password', 'ready' => false],
    ];

    #[Route('/', name: 'app_home')]
    public function home(): Response
    {
        return $this->render('home.html.twig', ['providers' => self::PROVIDERS]);
    }

    #[Route('/keycloak', name: 'app_keycloak')]
    public function keycloak(#[CurrentUser] ?OidcUser $user): Response
    {
        return $this->profile('keycloak', 'Keycloak', $user);
    }

    #[Route('/authentik', name: 'app_authentik')]
    public function authentik(#[CurrentUser] ?OidcUser $user): Response
    {
        return $this->profile('authentik', 'Authentik', $user);
    }

    #[Route('/gravitee', name: 'app_gravitee')]
    public function gravitee(#[CurrentUser] ?OidcUser $user): Response
    {
        return $this->profile('gravitee', 'Gravitee AM', $user);
    }

    private function profile(string $key, string $label, ?OidcUser $user): Response
    {
        return $this->render('profile.html.twig', [
            'key' => $key,
            'label' => $label,
            'user' => $user,
        ]);
    }
}
