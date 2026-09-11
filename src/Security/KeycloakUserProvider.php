<?php

namespace App\Security;

use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\AttributesBasedUserProviderInterface;
use Symfony\Component\Security\Core\User\OidcUser;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Custom user provider that maps Keycloak realm roles onto Symfony roles.
 *
 * The identifier is always the verified "sub" claim from the OIDC flow.
 * Roles are computed here and nowhere else: the built-in "oidc" provider never lets
 * a claim grant a role (every user gets ROLE_USER only). This provider uses the
 * realm_access.roles claim from the UserInfo endpoint to grant additional roles.
 *
 * @implements AttributesBasedUserProviderInterface<OidcUser>
 */
final class KeycloakUserProvider implements AttributesBasedUserProviderInterface
{
    /**
     * @param array<string, mixed> $attributes All claims collected during authentication
     */
    public function loadUserByIdentifier(string $identifier, array $attributes = []): UserInterface
    {
        // The identifier is the verified "sub" claim from the OIDC flow.
        // Without it, the authentication cannot proceed.
        if (!isset($attributes['sub']) || !is_string($attributes['sub']) || '' === $attributes['sub']) {
            $exception = new UserNotFoundException('The "sub" claim is required for OIDC authentication.');
            $exception->setUserIdentifier($identifier);
            throw $exception;
        }

        // Drop any incoming "roles" claim before passing to OidcUser::fromClaims,
        // since that would map onto the roles constructor argument and grant privileges
        // from the provider that we do not trust. Only the computed roles below are valid.
        unset($attributes['roles']);

        // Compute roles from Keycloak realm roles.
        // The realm-roles-userinfo protocol mapper in the Keycloak realm configuration
        // maps realm roles to the "realm_access.roles" claim in the UserInfo response.
        $roles = ['ROLE_USER'];
        if (isset($attributes['realm_access']['roles']) && is_array($attributes['realm_access']['roles'])) {
            foreach ($attributes['realm_access']['roles'] as $role) {
                if (is_string($role) && ($role === 'admin' || $role === 'editor')) {
                    $roles[] = 'ROLE_' . strtoupper($role);
                }
            }
        }

        // Build the OidcUser with the verified sub as the identifier and the computed roles.
        // The claims passed to fromClaims include all the user data from the provider,
        // which OidcUser maps onto its standard claim properties.
        $claims = $attributes;
        $claims['userIdentifier'] = $identifier;
        $claims['roles'] = $roles;

        return OidcUser::fromClaims($claims);
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
        if (!$user instanceof OidcUser) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', $user::class));
        }

        // OidcUser is self-contained: no refresh needed, return it unchanged.
        return $user;
    }

    public function supportsClass(string $class): bool
    {
        return OidcUser::class === $class;
    }
}
