<?php

namespace App\Tests\Unit\Security;

use App\Security\KeycloakUserProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\OidcUser;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Unit tests for KeycloakUserProvider.
 */
class KeycloakUserProviderTest extends TestCase
{
    private KeycloakUserProvider $provider;

    protected function setUp(): void
    {
        $this->provider = new KeycloakUserProvider();
    }

    /**
     * Test that admin and editor roles are mapped correctly.
     */
    public function testRoleMapping(): void
    {
        $attributes = [
            'sub' => '11111111-1111-4111-8111-111111111111',
            'preferred_username' => 'alice',
            'email' => 'alice@example.com',
            'realm_access' => [
                'roles' => ['admin', 'editor'],
            ],
        ];

        $user = $this->provider->loadUserByIdentifier('11111111-1111-4111-8111-111111111111', $attributes);

        $this->assertInstanceOf(OidcUser::class, $user);
        $this->assertEquals('11111111-1111-4111-8111-111111111111', $user->getUserIdentifier());
        
        $roles = $user->getRoles();
        $this->assertContains('ROLE_USER', $roles);
        $this->assertContains('ROLE_ADMIN', $roles);
        $this->assertContains('ROLE_EDITOR', $roles);
    }

    /**
     * Test that unknown realm roles are ignored.
     */
    public function testUnknownRolesIgnored(): void
    {
        $attributes = [
            'sub' => '11111111-1111-4111-8111-111111111111',
            'preferred_username' => 'alice',
            'realm_access' => [
                'roles' => ['admin', 'unknown_role', 'viewer'],
            ],
        ];

        $user = $this->provider->loadUserByIdentifier('11111111-1111-4111-8111-111111111111', $attributes);

        $roles = $user->getRoles();
        $this->assertContains('ROLE_USER', $roles);
        $this->assertContains('ROLE_ADMIN', $roles);
        $this->assertNotContains('ROLE_UNKNOWN_ROLE', $roles);
        $this->assertNotContains('ROLE_VIEWER', $roles);
    }

    /**
     * Test that incoming roles claim is dropped.
     */
    public function testIncomingRolesClaimDropped(): void
    {
        $attributes = [
            'sub' => '11111111-1111-4111-8111-111111111111',
            'preferred_username' => 'alice',
            'roles' => ['admin', 'editor'], // This should be dropped
            'realm_access' => [
                'roles' => ['admin', 'editor'],
            ],
        ];

        $user = $this->provider->loadUserByIdentifier('11111111-1111-4111-8111-111111111111', $attributes);

        // The user should have the correct roles from realm_access, not from the top-level roles
        $roles = $user->getRoles();
        $this->assertContains('ROLE_USER', $roles);
        $this->assertContains('ROLE_ADMIN', $roles);
        $this->assertContains('ROLE_EDITOR', $roles);
        
        // The user object should not have a roles claim in its attributes
        // (it was dropped before creating the OidcUser)
    }

    /**
     * Test that the identifier is the sub claim.
     */
    public function testIdentifierIsSub(): void
    {
        $attributes = [
            'sub' => '11111111-1111-4111-8111-111111111111',
            'preferred_username' => 'alice',
        ];

        $user = $this->provider->loadUserByIdentifier('11111111-1111-4111-8111-111111111111', $attributes);

        $this->assertEquals('11111111-1111-4111-8111-111111111111', $user->getUserIdentifier());
    }

    /**
     * Test that missing sub throws UserNotFoundException.
     */
    public function testMissingSubThrowsException(): void
    {
        $this->expectException(UserNotFoundException::class);
        $this->expectExceptionMessage('The "sub" claim is required for OIDC authentication.');
        
        $this->provider->loadUserByIdentifier('test-user', []);
    }

    /**
     * Test that empty sub throws UserNotFoundException.
     */
    public function testEmptySubThrowsException(): void
    {
        $this->expectException(UserNotFoundException::class);
        $this->expectExceptionMessage('The "sub" claim is required for OIDC authentication.');
        
        $this->provider->loadUserByIdentifier('', ['sub' => '']);
    }

    /**
     * Test that non-string sub throws UserNotFoundException.
     */
    public function testNonStringSubThrowsException(): void
    {
        $this->expectException(UserNotFoundException::class);
        $this->expectExceptionMessage('The "sub" claim is required for OIDC authentication.');
        
        $this->provider->loadUserByIdentifier('test-user', ['sub' => 123]);
    }

    /**
     * Test that refreshUser returns the same instance.
     */
    public function testRefreshUserReturnsSameInstance(): void
    {
        $attributes = [
            'sub' => '11111111-1111-4111-8111-111111111111',
            'preferred_username' => 'alice',
        ];

        $user = $this->provider->loadUserByIdentifier('11111111-1111-4111-8111-111111111111', $attributes);
        
        $refreshedUser = $this->provider->refreshUser($user);
        
        $this->assertSame($user, $refreshedUser);
    }

    /**
     * Test that refreshUser rejects other user classes.
     */
    public function testRefreshUserRejectsOtherUserClasses(): void
    {
        $this->expectException(\TypeError::class);
        
        $mockUser = new \stdClass();
        $this->provider->refreshUser($mockUser);
    }

    /**
     * Test that supportsClass only supports OidcUser.
     */
    public function testSupportsClass(): void
    {
        $this->assertTrue($this->provider->supportsClass(OidcUser::class));
        $this->assertFalse($this->provider->supportsClass(\stdClass::class));
        $this->assertFalse($this->provider->supportsClass(UserInterface::class));
    }

    /**
     * Test that a user with no realm_access has only ROLE_USER.
     */
    public function testUserWithoutRealmAccess(): void
    {
        $attributes = [
            'sub' => '11111111-1111-4111-8111-111111111111',
            'preferred_username' => 'alice',
        ];

        $user = $this->provider->loadUserByIdentifier('11111111-1111-4111-8111-111111111111', $attributes);

        $roles = $user->getRoles();
        $this->assertCount(1, $roles);
        $this->assertEquals(['ROLE_USER'], $roles);
    }

    /**
     * Test that a user with empty realm_access roles has only ROLE_USER.
     */
    public function testUserWithEmptyRealmRoles(): void
    {
        $attributes = [
            'sub' => '11111111-1111-4111-8111-111111111111',
            'preferred_username' => 'alice',
            'realm_access' => [
                'roles' => [],
            ],
        ];

        $user = $this->provider->loadUserByIdentifier('11111111-1111-4111-8111-111111111111', $attributes);

        $roles = $user->getRoles();
        $this->assertCount(1, $roles);
        $this->assertEquals(['ROLE_USER'], $roles);
    }

    /**
     * Test that realm_access with non-array roles is handled gracefully.
     */
    public function testRealmAccessWithNonArrayRoles(): void
    {
        $attributes = [
            'sub' => '11111111-1111-4111-8111-111111111111',
            'preferred_username' => 'alice',
            'realm_access' => [
                'roles' => 'not-an-array',
            ],
        ];

        $user = $this->provider->loadUserByIdentifier('11111111-1111-4111-8111-111111111111', $attributes);

        $roles = $user->getRoles();
        $this->assertCount(1, $roles);
        $this->assertEquals(['ROLE_USER'], $roles);
    }
}
