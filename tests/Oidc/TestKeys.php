<?php

namespace App\Tests\Oidc;

use Jose\Component\KeyManagement\JWKFactory;

/**
 * Generates test keys for the fake Keycloak provider.
 *
 * Keys are generated once per process and reused for all tests.
 */
final class TestKeys
{
    private static ?array $providerRsaKey = null;
    private static ?array $providerEcKey = null;
    private static ?array $impostorRsaKey = null;

    /**
     * Generate and return the provider RSA key (kid: rsa-test).
     */
    public static function providerRsaKey(): array
    {
        if (null === self::$providerRsaKey) {
            self::$providerRsaKey = self::createRsaKey('rsa-test', 'RS256');
        }

        return self::$providerRsaKey;
    }

    /**
     * Generate and return the provider EC key (kid: ec-test, ES256).
     */
    public static function providerEcKey(): array
    {
        if (null === self::$providerEcKey) {
            self::$providerEcKey = self::createEcKey('ec-test', 'ES256', 'P-256');
        }

        return self::$providerEcKey;
    }

    /**
     * Generate and return the impostor RSA key (kid: rsa-test, same as provider RSA key).
     * This key is used for signature rejection tests.
     */
    public static function impostorRsaKey(): array
    {
        if (null === self::$impostorRsaKey) {
            self::$impostorRsaKey = self::createRsaKey('rsa-test', 'RS256');
        }

        return self::$impostorRsaKey;
    }

    /**
     * Return the public JWKS containing the two provider keys.
     */
    public static function jwks(): array
    {
        return [
            'keys' => [
                self::publicKeyData(self::providerRsaKey()),
                self::publicKeyData(self::providerEcKey()),
            ],
        ];
    }

    /**
     * Create an RSA key with the given kid and alg.
     */
    private static function createRsaKey(string $kid, string $alg): array
    {
        $jwk = JWKFactory::createRSAKey(2048, [
            'kid' => $kid,
            'alg' => $alg,
            'use' => 'sig',
        ]);

        return [
            'private_key' => $jwk,
            'public_key' => $jwk->toPublic(),
        ];
    }

    /**
     * Create an EC key with the given kid, alg and curve.
     */
    private static function createEcKey(string $kid, string $alg, string $curve): array
    {
        $jwk = JWKFactory::createECKey($curve, [
            'kid' => $kid,
            'alg' => $alg,
            'use' => 'sig',
        ]);

        return [
            'private_key' => $jwk,
            'public_key' => $jwk->toPublic(),
        ];
    }

    /**
     * Extract public key data for JWKS from a key pair.
     */
    private static function publicKeyData(array $keyPair): array
    {
        $publicKey = $keyPair['public_key'];
        $keyData = $publicKey->all();

        // Ensure required fields are present
        $keyData['kty'] ??= 'RSA';
        $keyData['use'] ??= 'sig';
        $keyData['alg'] ??= 'RS256';
        $keyData['kid'] ??= 'unknown';

        return $keyData;
    }
}
