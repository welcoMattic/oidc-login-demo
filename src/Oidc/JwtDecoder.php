<?php

namespace App\Oidc;

/**
 * Tiny helper to decode JWT tokens for display purposes only.
 *
 * The authenticator already verified the token signature during authentication,
 * so this decoder performs no signature check. It only decodes the base64url
 * encoded parts for display in the account page.
 */
final class JwtDecoder
{
    /**
     * Decodes a JWT token into its header and payload.
     *
     * @return array{header: array<string, mixed>, payload: array<string, mixed>}
     */
    public static function decode(string $jwt): array
    {
        $parts = explode('.', $jwt);

        if (count($parts) !== 3) {
            throw new \InvalidArgumentException('Invalid JWT format: expected 3 parts separated by dots.');
        }

        return [
            'header' => self::decodePart($parts[0]),
            'payload' => self::decodePart($parts[1]),
        ];
    }

    /**
     * Decodes a base64url encoded JWT part.
     *
     * @return array<string, mixed>
     */
    private static function decodePart(string $part): array
    {
        // Convert base64url to base64
        $base64 = strtr($part, '-_', '+/');
        
        // Add padding if necessary
        $padLength = 4 - (strlen($base64) % 4);
        if ($padLength < 4) {
            $base64 .= str_repeat('=', $padLength);
        }

        $decoded = base64_decode($base64, true);
        
        if ($decoded === false) {
            throw new \InvalidArgumentException('Failed to decode JWT part: invalid base64 encoding.');
        }

        $data = json_decode($decoded, true);
        
        if (!is_array($data)) {
            throw new \InvalidArgumentException('Failed to decode JWT part: invalid JSON.');
        }

        return $data;
    }
}