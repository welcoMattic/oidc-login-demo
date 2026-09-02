<?php

namespace App\Tests\Unit\Oidc;

use App\Oidc\JwtDecoder;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for JwtDecoder.
 */
class JwtDecoderTest extends TestCase
{
    /**
     * Test decoding a valid JWT token.
     */
    public function testDecodeValidToken(): void
    {
        $header = json_encode(['alg' => 'RS256', 'typ' => 'JWT']);
        $payload = json_encode(['sub' => '1234567890', 'name' => 'John Doe']);
        
        // Create a JWT with base64url encoding
        $headerB64 = $this->base64UrlEncode($header);
        $payloadB64 = $this->base64UrlEncode($payload);
        $signature = $this->base64UrlEncode('test-signature');
        
        $jwt = $headerB64 . '.' . $payloadB64 . '.' . $signature;
        
        $result = JwtDecoder::decode($jwt);
        
        $this->assertArrayHasKey('header', $result);
        $this->assertArrayHasKey('payload', $result);
        
        $this->assertEquals(['alg' => 'RS256', 'typ' => 'JWT'], $result['header']);
        $this->assertEquals(['sub' => '1234567890', 'name' => 'John Doe'], $result['payload']);
    }

    /**
     * Test decoding a JWT with different header and payload.
     */
    public function testDecodeDifferentContent(): void
    {
        $header = json_encode(['alg' => 'ES256', 'kid' => 'key-1']);
        $payload = json_encode(['iss' => 'https://example.com', 'exp' => 1234567890, 'iat' => 1234567800]);
        
        $headerB64 = $this->base64UrlEncode($header);
        $payloadB64 = $this->base64UrlEncode($payload);
        $signature = $this->base64UrlEncode('test-signature');
        
        $jwt = $headerB64 . '.' . $payloadB64 . '.' . $signature;
        
        $result = JwtDecoder::decode($jwt);
        
        $this->assertEquals(['alg' => 'ES256', 'kid' => 'key-1'], $result['header']);
        $this->assertEquals(['iss' => 'https://example.com', 'exp' => 1234567890, 'iat' => 1234567800], $result['payload']);
    }

    /**
     * Test that a token with invalid format (not 3 parts) throws an exception.
     */
    public function testInvalidFormatThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid JWT format: expected 3 parts separated by dots.');
        
        JwtDecoder::decode('invalid-token');
    }

    /**
     * Test that a token with only 2 parts throws an exception.
     */
    public function testTwoPartsThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid JWT format: expected 3 parts separated by dots.');
        
        JwtDecoder::decode('header.payload');
    }

    /**
     * Test that a token with invalid base64 in header throws an exception.
     */
    public function testInvalidHeaderBase64ThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Failed to decode JWT part: invalid base64 encoding.');
        
        // Use invalid base64 for header
        $jwt = 'invalid!base64.' . $this->base64UrlEncode('{}') . '.' . $this->base64UrlEncode('{}');
        JwtDecoder::decode($jwt);
    }

    /**
     * Test that a token with invalid base64 in payload throws an exception.
     */
    public function testInvalidPayloadBase64ThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Failed to decode JWT part: invalid base64 encoding.');
        
        // Use invalid base64 for payload
        $jwt = $this->base64UrlEncode('{}') . '.invalid!base64.' . $this->base64UrlEncode('{}');
        JwtDecoder::decode($jwt);
    }

    /**
     * Test that a token with invalid JSON in header throws an exception.
     */
    public function testInvalidHeaderJsonThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Failed to decode JWT part: invalid JSON.');
        
        // Use invalid JSON for header
        $jwt = $this->base64UrlEncode('not json') . '.' . $this->base64UrlEncode('{}') . '.' . $this->base64UrlEncode('{}');
        JwtDecoder::decode($jwt);
    }

    /**
     * Test that a token with invalid JSON in payload throws an exception.
     */
    public function testInvalidPayloadJsonThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Failed to decode JWT part: invalid JSON.');
        
        // Use invalid JSON for payload
        $jwt = $this->base64UrlEncode('{}') . '.' . $this->base64UrlEncode('not json') . '.' . $this->base64UrlEncode('{}');
        JwtDecoder::decode($jwt);
    }

    /**
     * Test that a token with missing header throws an exception.
     */
    public function testEmptyHeaderThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Failed to decode JWT part: invalid JSON.');
        
        // Use empty object for header which should be valid, but let's test with invalid JSON
        $jwt = $this->base64UrlEncode('') . '.' . $this->base64UrlEncode('{}') . '.' . $this->base64UrlEncode('{}');
        JwtDecoder::decode($jwt);
    }

    /**
     * Test decoding a token with empty parts (should still work with empty objects).
     */
    public function testEmptyParts(): void
    {
        $jwt = $this->base64UrlEncode('{}') . '.' . $this->base64UrlEncode('{}') . '.' . $this->base64UrlEncode('{}');
        
        $result = JwtDecoder::decode($jwt);
        
        $this->assertEquals([], $result['header']);
        $this->assertEquals([], $result['payload']);
    }

    /**
     * Test decoding a token with complex nested payload.
     */
    public function testComplexNestedPayload(): void
    {
        $header = json_encode(['alg' => 'RS256', 'typ' => 'JWT']);
        $payload = json_encode([
            'sub' => '1234567890',
            'name' => 'John Doe',
            'realm_access' => [
                'roles' => ['admin', 'user'],
            ],
            'nested' => [
                'deep' => [
                    'value' => 'test',
                ],
            ],
        ]);
        
        $headerB64 = $this->base64UrlEncode($header);
        $payloadB64 = $this->base64UrlEncode($payload);
        $signature = $this->base64UrlEncode('test-signature');
        
        $jwt = $headerB64 . '.' . $payloadB64 . '.' . $signature;
        
        $result = JwtDecoder::decode($jwt);
        
        $expectedPayload = [
            'sub' => '1234567890',
            'name' => 'John Doe',
            'realm_access' => [
                'roles' => ['admin', 'user'],
            ],
            'nested' => [
                'deep' => [
                    'value' => 'test',
                ],
            ],
        ];
        
        $this->assertEquals($expectedPayload, $result['payload']);
    }

    /**
     * Helper method to encode base64url.
     */
    private function base64UrlEncode(string $data): string
    {
        $base64 = base64_encode($data);
        // Convert to base64url
        return rtrim(strtr($base64, '+/', '-_'), '=');
    }
}
