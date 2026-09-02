<?php

namespace App\Trace;

use Symfony\Component\DependencyInjection\Attribute\AsDecorator;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;
use Symfony\Contracts\HttpClient\ResponseStreamInterface;
use Symfony\Contracts\Service\ResetInterface;

/**
 * Decorates the HTTP client to record all exchanges made during OIDC authentication.
 *
 * This recorder only keeps the response objects (not their bodies) at request time,
 * so the trace builder can read them later via getContent(false) and getHeaders(false)
 * since Symfony's HttpClient buffers responses by default.
 */
#[AsDecorator('http_client')]
final class OidcHttpRecorder implements HttpClientInterface, ResetInterface
{
    /** @var list<array{method: string, url: string, options: array, response: ResponseInterface}> */
    private array $exchanges = [];

    public function __construct(
        private HttpClientInterface $inner,
    ) {
    }

    public function request(string $method, string $url, array $options = []): ResponseInterface
    {
        // Delegate to inner client first to get the response
        $response = $this->inner->request($method, $url, $options);

        // Record the exchange (response object, not body - it's buffered)
        $this->exchanges[] = [
            'method' => $method,
            'url' => $url,
            'options' => $options,
            'response' => $response,
        ];

        // Return the response UNWRAPPED so stream() can delegate directly
        return $response;
    }

    public function withOptions(array $options): static
    {
        // Return a clone that wraps the inner client's withOptions result
        $clone = clone $this;
        $clone->inner = $this->inner->withOptions($options);
        return $clone;
    }

    /**
     * @return list<array{method: string, url: string, options: array, response: ResponseInterface}>
     */
    public function getExchanges(): array
    {
        return $this->exchanges;
    }

    public function reset(): void
    {
        $this->exchanges = [];
    }

    public function stream(ResponseInterface|iterable $responses, ?float $timeout = null): ResponseStreamInterface
    {
        // Delegate stream() to the inner client - this must work with the same response objects
        // that were returned by request(), which it does since we return them unwrapped
        return $this->inner->stream($responses, $timeout);
    }
}