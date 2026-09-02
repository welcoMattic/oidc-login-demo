<?php

namespace App\Tests\Unit\Trace;

use App\Trace\OidcHttpRecorder;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Contracts\HttpClient\ResponseInterface;

/**
 * Unit tests for OidcHttpRecorder.
 */
class OidcHttpRecorderTest extends TestCase
{
    private OidcHttpRecorder $recorder;
    private MockHttpClient $innerClient;

    protected function setUp(): void
    {
        $this->innerClient = new MockHttpClient();
        $this->recorder = new OidcHttpRecorder($this->innerClient);
    }

    /**
     * Test that the recorder records method, url and options.
     */
    public function testRecordsRequests(): void
    {
        $this->innerClient->setResponseFactory(function () {
            return new MockResponse('test content', ['http_code' => 200]);
        });

        $this->recorder->request('GET', 'https://example.com/test', ['headers' => ['Accept' => 'application/json']]);

        $exchanges = $this->recorder->getExchanges();
        
        $this->assertCount(1, $exchanges);
        
        $exchange = $exchanges[0];
        $this->assertEquals('GET', $exchange['method']);
        $this->assertEquals('https://example.com/test', $exchange['url']);
        $this->assertEquals(['headers' => ['Accept' => 'application/json']], $exchange['options']);
        $this->assertInstanceOf(MockResponse::class, $exchange['response']);
    }

    /**
     * Test that the recorder returns the inner response unwrapped.
     */
    public function testReturnsInnerResponseUnwrapped(): void
    {
        $this->innerClient->setResponseFactory(function () {
            return new MockResponse('test content', ['http_code' => 200]);
        });

        $response = $this->recorder->request('GET', 'https://example.com/test');
        
        // Should return a MockResponse instance
        $this->assertInstanceOf(MockResponse::class, $response);
    }

    /**
     * Test that multiple requests are recorded.
     */
    public function testRecordsMultipleRequests(): void
    {
        $this->innerClient->setResponseFactory(function ($method, $url, $options) {
            return new MockResponse('response for ' . $url, ['http_code' => 200]);
        });

        $this->recorder->request('GET', 'https://example.com/first');
        $this->recorder->request('POST', 'https://example.com/second', ['body' => ['key' => 'value']]);

        $exchanges = $this->recorder->getExchanges();
        
        $this->assertCount(2, $exchanges);
        
        $this->assertEquals('GET', $exchanges[0]['method']);
        $this->assertEquals('https://example.com/first', $exchanges[0]['url']);
        
        $this->assertEquals('POST', $exchanges[1]['method']);
        $this->assertEquals('https://example.com/second', $exchanges[1]['url']);
        $this->assertEquals(['body' => ['key' => 'value']], $exchanges[1]['options']);
    }

    /**
     * Test that reset clears the recorded exchanges.
     */
    public function testResetClearsExchanges(): void
    {
        $this->innerClient->setResponseFactory(function () {
            return new MockResponse('test', ['http_code' => 200]);
        });

        $this->recorder->request('GET', 'https://example.com/test');
        
        $this->assertCount(1, $this->recorder->getExchanges());
        
        $this->recorder->reset();
        
        $this->assertCount(0, $this->recorder->getExchanges());
    }

    /**
     * Test that withOptions returns a clone with the inner client's withOptions result.
     */
    public function testWithOptions(): void
    {
        $this->innerClient->setResponseFactory(function () {
            return new MockResponse('test', ['http_code' => 200]);
        });

        $recorderWithOptions = $this->recorder->withOptions(['timeout' => 30]);
        
        // Should be a different instance
        $this->assertNotSame($this->recorder, $recorderWithOptions);
        
        // Should be an OidcHttpRecorder
        $this->assertInstanceOf(OidcHttpRecorder::class, $recorderWithOptions);
    }

    /**
     * Test that withOptions preserves recording functionality.
     */
    public function testWithOptionsPreservesRecording(): void
    {
        $this->innerClient->setResponseFactory(function () {
            return new MockResponse('test', ['http_code' => 200]);
        });

        $recorderWithOptions = $this->recorder->withOptions(['timeout' => 30]);
        
        // Make a request with the new recorder
        $recorderWithOptions->request('GET', 'https://example.com/test');
        
        // The original recorder should still have no exchanges (it's a separate instance)
        $this->assertCount(0, $this->recorder->getExchanges());
        
        // The new recorder should have the exchange
        $exchanges = $recorderWithOptions->getExchanges();
        $this->assertCount(1, $exchanges);
        $this->assertEquals('GET', $exchanges[0]['method']);
        $this->assertEquals('https://example.com/test', $exchanges[0]['url']);
    }

    /**
     * Test that stream delegates to the inner client.
     */
    public function testStreamDelegatesToInnerClient(): void
    {
        $testResponse = new MockResponse('stream data', ['http_code' => 200]);
        
        // Create a recorder with a mock inner client
        $innerClient = $this->createMock(\Symfony\Contracts\HttpClient\HttpClientInterface::class);
        $innerClient->expects($this->once())
            ->method('stream')
            ->with([$testResponse], null)
            ->willReturn($this->createStub(\Symfony\Contracts\HttpClient\ResponseStreamInterface::class));

        $recorder = new OidcHttpRecorder($innerClient);
        
        // This should delegate to the inner client - stream expects an array of responses
        $recorder->stream([$testResponse]);
    }

    /**
     * Test that the recorder records requests with different HTTP methods.
     */
    public function testRecordsDifferentHttpMethods(): void
    {
        $this->innerClient->setResponseFactory(function () {
            return new MockResponse('test', ['http_code' => 200]);
        });

        $methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
        
        foreach ($methods as $method) {
            $this->recorder->request($method, 'https://example.com/' . strtolower($method));
        }

        $exchanges = $this->recorder->getExchanges();
        $this->assertCount(5, $exchanges);
        
        foreach ($methods as $i => $method) {
            $this->assertEquals($method, $exchanges[$i]['method']);
        }
    }

    /**
     * Test that the recorder records complex options.
     */
    public function testRecordsComplexOptions(): void
    {
        $this->innerClient->setResponseFactory(function () {
            return new MockResponse('test', ['http_code' => 200]);
        });

        $options = [
            'headers' => ['Content-Type' => 'application/json'],
            'body' => ['key1' => 'value1', 'key2' => 'value2'],
            'timeout' => 30,
        ];

        $this->recorder->request('POST', 'https://example.com/api', $options);

        $exchanges = $this->recorder->getExchanges();
        $this->assertCount(1, $exchanges);
        
        $this->assertEquals($options, $exchanges[0]['options']);
    }
}
