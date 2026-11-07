<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Tests\Unit;

use Hachitechs\HideguardPhp\Access\CircuitPermit;
use Hachitechs\HideguardPhp\Configuration\CircuitBreakerPolicy;
use Hachitechs\HideguardPhp\Contracts\{CircuitBreakerStoreContract, HttpTransport};
use Hachitechs\HideguardPhp\Exceptions\ApiException;
use Hachitechs\HideguardPhp\Http\{CircuitBreakingTransport, HttpResponse};
use Hachitechs\HideguardPhp\Tests\Support\FrozenClock;
use PHPUnit\Framework\TestCase;

final class CircuitBreakingTransportTest extends TestCase
{
    /** @dataProvider responses */
    public function testClassifiesInfrastructureFailuresWithoutRetry(int $status, bool $failed): void
    {
        $store = $this->createMock(CircuitBreakerStoreContract::class);
        $permit = new CircuitPermit(1);
        $policy = new CircuitBreakerPolicy();
        $store->expects(self::once())->method('acquire')
            ->with(self::isType('string'), 1000, $policy)->willReturn($permit);
        $store->expects(self::once())->method('record')->with(self::isType('string'), $permit, $failed, 1000, $policy);
        $transport = $this->createMock(HttpTransport::class);
        $response = new HttpResponse($status, '{"verdict":"block"}');
        $transport->expects(self::once())->method('post')
            ->with('https://fixture', ['x-api-key' => 'secret'], '{}')->willReturn($response);
        $subject = new CircuitBreakingTransport($transport, $store, new FrozenClock(), $policy, 'site');
        self::assertSame($response, $subject->post('https://fixture', ['x-api-key' => 'secret'], '{}'));
    }

    public static function responses(): array
    {
        return [[200, false], [400, false], [401, false], [429, true], [500, true], [503, true]];
    }

    public function testOpenOrUnavailableStateNeverCallsHttp(): void
    {
        $store = $this->createMock(CircuitBreakerStoreContract::class);
        $store->method('acquire')->willThrowException(new \RuntimeException('storage unavailable or open'));
        $transport = $this->createMock(HttpTransport::class);
        $transport->expects(self::never())->method('post');
        $store->expects(self::never())->method('record');
        $this->expectException(ApiException::class);
        (new CircuitBreakingTransport($transport, $store, new FrozenClock(), new CircuitBreakerPolicy(), 'site'))
            ->post('https://fixture', [], '{}');
    }

    public function testStateWriteFailureDiscardsSuccessfulAllow(): void
    {
        $store = $this->createMock(CircuitBreakerStoreContract::class);
        $store->method('acquire')->willReturn(new CircuitPermit(1));
        $store->expects(self::once())->method('record')->willThrowException(new \RuntimeException('DB unavailable'));
        $transport = $this->createMock(HttpTransport::class);
        $transport->expects(self::once())->method('post')->willReturn(new HttpResponse(200, '{"verdict":"allow"}'));
        $this->expectException(ApiException::class);
        (new CircuitBreakingTransport($transport, $store, new FrozenClock(), new CircuitBreakerPolicy(), 'site'))
            ->post('https://fixture', [], '{}');
    }

    public function testTransportExceptionIsCountedAndRethrownWithoutRetry(): void
    {
        $store = $this->createMock(CircuitBreakerStoreContract::class);
        $permit = new CircuitPermit(1);
        $store->method('acquire')->willReturn($permit);
        $store->expects(self::once())->method('record')
            ->with(self::isType('string'), $permit, true, 1000, self::anything());
        $error = new ApiException('timeout', 504);
        $transport = $this->createMock(HttpTransport::class);
        $transport->expects(self::once())->method('post')->willThrowException($error);
        try {
            (new CircuitBreakingTransport($transport, $store, new FrozenClock(), new CircuitBreakerPolicy(), 'site'))
                ->post('https://fixture', [], '{}');
            self::fail('Timeout allowed access.');
        } catch (ApiException $caught) {
            self::assertSame($error, $caught);
        }
    }

    public function testCircuitKeyIsStableForDynamicHeadersAndIsolatesScopeEndpointAndCredential(): void
    {
        $keys = [];
        $store = $this->createMock(CircuitBreakerStoreContract::class);
        $store->method('acquire')->willReturnCallback(function ($key) use (&$keys) {
            $keys[] = $key;
            return new CircuitPermit(0);
        });
        $transport = $this->createStub(HttpTransport::class);
        $transport->method('post')->willReturn(new HttpResponse(200, '{}'));
        $build = fn($scope) => new CircuitBreakingTransport(
            $transport,
            $store,
            new FrozenClock(),
            new CircuitBreakerPolicy(),
            $scope
        );
        $build('one')->post('https://a', ['X-API-Key' => 'secret', 'request-id' => '1'], '{}');
        $build('one')->post('https://a', ['request-id' => '2', 'x-api-key' => 'secret'], 'different body');
        $build('two')->post('https://a', ['x-api-key' => 'secret'], '{}');
        $build('one')->post('https://b', ['x-api-key' => 'secret'], '{}');
        $build('one')->post('https://a', ['x-api-key' => 'rotated'], '{}');
        self::assertSame($keys[0], $keys[1]);
        self::assertCount(4, array_unique($keys));
        self::assertStringNotContainsString('secret', json_encode($keys));
    }
}
