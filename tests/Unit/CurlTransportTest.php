<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Tests\Unit;

use Hachitechs\HideguardPhp\Exceptions\ApiException;
use Hachitechs\HideguardPhp\Http\CurlTransport;
use PHPUnit\Framework\TestCase;

final class CurlTransportTest extends TestCase
{
    /** @dataProvider invalidTimeouts */
    public function testRejectsUnboundedOrInconsistentTimeouts(int $total, int $connect): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new CurlTransport($total, $connect);
    }

    public static function invalidTimeouts(): array
    {
        return [[0, 0], [-1, 1], [10, 0], [3, 4]];
    }

    public function testDefaultTransportRefusesPlainHttpBeforeConnecting(): void
    {
        if (!function_exists('curl_init')) {
            self::markTestSkipped('Requires ext-curl.');
        }
        $this->expectException(ApiException::class);
        $this->expectExceptionMessage('cURL error 1');
        (new CurlTransport())->post('http://127.0.0.1:1/api/v1/verdict', [], '{}');
    }

    public function testResponseLimitMustBePositive(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new CurlTransport(maxResponseBytes: 0);
    }
}
