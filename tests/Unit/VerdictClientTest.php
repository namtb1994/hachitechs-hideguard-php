<?php

declare(strict_types=1);

namespace Hachitech\Antidetect\Tests\Unit;

use Hachitech\Antidetect\Contracts\HttpTransport;
use Hachitech\Antidetect\Exceptions\ApiException;
use Hachitech\Antidetect\Exceptions\FailureReason;
use Hachitech\Antidetect\Exceptions\GuardException;
use Hachitech\Antidetect\Http\HttpResponse;
use Hachitech\Antidetect\VerdictClient;
use PHPUnit\Framework\TestCase;

final class VerdictClientTest extends TestCase
{
    public function testPostsVisitorAsJsonWithApiKeyAndReturnsCompleteNestedResponse(): void
    {
        $visitorId = 'a313d75f78dc6dabb6e5138cbf341fe4';
        $payload = ['visitorId' => $visitorId, 'verdict' => 'allow',
            'reasons' => [['code' => 'test', 'detail' => ['score' => 0]]]];
        $transport = $this->createMock(HttpTransport::class);
        $transport->expects(self::once())->method('post')->with(
            'https://dev.hideguard.io:8443/api/v1/verdict',
            ['Accept' => 'application/json', 'Content-Type' => 'application/json', 'x-api-key' => 'secret-key'],
            '{"visitorId":"' . $visitorId . '"}'
        )->willReturn(new HttpResponse(200, json_encode($payload, JSON_THROW_ON_ERROR)));

        $client = new VerdictClient(' HTTPS://DEV.HIDEGUARD.IO:8443/ ', 'secret-key', $transport);
        self::assertSame($payload, $client->getVerdict($visitorId));
    }

    /** @dataProvider arrayResponses */
    public function testAcceptsObjectsAndListsWithoutAssumingAVerdictSchema(string $json, array $expected): void
    {
        $transport = $this->createMock(HttpTransport::class);
        $transport->method('post')->willReturn(new HttpResponse(201, $json));
        $client = new VerdictClient('https://example.com', 'key', $transport);
        self::assertSame($expected, $client->getVerdict('visitor'));
    }

    public static function arrayResponses(): array
    {
        return [
            ['{}', []], ['[]', []], ['[{"verdict":"block"}]', [['verdict' => 'block']]],
            ['{"id":123456789012345678901}', ['id' => '123456789012345678901']],
        ];
    }

    public function testQuotesBackslashesAndUnicodeInVisitorIdAreJsonEncoded(): void
    {
        $visitorId = 'visitor"\\khách';
        $transport = $this->createMock(HttpTransport::class);
        $transport->expects(self::once())->method('post')->with(
            'https://example.com/api/v1/verdict',
            self::anything(),
            self::callback(fn(string $body) => json_decode($body, true) === ['visitorId' => $visitorId])
        )->willReturn(new HttpResponse(200, '{}'));
        $client = new VerdictClient('https://example.com:443/', 'key', $transport);
        self::assertSame([], $client->getVerdict($visitorId));
    }

    /** @dataProvider invalidBaseUrls */
    public function testRejectsInvalidOriginsBeforeMakingARequest(string $baseUrl): void
    {
        $transport = $this->createMock(HttpTransport::class);
        $transport->expects(self::never())->method('post');
        $this->expectException(GuardException::class);
        new VerdictClient($baseUrl, 'key', $transport);
    }

    public static function invalidBaseUrls(): array
    {
        return ConfigurationTest::invalidEndpointUrls();
    }

    /** @dataProvider invalidApiKeys */
    public function testRejectsEmptyKeysAndHeaderInjection(string $apiKey): void
    {
        $this->expectException(GuardException::class);
        new VerdictClient('https://example.com', $apiKey);
    }

    public static function invalidApiKeys(): array
    {
        return [[''], [' '], ["key\r\nX-Other: value"], ["key\0"], ['key with spaces']];
    }

    /** @dataProvider invalidVisitorIds */
    public function testRejectsInvalidVisitorsBeforeMakingARequest(string $visitorId): void
    {
        $transport = $this->createMock(HttpTransport::class);
        $transport->expects(self::never())->method('post');
        try {
            (new VerdictClient('https://example.com', 'key', $transport))->getVerdict($visitorId);
            self::fail('Invalid visitor must be rejected.');
        } catch (GuardException $error) {
            self::assertSame(FailureReason::InvalidIdentity, $error->reason);
        }
    }

    public static function invalidVisitorIds(): array
    {
        return [[''], ['  '], ["visitor\0"], ["visitor\n"], ["\xff"]];
    }

    /** @dataProvider httpErrors */
    public function testRejectsHttpErrorsAndRedirectsWithoutExposingResponseBody(int $status): void
    {
        $transport = $this->createMock(HttpTransport::class);
        $transport->expects(self::once())->method('post')->willReturn(new HttpResponse($status, 'secret-key'));
        try {
            (new VerdictClient('https://example.com', 'secret-key', $transport))->getVerdict('visitor');
            self::fail('HTTP failure must be rejected.');
        } catch (ApiException $error) {
            self::assertSame($status, $error->statusCode);
            self::assertSame('HideGuard verdict request returned HTTP ' . $status . '.', $error->getMessage());
        }
    }

    public static function httpErrors(): array
    {
        return [[0], [199], [300], [302], [401], [403], [429], [500], [503]];
    }

    /** @dataProvider invalidResponses */
    public function testRejectsInvalidJsonAndScalarResponses(string $body): void
    {
        $transport = $this->createMock(HttpTransport::class);
        $transport->method('post')->willReturn(new HttpResponse(200, $body));
        $this->expectException(ApiException::class);
        (new VerdictClient('https://example.com', 'key', $transport))->getVerdict('visitor');
    }

    public static function invalidResponses(): array
    {
        return [[''], ['<html>error</html>'], ['{'], ['null'], ['true'], ['123'], ['"allow"'], ["{\"x\":\"\xff\"}"]];
    }

    public function testTransportFailureIsPropagatedWithoutRetry(): void
    {
        $failure = new ApiException('Connection timed out.');
        $transport = $this->createMock(HttpTransport::class);
        $transport->expects(self::once())->method('post')->willThrowException($failure);
        try {
            (new VerdictClient('https://example.com', 'key', $transport))->getVerdict('visitor');
            self::fail('Network failure must propagate.');
        } catch (ApiException $error) {
            self::assertSame($failure, $error);
            self::assertNull($error->statusCode);
        }
    }
}
