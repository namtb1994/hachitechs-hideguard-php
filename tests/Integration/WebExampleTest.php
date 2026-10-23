<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Tests\Integration;

use Hachitechs\HideguardPhp\Tests\Support\UsesMySql;
use PHPUnit\Framework\TestCase;

final class WebExampleTest extends TestCase
{
    use UsesMySql {
        tearDown as disposeDatabase;
    }

    /** @var resource|null */
    private $server = null;
    private string $log = '';
    private string $cookie = '';
    private string $origin;

    protected function setUp(): void
    {
        $this->createStorage();
        $socket = stream_socket_server('tcp://127.0.0.1:0');
        $address = stream_socket_get_name($socket, false);
        fclose($socket);
        $this->origin = 'http://' . $address;
        $this->log = tempnam(sys_get_temp_dir(), 'hg-web-');
        $environment = array_merge(getenv(), [
            'HG_MYSQL_DSN' => getenv('HG_TEST_MYSQL_DSN'),
            'HG_MYSQL_USER' => getenv('HG_TEST_MYSQL_USER'),
            'HG_MYSQL_PASSWORD' => getenv('HG_TEST_MYSQL_PASSWORD'),
            'HG_TABLE_PREFIX' => $this->databaseFixture->prefix,
            'HG_SITE_KEY' => 'test-development-key',
        ]);
        $this->server = proc_open(
            [PHP_BINARY, '-S', $address, 'examples/plain-php/web/router.php'],
            [0 => ['file', '/dev/null', 'r'], 1 => ['file', $this->log, 'w'], 2 => ['file', $this->log, 'a']],
            $pipes,
            dirname(__DIR__, 2),
            $environment
        );
        for ($attempt = 0; $attempt < 30; $attempt++) {
            $ready = @stream_socket_client('tcp://' . $address);
            if ($ready) {
                fclose($ready);
                return;
            }
            usleep(100000);
        }
        self::fail('The example PHP server did not start.');
    }

    protected function tearDown(): void
    {
        if (is_resource($this->server)) {
            proc_terminate($this->server);
            proc_close($this->server);
        }
        if ($this->log !== '') {
            unlink($this->log);
        }
        $this->disposeDatabase();
    }

    public function testPlainPhpWebEnforcesIdentityCsrfResourceAndBlocksWithoutFrameworkBoot(): void
    {
        [$code, $html] = $this->request('/protected');
        self::assertSame(200, $code);
        self::assertStringContainsString('Protected example content', $html);
        self::assertStringContainsString('inert data-hachitech-ab-inert', $html);
        preg_match('/"csrfToken":"([a-f0-9]{64})"/', $html, $match);
        $csrf = $match[1];
        preg_match('/"verificationId":"([a-f0-9]{32})"/', $html, $match);
        $verificationId = $match[1];
        self::assertSame(400, $this->request('/submit', ['csrf' => 'invalid'])[0]);
        self::assertSame(403, $this->request('/submit', ['csrf' => $csrf])[0]);
        [$code, $body] = $this->request('/verdict', [
            'csrf' => $csrf, 'verificationId' => $verificationId, 'verdict' => 'allow', 'visitorId' => 'web-visitor',
        ]);
        self::assertSame(200, $code);
        self::assertSame('allowed', json_decode($body, true)['status']);
        [$code, $body] = $this->request('/submit', ['csrf' => $csrf]);
        self::assertSame(200, $code);
        self::assertSame(1, json_decode($body, true)['submitted']);
        self::assertSame(403, $this->request('/submit', ['csrf' => $csrf])[0]);
        [$code, $body] = $this->request('/access', ['csrf' => $csrf]);
        $verificationId = json_decode($body, true)['verificationId'];
        [$code, $body] = $this->request('/verdict', [
            'csrf' => $csrf, 'verificationId' => $verificationId, 'verdict' => 'block', 'visitorId' => 'web-visitor',
        ]);
        $block = json_decode($body, true);
        self::assertSame(401, $code);
        self::assertSame('blocked', $block['status']);
        [$code, $html] = $this->request('/protected');
        self::assertSame(401, $code);
        self::assertStringNotContainsString('Protected example content', $html);
        self::assertStringContainsString('data-state="blocked"', $html);
        [$code, $body] = $this->request('/verdict', ['csrf' => $csrf, 'verdict' => 'invalid']);
        self::assertSame(401, $code);
        self::assertSame($block['blockedUntil'], json_decode($body, true)['blockedUntil']);
        self::assertSame(200, $this->request('/')[0]);
        [$code, $script] = $this->request('/runtime.js');
        self::assertSame(200, $code);
        self::assertStringContainsString('initialize', $script);
        self::assertStringContainsString('styleText', $script);
    }

    public function testNoSdkResponseExpiresAtServerAndRetryRotatesAttempt(): void
    {
        [, $html] = $this->request('/protected');
        preg_match('/"csrfToken":"([a-f0-9]{64})"/', $html, $match);
        $csrf = $match[1];
        [, $body] = $this->request('/access', ['csrf' => $csrf]);
        $first = json_decode($body, true);
        [, $body] = $this->request('/access', ['csrf' => $csrf]);
        self::assertSame($first['verificationUntil'], json_decode($body, true)['verificationUntil']);
        // Simulate expiry without JavaScript, an SDK report or a client failure notification.
        $this->databaseFixture->pdo->exec(
            'UPDATE `' . $this->databaseFixture->prefix . 'session` SET verification_until = 1'
        );
        self::assertSame(302, $this->request('/protected')[0]);
        [$status, $gate] = $this->request('/gate?failed=1');
        self::assertSame(403, $status);
        self::assertStringNotContainsString('Protected example content', $gate);
        self::assertStringContainsString('data-action="retry"', $gate);
        self::assertSame(403, $this->request('/access', ['csrf' => $csrf])[0]);
        [$status, $body] = $this->request('/access', ['csrf' => $csrf, 'retry' => '1']);
        self::assertSame(200, $status);
        $next = json_decode($body, true);
        self::assertNotSame($first['verificationId'], $next['verificationId']);
        [$status, $body] = $this->request('/verdict', ['csrf' => $csrf, 'verificationId' => $first['verificationId'],
            'verdict' => 'allow', 'visitorId' => 'web-visitor']);
        self::assertSame('verification_required', json_decode($body, true)['status']);
        self::assertSame(
            403,
            $this->request('/fail', ['csrf' => $csrf, 'verificationId' => $next['verificationId']])[0]
        );
        self::assertSame(302, $this->request('/protected')[0]);
    }

    /** @return array{int,string} */
    private function request(string $path, ?array $body = null): array
    {
        $headers = 'Cookie: ' . $this->cookie . "\r\n";
        if ($body !== null) {
            $headers .= "Content-Type: application/x-www-form-urlencoded\r\n";
        }
        $context = stream_context_create(['http' => [
            'method' => $body === null ? 'GET' : 'POST', 'header' => $headers,
            'content' => $body === null ? '' : http_build_query($body),
            'ignore_errors' => true, 'follow_location' => 0, 'timeout' => 3,
        ]]);
        $content = file_get_contents($this->origin . $path, false, $context);
        foreach ($http_response_header as $header) {
            if (preg_match('/^Set-Cookie: ([^;]+)/i', $header, $match)) {
                $this->cookie = $match[1];
            }
        }
        preg_match('/\s(\d{3})\s/', $http_response_header[0], $match);
        return [(int)$match[1], $content];
    }
}
