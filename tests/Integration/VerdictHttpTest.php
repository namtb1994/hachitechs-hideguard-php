<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Tests\Integration;

use PHPUnit\Framework\TestCase;

final class VerdictHttpTest extends TestCase
{
    /** @var resource|null */
    private $server = null;
    private string $directory = '';

    protected function setUp(): void
    {
        if (!function_exists('curl_init') || !function_exists('openssl_pkey_new') || !function_exists('proc_open')) {
            self::markTestSkipped('HTTPS transport checks require curl, openssl and proc_open.');
        }
        $this->directory = sys_get_temp_dir() . '/hg-verdict-' . bin2hex(random_bytes(8));
        mkdir($this->directory, 0700);
        $config = $this->directory . '/openssl.cnf';
        file_put_contents($config, "[req]\ndistinguished_name=dn\n[dn]\n[san]\nsubjectAltName=IP:127.0.0.1\n");
        $key = openssl_pkey_new(['private_key_bits' => 2048]);
        $options = ['config' => $config, 'digest_alg' => 'sha256', 'x509_extensions' => 'san'];
        $csr = openssl_csr_new(['commonName' => '127.0.0.1'], $key, $options);
        $certificate = openssl_csr_sign($csr, null, $key, 1, $options);
        self::assertNotFalse($certificate);
        openssl_x509_export($certificate, $certPem);
        openssl_pkey_export($key, $keyPem);
        file_put_contents($this->directory . '/server.pem', $certPem . $keyPem);
    }

    protected function tearDown(): void
    {
        if (is_resource($this->server)) {
            proc_terminate($this->server);
            proc_close($this->server);
        }
        if ($this->directory !== '') {
            foreach (glob($this->directory . '/*') ?: [] as $file) {
                unlink($file);
            }
            rmdir($this->directory);
        }
        parent::tearDown();
    }

    public function testNativeCurlSendsPostHeadersJsonAndDecodesGzipOverVerifiedTls(): void
    {
        $result = $this->request('success');
        self::assertSame(['verdict' => 'allow', 'reasons' => [['code' => 'https-fixture']]], $result['response']);
        [$line, $headers, $body] = json_decode(file_get_contents($this->directory . '/request.json'), true);
        self::assertSame('POST /api/v1/verdict HTTP/1.1', $line);
        self::assertSame('test-api-key', $headers['x-api-key']);
        self::assertSame('application/json', $headers['content-type']);
        self::assertSame('application/json', $headers['accept']);
        self::assertStringContainsString('gzip', $headers['accept-encoding']);
        self::assertSame(['visitorId' => 'test-visitor'], json_decode($body, true));
    }

    public function testNativeCurlDoesNotForwardCredentialsToRedirects(): void
    {
        $result = $this->request('redirect');
        self::assertSame(302, $result['status']);
        self::assertSame('HideGuard verdict request returned HTTP 302.', $result['error']);
    }

    public function testNativeCurlRejectsAnUntrustedServerCertificate(): void
    {
        $result = $this->request('success', false);
        self::assertNull($result['status']);
        self::assertSame('HideGuard HTTP request failed (cURL error 60).', $result['error']);
        self::assertFileDoesNotExist($this->directory . '/request.json');
    }

    public function testNativeCurlEnforcesTheTotalTimeout(): void
    {
        $result = $this->request('timeout');
        self::assertNull($result['status']);
        self::assertSame('HideGuard HTTP request failed (cURL error 28).', $result['error']);
    }

    /** @dataProvider oversizedResponses */
    public function testNativeCurlRejectsOversizedBodiesIncludingGzipExpansion(string $mode): void
    {
        $result = $this->request($mode);
        self::assertSame('HideGuard verdict response exceeds the size limit.', $result['error']);
        self::assertNull($result['status']);
    }

    public static function oversizedResponses(): array
    {
        return [['oversized-gzip'], ['oversized-plain']];
    }

    private function request(string $mode, bool $trustCertificate = true): array
    {
        $pem = $this->directory . '/server.pem';
        $this->server = proc_open(
            [PHP_BINARY, __DIR__ . '/../Support/verdict-http-server.php',
                $pem, $this->directory . '/request.json', $mode],
            [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'],
                2 => ['file', $this->directory . '/server.log', 'w']],
            $serverPipes
        );
        self::assertIsResource($this->server);
        $origin = 'https://' . trim((string)fgets($serverPipes[1]));
        fclose($serverPipes[1]);
        // curl.cainfo is PHP_INI_SYSTEM, so use an isolated PHP process to trust only this fixture.
        $code = <<<'PHP'
require 'vendor/autoload.php';
try {
    $transport = new \Hachitechs\HideguardPhp\Http\CurlTransport(1, 1);
    $client = new \Hachitechs\HideguardPhp\VerdictClient($argv[1], 'test-api-key', $transport);
    echo json_encode(['response' => $client->getVerdict('test-visitor')], JSON_THROW_ON_ERROR);
} catch (\Hachitechs\HideguardPhp\Exceptions\ApiException $error) {
    echo json_encode(['error' => $error->getMessage(), 'status' => $error->statusCode], JSON_THROW_ON_ERROR);
}
PHP;
        $command = [PHP_BINARY];
        if ($trustCertificate) {
            array_push($command, '-d', 'curl.cainfo=' . $pem);
        }
        array_push($command, '-r', $code, $origin);
        $client = proc_open(
            $command,
            [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'],
                2 => ['file', $this->directory . '/client.log', 'w']],
            $clientPipes,
            dirname(__DIR__, 2)
        );
        self::assertIsResource($client);
        $output = stream_get_contents($clientPipes[1]);
        fclose($clientPipes[1]);
        self::assertSame(0, proc_close($client), file_get_contents($this->directory . '/client.log'));
        return json_decode($output, true, 512, JSON_THROW_ON_ERROR);
    }
}
