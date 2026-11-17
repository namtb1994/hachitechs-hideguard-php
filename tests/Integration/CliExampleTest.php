<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Tests\Integration;

use Hachitechs\HideguardPhp\Tests\Support\SignedVerdictFixture;
use Hachitechs\HideguardPhp\Tests\Support\UsesMySql;
use PHPUnit\Framework\TestCase;

final class CliExampleTest extends TestCase
{
    use UsesMySql;

    protected function setUp(): void
    {
        $this->createStorage();
    }

    public function testCliVerifiesSignedVerdictsAndPreservesBlocks(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'hg-signed-');
        try {
            $payload = SignedVerdictFixture::payload();
            $payload['score']++;
            file_put_contents($file, json_encode($payload, JSON_THROW_ON_ERROR));
            [$exit, $output, $error] = $this->runExample($file);
            self::assertNotSame(0, $exit);
            self::assertStringContainsString('Invalid HideGuard response signature.', $output . $error);

            file_put_contents($file, json_encode(SignedVerdictFixture::payload(), JSON_THROW_ON_ERROR));
            [$exit, $output] = $this->runExample($file);
            self::assertSame(0, $exit);
            self::assertSame('allowed', json_decode($output, true)['status']);
            self::assertSame('verified', json_decode($output, true)['verification']);

            file_put_contents($file, json_encode(SignedVerdictFixture::payload('block'), JSON_THROW_ON_ERROR));
            [$exit, $output] = $this->runExample($file);
            self::assertSame(0, $exit);
            $blocked = json_decode($output, true);
            self::assertSame('blocked', $blocked['status']);
            [$exit, $output] = $this->runExample($file);
            self::assertSame(0, $exit);
            self::assertSame($blocked['blockedUntil'], json_decode($output, true)['blockedUntil']);
        } finally {
            unlink($file);
        }
    }

    /** @return array{int, string, string} */
    private function runExample(string $file): array
    {
        $process = proc_open(
            [PHP_BINARY, 'examples/plain-php/demo.php', $file],
            [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            dirname(__DIR__, 2),
            array_merge(getenv(), [
                'HG_MYSQL_DSN' => getenv('HG_TEST_MYSQL_DSN'),
                'HG_MYSQL_USER' => getenv('HG_TEST_MYSQL_USER'),
                'HG_MYSQL_PASSWORD' => getenv('HG_TEST_MYSQL_PASSWORD'),
                'HG_TABLE_PREFIX' => $this->databaseFixture->prefix,
                'HG_SITE_KEY' => 'test-site-key',
                'HG_SIGNATURE_PUBLIC_KEY' => SignedVerdictFixture::publicKey(),
            ])
        );
        $output = stream_get_contents($pipes[1]);
        $error = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        return [proc_close($process), $output, $error];
    }
}
