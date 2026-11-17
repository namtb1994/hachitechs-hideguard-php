<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Tests\Integration;

use Hachitechs\HideguardPhp\Access\AccessContext;
use Hachitechs\HideguardPhp\Access\BrowserState;
use Hachitechs\HideguardPhp\Exceptions\FailureReason;
use Hachitechs\HideguardPhp\Exceptions\GuardException;
use Hachitechs\HideguardPhp\Storage\PdoMySqlStorage;
use Hachitechs\HideguardPhp\Tests\Support\MySqlFixture;
use Hachitechs\HideguardPhp\Tests\Support\StorageBehavior;
use Hachitechs\HideguardPhp\Tests\Support\UsesMySql;
use Hachitechs\HideguardPhp\Configuration\ProtectionPolicy;
use Hachitechs\HideguardPhp\Guard;
use Hachitechs\HideguardPhp\Tests\Support\FrozenClock;

final class MySqlStorageTest extends StorageBehavior
{
    use UsesMySql;

    public function testLockIsSharedAcrossConnectionsAndReleasedAfterDomainFailure(): void
    {
        $other = new PdoMySqlStorage(MySqlFixture::connect(), $this->databaseFixture->prefix, 0);
        $this->atomic->run('scope', function () use ($other): void {
            try {
                $other->run('scope', fn() => null);
                self::fail('Another connection must not enter the locked scope.');
            } catch (GuardException $error) {
                self::assertSame(FailureReason::Busy, $error->reason);
            }
            self::assertSame('independent', $other->run('other-scope', fn() => 'independent'));
        });
        self::assertSame('released', $other->run('scope', fn() => 'released'));
    }

    public function testRealProcessesShareActorRateLimit(): void
    {
        $results = $this->workers(['rate', 'rate', 'rate', 'rate']);
        self::assertSame(60, array_sum(array_column($results, 'accepted')));
        self::assertSame(40, array_sum(array_column($results, 'limited')));
        self::assertSame(60, $this->storage->rate('concurrency', hash('sha256', 'actor:shared'))->requests);
    }

    public function testConcurrentReportsCannotReopenOrExtendBlock(): void
    {
        $this->workers(['allow', 'block']);
        $guard = Guard::factory()->withStorage($this->storage)->withClock(new FrozenClock())->make();
        $decision = $guard->inspect(
            new AccessContext('concurrency', 'reports'),
            new ProtectionPolicy(enabled: true, environment: 'development', publicKey: 'key')
        );
        self::assertSame('blocked', $decision->status);
        self::assertSame(4600, $decision->expiresAt);
        self::assertSame(0, $this->storage->session('concurrency', 'reports')->grantedUntil);
    }

    public function testExternalTransactionIsLeftUntouchedAndSchemaSetupIsExplicit(): void
    {
        $pdo = $this->databaseFixture->pdo;
        $pdo->beginTransaction();
        try {
            try {
                $this->atomic->run('scope', fn() => null);
                self::fail('Access storage must reject an external transaction.');
            } catch (\LogicException) {
                self::assertTrue($pdo->inTransaction());
            }
            try {
                $this->storage->initializeSchema();
                self::fail('DDL inside a transaction must be rejected.');
            } catch (\LogicException) {
                self::assertTrue($pdo->inTransaction());
            }
        } finally {
            $pdo->rollBack();
        }
    }

    public function testSetupRejectsExistingNonTransactionalTables(): void
    {
        $this->databaseFixture->pdo->exec('ALTER TABLE `' . $this->databaseFixture->prefix . 'session` ENGINE=MyISAM');
        $this->expectException(\LogicException::class);
        $this->storage->initializeSchema();
    }

    public function testExplicitSchemaUpgradeAddsAttemptColumnsWithoutLosingExistingRecords(): void
    {
        $table = '`' . $this->databaseFixture->prefix . 'session`';
        $this->atomic->run(
            'scope',
            fn() => $this->storage->saveSession('scope', new BrowserState('legacy', grantedUntil: 2000))
        );

        $this->databaseFixture->pdo->exec('ALTER TABLE ' . $table . ' DROP verification_id, DROP verification_until');
        $this->storage->initializeSchema();
        $this->storage->initializeSchema();
        self::assertSame(2000, $this->storage->session('scope', 'legacy')->grantedUntil);
        self::assertNull($this->storage->session('scope', 'legacy')->verificationId);
        self::assertSame(0, $this->storage->session('scope', 'legacy')->verificationUntil);
    }

    /**
     * @param list<string> $modes
     * @return list<array<string, int>>
     */
    private function workers(array $modes): array
    {
        $running = [];
        foreach ($modes as $index => $mode) {
            $process = proc_open(
                [
                    PHP_BINARY, dirname(__DIR__) . '/Support/worker.php',
                    $this->databaseFixture->prefix, $mode, (string)$index,
                ],
                [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
                $pipes
            );
            self::assertIsResource($process);
            fclose($pipes[0]);
            $running[] = [$process, $pipes];
        }
        $results = [];
        foreach ($running as [$process, $pipes]) {
            $output = stream_get_contents($pipes[1]);
            $error = stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            self::assertSame(0, proc_close($process), $error);
            $results[] = json_decode($output, true, 512, JSON_THROW_ON_ERROR);
        }
        return $results;
    }
}
