<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Tests\Integration;

use Hachitechs\HideguardPhp\Access\{AccessContext, BrowserState, ResourceRef};
use Hachitechs\HideguardPhp\Configuration\{ProtectionPolicy, RateLimits, CircuitBreakerPolicy};
use Hachitechs\HideguardPhp\Exceptions\{GuardException, FailureReason, ApiException};
use Hachitechs\HideguardPhp\Guard;
use Hachitechs\HideguardPhp\Storage\{PdoMySqlStorage, PdoCircuitBreakerStore};
use Hachitechs\HideguardPhp\Tests\Support\{MySqlFixture, FrozenClock};
use PHPUnit\Framework\TestCase;

final class HighTrafficStorageTest extends TestCase
{
    private ?MySqlFixture $fixture = null;
    private PdoMySqlStorage $storage;

    protected function setUp(): void
    {
        if (!getenv('HG_TEST_MYSQL_DSN')) {
            self::markTestSkipped('MySQL credentials required.');
        }
        $this->fixture = new MySqlFixture();
        $this->storage = new PdoMySqlStorage($this->fixture->pdo, $this->fixture->prefix);
    }

    protected function tearDown(): void
    {
        if ($this->fixture !== null) {
            $this->fixture->pdo->exec('DROP TABLE IF EXISTS `' . $this->fixture->prefix . 'circuit`');
            $this->fixture->dispose();
        }
        parent::tearDown();
    }

    private function busy(callable $work): void
    {
        try {
            $work();
            self::fail('Expected a shared lock conflict.');
        } catch (GuardException $error) {
            self::assertSame(FailureReason::Busy, $error->reason);
        }
    }

    public function testUnrelatedBrowserAndResourceEnterBeforeReleaseWhileScopeFenceAndSharedKeysBlock(): void
    {
        $other = new PdoMySqlStorage(MySqlFixture::connect(), $this->fixture->prefix, 0);
        $a = new ResourceRef('quote', '1');
        $b = new ResourceRef('quote', '2');
        $this->storage->run('scope', function () use ($other, $b): void {
            // Scope-exclusive baseline: an unrelated browser cannot enter.
            $this->busy(fn() => $other->runBrowser('scope', 'B', $b, fn() => null));
        });
        $this->storage->runBrowser('scope', 'A', $a, function () use ($other, $a, $b): void {
            self::assertSame('entered', $other->runBrowser('scope', 'B', $b, fn() => 'entered'));
            $this->busy(fn() => $other->runBrowser('scope', 'A', $b, fn() => null));
            $this->busy(fn() => $other->runResource('scope', $a, fn() => null));
            $this->busy(fn() => $other->run('scope', fn() => null));
            self::assertSame('other scope', $other->run('scope2', fn() => 'other scope'));
        });
        self::assertSame('released', $other->run('scope', fn() => 'released'));
    }

    public function testCapacityLastSlotAcrossTwentyProcessesAndTransactionalCounterRepair(): void
    {
        $this->storage->run(
            'concurrency',
            fn() => $this->storage->saveSession('concurrency', new BrowserState('existing'))
        );
        $results = $this->workers('capacity');
        self::assertSame(1, array_sum($results));
        self::assertSame(2, $this->storage->sessionCount('concurrency'));
        self::assertSame(2, (int)$this->fixture->pdo
            ->query('SELECT COUNT(*) FROM `' . $this->fixture->prefix . 'session`')->fetchColumn());
        try {
            $this->storage->run('concurrency', function (): void {
                $this->storage->saveSession('concurrency', new BrowserState('rollback'));
                throw new \RuntimeException('infrastructure failed');
            });
        } catch (\RuntimeException) {
        }
        self::assertNull($this->storage->session('concurrency', 'rollback'));
        self::assertSame(2, $this->storage->sessionCount('concurrency'));
        $this->fixture->pdo
            ->exec('UPDATE `' . $this->fixture->prefix . 'control` SET value=99 WHERE name=\'sessions\'');
        self::assertSame(99, $this->storage->sessionCount('concurrency'));
        self::assertSame(2, $this->storage->run(
            'concurrency',
            fn() => $this->storage->reconcileSessionCount('concurrency')
        ));
        $this->fixture->pdo->exec('UPDATE `' . $this->fixture->prefix . 'control` SET value=0 WHERE name=\'sessions\'');
        try {
            $this->storage->run('concurrency', fn() => $this->storage->cleanupBatch('concurrency', 2000, 2001, 100));
            self::fail('Counter underflow must roll back the batch.');
        } catch (\LogicException $error) {
            self::assertStringContainsString('counter drift', $error->getMessage());
        }
        self::assertSame(2, (int)$this->fixture->pdo
            ->query('SELECT COUNT(*) FROM `' . $this->fixture->prefix . 'session`')->fetchColumn());
        self::assertSame(2, $this->storage->run(
            'concurrency',
            fn() => $this->storage->reconcileSessionCount('concurrency')
        ));
        // An existing installation with no control table is migrated explicitly, without losing security state.
        $this->storage->run('legacy', function (): void {
            $this->storage->saveSession('legacy', new BrowserState(
                'blocked',
                visitorId: 'visitor',
                blockedUntil: 2000
            ));
            $this->storage->block('legacy', 'visitor', null, 2000);
        });
        $this->fixture->pdo->exec('DROP TABLE `' . $this->fixture->prefix . 'control`');
        $this->storage->initializeSchema();
        self::assertSame(1, $this->storage->sessionCount('legacy'));
        self::assertSame(2000, $this->storage->blockExpiry('legacy', 'visitor', null));
        self::assertSame(2000, $this->storage->session('legacy', 'blocked')->blockedUntil);
        $this->storage->initializeSchema();
        self::assertSame(2, $this->storage->sessionCount('concurrency'));
    }

    public function testTwentyTransfersKeepUniqueBindingAndConsumedGrantCannotBeRestoredByOldOwner(): void
    {
        $policy = new ProtectionPolicy(enabled: true, publicKey: 'key');
        $this->storage->run('concurrency', function () use ($policy): void {
            for ($i = 0; $i < 20; $i++) {
                $this->storage->saveSession('concurrency', new BrowserState(
                    'worker-' . $i,
                    grantedUntil: 2000,
                    policyHash: $policy->fingerprint(),
                    verification: 'verified'
                ));
            }
        });
        self::assertSame(20, array_sum($this->workers('bind')));
        $resource = new ResourceRef('quote', '99');
        $owner = $this->storage->resource('concurrency', $resource);
        self::assertNotNull($owner);
        self::assertSame(1, (int)$this->fixture->pdo->query(
            'SELECT COUNT(*) FROM `' . $this->fixture->prefix . 'session` WHERE resource_id=\'99\''
        )->fetchColumn());
        $guard = Guard::factory()->withStorage($this->storage)->withClock(new FrozenClock())->make();
        $guard->consumeGrant('concurrency', $resource);
        self::assertNull($this->storage->resource('concurrency', $resource));
        self::assertSame(0, $this->storage->session('concurrency', $owner->browserId)->grantedUntil);
        $guard->preflight(new AccessContext('concurrency', $owner->browserId), $policy);
        self::assertNull($this->storage->resource('concurrency', $resource));
        try {
            $guard->assertResourceAllowed('concurrency', $policy, $resource);
            self::fail('Consumed grant reopened.');
        } catch (GuardException $error) {
            self::assertSame(FailureReason::PermissionDenied, $error->reason);
        }
    }

    public function testBatchBudgetIsTotalAndProtectsActiveStateAndNextCallContinues(): void
    {
        $this->storage->run('scope', function (): void {
            $this->storage->block('scope', 'expired', null, 900);
            $this->storage->saveRate(
                'scope',
                hash('sha256', 'expired'),
                new \Hachitechs\HideguardPhp\Access\RateWindow(1, 900)
            );
            for ($i = 0; $i < 5; $i++) {
                $this->storage->saveSession('scope', new BrowserState('expired-' . $i));
            }
            $this->storage->saveSession('scope', new BrowserState('grant', grantedUntil: 2000));
            $this->storage->saveSession('scope', new BrowserState('block', blockedUntil: 2000));
            $this->storage->saveSession('scope', new BrowserState('attempt', verificationUntil: 2000));
        });
        $guard = Guard::factory()->withStorage($this->storage)->withClock(new FrozenClock())->make();
        $policy = new ProtectionPolicy(limits: new RateLimits(sessionRetentionSeconds: 10));
        $totals = [];
        do {
            $result = $guard->cleanupBatch('scope', $policy, 3);
            self::assertLessThanOrEqual(3, $result->total());
            $totals[] = $result->total();
        } while ($result->hasMore);
        self::assertSame([3, 3, 1], $totals);
        self::assertSame(3, $this->storage->sessionCount('scope'));
        foreach (['grant', 'block', 'attempt'] as $browser) {
            self::assertNotNull($this->storage->session('scope', $browser));
        }
        self::assertSame(0, $guard->cleanupBatch('scope', $policy, 3)->total());
    }

    public function testCircuitGenerationLeaseAndTwentySharedHalfOpenContenders(): void
    {
        $circuit = new PdoCircuitBreakerStore($this->fixture->pdo, $this->fixture->prefix . 'circuit');
        $circuit->initializeSchema();
        $policy = new CircuitBreakerPolicy(threshold: 2);
        $key = hash('sha256', 'shared');
        $stale = $circuit->acquire($key, 1000, $policy);
        for ($i = 0; $i < 2; $i++) {
            $permit = $circuit->acquire($key, 1000, $policy);
            $circuit->record($key, $permit, true, 1000, $policy);
        }
        $circuit->record($key, $stale, false, 1001, $policy);
        try {
            $circuit->acquire($key, 1029, $policy);
            self::fail('Stale success closed the circuit.');
        } catch (ApiException $error) {
            self::assertSame(503, $error->statusCode);
        }
        self::assertSame(1, array_sum($this->workers('probe')));
        try {
            $circuit->acquire($key, 1044, $policy);
            self::fail('Parallel probe allowed.');
        } catch (ApiException $error) {
            self::assertSame(503, $error->statusCode);
        }
        $expired = $circuit->acquire($key, 1045, $policy);
        $replacement = $circuit->acquire($key, 1060, $policy);
        $circuit->record($key, $expired, false, 1061, $policy);
        try {
            $circuit->acquire($key, 1061, $policy);
            self::fail('Expired probe reopened the circuit.');
        } catch (ApiException $error) {
            self::assertSame(503, $error->statusCode);
        }
        $circuit->record($key, $replacement, false, 1061, $policy);
        self::assertNull($circuit->acquire($key, 1062, $policy)->probeToken);
    }

    public function testSessionCountSeedsOnceThenAvoidsCountScansOnRepeatedReads(): void
    {
        $pdo = new class (
            (string)getenv('HG_TEST_MYSQL_DSN'),
            (string)getenv('HG_TEST_MYSQL_USER'),
            (string)getenv('HG_TEST_MYSQL_PASSWORD')
) extends \PDO {
            /** @var list<string> */
            public array $queries = [];
            public function prepare(string $query, array $options = []): \PDOStatement|false
            {
                $this->queries[] = $query;
                return parent::prepare($query, $options);
            }
        };
        $storage = new PdoMySqlStorage($pdo, $this->fixture->prefix);
        for ($i = 0; $i < 20; $i++) {
            $statement = $pdo->prepare('SELECT COUNT(*) FROM `' . $this->fixture->prefix . 'session` WHERE scope_id=?');
            $statement->execute(['seed']);
            self::assertSame(0, (int)$statement->fetchColumn());
        }
        $countScans = fn() => count(array_filter($pdo->queries, fn($query) => str_contains($query, 'COUNT(*)')));
        self::assertSame(20, $countScans());
        $pdo->queries = [];
        self::assertSame(0, $storage->sessionCount('seed'));
        self::assertSame(1, $countScans());
        $pdo->queries = [];
        for ($i = 0; $i < 20; $i++) {
            self::assertSame(0, $storage->sessionCount('seed'));
        }
        self::assertSame(0, $countScans());
    }

    public function testOutageCutsOneHundredHttpAttemptsToFiveAndRecoversWithoutDbLockDuringNetwork(): void
    {
        $circuit = new PdoCircuitBreakerStore($this->fixture->pdo, $this->fixture->prefix . 'circuit');
        $circuit->initializeSchema();
        $count = 0;
        $fail = true;
        $clock = new FrozenClock();
        $transport = $this->createMock(\Hachitechs\HideguardPhp\Contracts\HttpTransport::class);
        $transport->method('post')->willReturnCallback(function () use (&$count, &$fail) {
            self::assertFalse($this->fixture->pdo->inTransaction(), 'Network must run outside DB locks.');
            $count++;
            return new \Hachitechs\HideguardPhp\Http\HttpResponse($fail ? 503 : 200, '{}');
        });
        for ($i = 0; $i < 100; $i++) {
            $transport->post('https://fixture', [], '{}');
        }
        self::assertSame(100, $count);
        $count = 0;
        $decorator = new \Hachitechs\HideguardPhp\Http\CircuitBreakingTransport(
            $transport,
            $circuit,
            $clock,
            new CircuitBreakerPolicy(),
            'site'
        );
        for ($i = 0; $i < 100; $i++) {
            try {
                $decorator->post('https://fixture', [], '{}');
            } catch (ApiException $error) {
                self::assertSame(503, $error->statusCode);
            }
        }
        self::assertSame(5, $count);
        $clock->timestamp = 1030;
        $fail = false;
        self::assertSame(200, $decorator->post('https://fixture', [], '{}')->statusCode);
        self::assertSame(200, $decorator->post('https://fixture', [], '{}')->statusCode);
        self::assertSame(7, $count);
    }

    public function testCircuitRowContentionIsBoundedAndFailsClosedWithoutHttp(): void
    {
        $circuit = new PdoCircuitBreakerStore($this->fixture->pdo, $this->fixture->prefix . 'circuit');
        $circuit->initializeSchema();
        $key = hash('sha256', 'site:https://fixture:[]');
        $circuit->acquire($key, 1000, new CircuitBreakerPolicy());
        $other = MySqlFixture::connect();
        $other->beginTransaction();
        $statement = $other->prepare('SELECT * FROM `' . $this->fixture->prefix
            . 'circuit` WHERE circuit_key=? FOR UPDATE');
        $statement->execute([$key]);
        $transport = $this->createMock(\Hachitechs\HideguardPhp\Contracts\HttpTransport::class);
        $transport->expects(self::never())->method('post');
        $before = (int)$this->fixture->pdo->query('SELECT @@SESSION.innodb_lock_wait_timeout')->fetchColumn();
        $start = microtime(true);
        try {
            (new \Hachitechs\HideguardPhp\Http\CircuitBreakingTransport(
                $transport,
                $circuit,
                new FrozenClock(),
                new CircuitBreakerPolicy(),
                'site'
            ))->post('https://fixture', [], '{}');
            self::fail('Contended storage allowed access.');
        } catch (ApiException $error) {
            self::assertSame(503, $error->statusCode);
        } finally {
            $other->rollBack();
        }
        self::assertLessThan(5, microtime(true) - $start);
        self::assertSame($before, (int)$this->fixture->pdo
            ->query('SELECT @@SESSION.innodb_lock_wait_timeout')->fetchColumn());
        self::assertFalse($this->fixture->pdo->inTransaction());
    }

    /** @return list<int> */
    private function workers(string $mode): array
    {
        $directory = sys_get_temp_dir() . '/' . $this->fixture->prefix;
        mkdir($directory);
        $children = [];
        try {
            for ($i = 0; $i < 20; $i++) {
                $child = proc_open(
                    [PHP_BINARY, dirname(__DIR__) . '/Support/traffic-worker.php',
                    $this->fixture->prefix, $mode, (string)$i, $directory],
                    [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
                    $pipes
                );
                self::assertIsResource($child);
                fclose($pipes[0]);
                $children[] = [$child, $pipes];
            }
            $deadline = microtime(true) + 20;
            while (count(glob($directory . '/*')) < 20) {
                self::assertLessThan($deadline, microtime(true), 'Workers did not become ready.');
                usleep(10000);
            }
            file_put_contents($directory . '/go', 'go');
            $results = [];
            foreach ($children as [$child, $pipes]) {
                $output = stream_get_contents($pipes[1]);
                $error = stream_get_contents($pipes[2]);
                fclose($pipes[1]);
                fclose($pipes[2]);
                self::assertSame(0, proc_close($child), $error . $output);
                self::assertContains($output, ['0', '1']);
                $results[] = (int)$output;
            }
            $children = [];
            return $results;
        } finally {
            foreach ($children as [$child, $pipes]) {
                if (is_resource($child)) {
                    proc_terminate($child);
                }
                foreach ($pipes as $pipe) {
                    if (is_resource($pipe)) {
                        fclose($pipe);
                    }
                }
                if (is_resource($child)) {
                    proc_close($child);
                }
            }
            foreach (glob($directory . '/*') as $file) {
                unlink($file);
            }
            rmdir($directory);
        }
    }
}
