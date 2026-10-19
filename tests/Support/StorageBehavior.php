<?php

declare(strict_types=1);

namespace Hachitech\Antidetect\Tests\Support;

use Hachitech\Antidetect\Access\BrowserState;
use Hachitech\Antidetect\Access\RateWindow;
use Hachitech\Antidetect\Access\ResourceRef;
use Hachitech\Antidetect\Contracts\AtomicMutationContract;
use Hachitech\Antidetect\Contracts\StorageContract;
use Hachitech\Antidetect\Exceptions\FailureReason;
use Hachitech\Antidetect\Exceptions\GuardException;
use PHPUnit\Framework\TestCase;

abstract class StorageBehavior extends TestCase
{
    protected StorageContract $storage;
    protected AtomicMutationContract $atomic;

    abstract protected function createStorage(): StorageContract;

    protected function setUp(): void
    {
        $this->storage = $this->createStorage();
        self::assertInstanceOf(AtomicMutationContract::class, $this->storage);
        $this->atomic = $this->storage;
    }

    public function testStateIsDetachedAndIdentityScopesPreserveExactBytes(): void
    {
        $this->atomic->run('scope', function (): void {
            $state = new BrowserState(
                'id',
                '0',
                'visitor',
                1400,
                1200,
                'hash',
                lastSeen: 1000,
                verification: 'verified',
                verificationId: str_repeat('a', 32),
                verificationUntil: 1035
            );
            $this->storage->saveSession('scope', $state);
            $state->grantedUntil = 0;
            $this->storage->saveSession('scope ', new BrowserState('id', lastSeen: 1000));
            $this->storage->saveSession('scope', new BrowserState('id ', lastSeen: 1000));
        });
        self::assertSame(1200, $this->storage->session('scope', 'id')->grantedUntil);
        self::assertSame(str_repeat('a', 32), $this->storage->session('scope', 'id')->verificationId);
        self::assertSame(1035, $this->storage->session('scope', 'id')->verificationUntil);
        self::assertSame('0', $this->storage->session('scope', 'id')->actorId);
        $read = $this->storage->session('scope', 'id');
        $read->revoke();
        self::assertSame(1200, $this->storage->session('scope', 'id')->grantedUntil);
        self::assertSame(2, $this->storage->sessionCount('scope'));
        self::assertSame(1, $this->storage->sessionCount('scope '));
    }

    public function testDomainFailureCommitsButInfrastructureFailureRollsBackAllState(): void
    {
        try {
            $this->atomic->run('scope', function (): void {
                $this->storage->saveSession('scope', new BrowserState('committed'));
                $this->storage->saveRate('scope', hash('sha256', 'bucket'), new RateWindow(1, 2000));
                throw new GuardException(FailureReason::InvalidVerdict, 'Expected rejection.');
            });
        } catch (GuardException) {
        }
        self::assertNotNull($this->storage->session('scope', 'committed'));
        try {
            $this->atomic->run('scope', function (): void {
                $this->storage->saveSession('scope', new BrowserState('rolled-back'));
                $this->storage->saveRate('scope', hash('sha256', 'bucket'), new RateWindow(2, 2000));
                $this->storage->block('scope', 'visitor', null, 3000);
                throw new \RuntimeException('Infrastructure failure.');
            });
        } catch (\RuntimeException) {
        }
        self::assertNull($this->storage->session('scope', 'rolled-back'));
        self::assertSame(1, $this->storage->rate('scope', hash('sha256', 'bucket'))->requests);
        self::assertSame(0, $this->storage->blockExpiry('scope', 'visitor', null));
        $this->atomic->run('scope', fn() => $this->storage->saveSession('scope', new BrowserState('after-failure')));
        self::assertNotNull($this->storage->session('scope', 'after-failure'));
    }

    public function testActorVisitorNamespacesAndResetRetainUnrelatedGrant(): void
    {
        $this->atomic->run('scope', function (): void {
            $this->storage->block('scope', 'same', 'same', 2000);
            $this->storage->saveSession('scope', new BrowserState('unrelated', grantedUntil: 1500));
        });
        self::assertSame(2000, $this->storage->blockExpiry('scope', 'same', null));
        self::assertSame(2000, $this->storage->blockExpiry('scope', null, 'same'));
        self::assertSame(2, $this->atomic->run('scope', fn() => $this->storage->resetBlocks('scope')));
        self::assertSame(1500, $this->storage->session('scope', 'unrelated')->grantedUntil);
    }

    public function testScopeRevocationAndResourceTransferKeepOtherRecords(): void
    {
        $resource = new ResourceRef('custom', "quote'/?", 'uuid');
        $this->atomic->run('scope', function () use ($resource): void {
            foreach (['one', 'two'] as $browser) {
                $this->storage->saveSession('scope', new BrowserState($browser, 'uuid', grantedUntil: 1500));
            }
            $this->storage->bindResource('scope', 'one', $resource);
            $this->storage->bindResource('scope', 'two', $resource);
        });
        self::assertNull($this->storage->session('scope', 'one')->resource);
        self::assertSame('two', $this->storage->resource('scope', $resource)->browserId);
        $this->atomic->run('scope', fn() => $this->storage->revokeResource('scope', $resource));
        self::assertSame(0, $this->storage->session('scope', 'two')->grantedUntil);
        self::assertSame(1500, $this->storage->session('scope', 'one')->grantedUntil);
        $this->atomic->run('scope', fn() => $this->storage->revokeScope('scope'));
        self::assertSame(0, $this->storage->session('scope', 'one')->grantedUntil);
    }

    public function testNestingIsRejectedWithoutCommittingPartialWrites(): void
    {
        try {
            $this->atomic->run('scope', function (): void {
                $this->storage->saveSession('scope', new BrowserState('partial'));
                $this->atomic->run('scope', fn() => null);
            });
            self::fail('Nested mutation must fail.');
        } catch (\LogicException) {
        }
        self::assertNull($this->storage->session('scope', 'partial'));
    }
}
