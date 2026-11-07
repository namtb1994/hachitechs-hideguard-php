<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Tests\Unit;

use Hachitechs\HideguardPhp\Access\CleanupResult;
use Hachitechs\HideguardPhp\Configuration\{ProtectionPolicy, RateLimits};
use Hachitechs\HideguardPhp\Contracts\{AtomicMutationContract, StorageContract, BatchCleanupContract};
use Hachitechs\HideguardPhp\Guard;
use Hachitechs\HideguardPhp\Tests\Support\FrozenClock;
use Hachitechs\HideguardPhp\Tests\Support\BatchStorageFixture;
use PHPUnit\Framework\TestCase;

final class BatchCleanupTest extends TestCase
{
    public function testBudgetReleasesAtomicScopeBeforeEachNextBatch(): void
    {
        $inside = false;
        $atomic = $this->createMock(AtomicMutationContract::class);
        $atomic->expects(self::exactly(10))->method('run')->with('scope', self::isType('callable'))
            ->willReturnCallback(function ($scope, $work) use (&$inside) {
                self::assertFalse($inside, 'The previous batch must release its transaction.');
                $inside = true;
                try {
                    return $work();
                } finally {
                    $inside = false;
                }
            });
        $storage = $this->getMockBuilder(BatchStorageFixture::class)->getMock();
        $storage->expects(self::never())->method('cleanup');
        $storage->expects(self::exactly(10))->method('cleanupBatch')->with('scope', 1000, 980, 500)
            ->willReturnCallback(function () use (&$inside) {
                self::assertTrue($inside);
                return new CleanupResult(0, 0, 500, true);
            });
        $guard = Guard::factory()->withStorage($storage)->withAtomicMutation($atomic)
            ->withClock(new FrozenClock())->make();
        self::assertTrue($guard->supportsBatchCleanup());
        $guard->cleanup('scope', new ProtectionPolicy(limits: new RateLimits(sessionRetentionSeconds: 10)));
        self::assertFalse($inside);
    }

    public function testLegacyAdapterKeepsSingleCleanupCall(): void
    {
        $storage = $this->createMock(StorageContract::class);
        $storage->expects(self::once())->method('cleanup')->with('scope', 1000, 980);
        $atomic = $this->createMock(AtomicMutationContract::class);
        $atomic->expects(self::once())->method('run')->willReturnCallback(fn($scope, $work) => $work());
        $guard = Guard::factory()->withStorage($storage)->withAtomicMutation($atomic)
            ->withClock(new FrozenClock())->make();
        self::assertFalse($guard->supportsBatchCleanup());
        $guard->cleanup('scope', new ProtectionPolicy(limits: new RateLimits(sessionRetentionSeconds: 10)));
        $this->expectException(\LogicException::class);
        $guard->cleanupBatch('scope', new ProtectionPolicy());
    }
}
