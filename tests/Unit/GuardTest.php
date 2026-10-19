<?php

declare(strict_types=1);

namespace Hachitech\Antidetect\Tests\Unit;

use Hachitech\Antidetect\Contracts\StorageContract;
use Hachitech\Antidetect\Exceptions\FailureReason;
use Hachitech\Antidetect\Tests\Support\GuardBehavior;
use Hachitech\Antidetect\Tests\Support\MemoryStorage;

final class GuardTest extends GuardBehavior
{
    public function testPreflightAndReportsPersistTheirFinalSessionOnlyOnce(): void
    {
        self::assertInstanceOf(MemoryStorage::class, $this->storage);
        $this->guard->preflight($this->context, $this->policy);
        self::assertSame(1, $this->storage->sessionWrites);
        self::assertSame(1000, $this->storage->session('site', 'browser')->lastSeen);

        $this->report($this->guard, $this->context, $this->policy, $this->payload());
        self::assertSame(2, $this->storage->sessionWrites);
        self::assertSame('allowed', $this->guard->inspect($this->context, $this->policy)->status);

        $this->clock->timestamp += 10;
        $this->assertFailure(
            FailureReason::InvalidVerdict,
            fn() => $this->report($this->guard, $this->context, $this->policy, [])
        );
        self::assertSame(3, $this->storage->sessionWrites);
        self::assertSame(1010, $this->storage->session('site', 'browser')->lastSeen);
        self::assertSame('verification_failed', $this->guard->inspect($this->context, $this->policy)->status);

        $this->report($this->guard, $this->context, $this->policy, $this->payload('block'));
        self::assertSame(5, $this->storage->sessionWrites);
        self::assertSame('blocked', $this->guard->inspect($this->context, $this->policy)->status);
    }

    protected function createStorage(): StorageContract
    {
        return new MemoryStorage();
    }
}
