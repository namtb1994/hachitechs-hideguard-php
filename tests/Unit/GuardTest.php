<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Tests\Unit;

use Hachitechs\HideguardPhp\Contracts\StorageContract;
use Hachitechs\HideguardPhp\Exceptions\FailureReason;
use Hachitechs\HideguardPhp\Tests\Support\GuardBehavior;
use Hachitechs\HideguardPhp\Tests\Support\MemoryStorage;

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

    public function testUnchangedBlockedRequestsDoNotWriteSessions(): void
    {
        $this->report($this->guard, $this->context, $this->policy, $this->payload('block'));
        $before = $this->storage->sessionWrites;
        $state = $this->storage->session('site', 'browser');
        for ($i = 0; $i < 1000; $i++) {
            self::assertSame('blocked', $this->guard->preflight($this->context, $this->policy)->status);
            self::assertSame('blocked', $this->guard->report($this->context, $this->policy, [])->status);
        }
        self::assertSame($before, $this->storage->sessionWrites);
        self::assertEquals($state, $this->storage->session('site', 'browser'));
    }

    public function testWarmReuseWritesOnlyWhenTouchIntervalIsDue(): void
    {
        $policy = new \Hachitechs\HideguardPhp\Configuration\ProtectionPolicy(
            enabled: true,
            environment: 'development',
            publicKey: 'key',
            limits: new \Hachitechs\HideguardPhp\Configuration\RateLimits(scopeRequests: 1000, identityRequests: 1000)
        );
        $this->report($this->guard, $this->context, $policy, $this->payload());
        $before = $this->storage->sessionWrites;
        for ($i = 0; $i < 100; $i++) {
            $this->guard->preflight($this->context, $policy);
        }
        self::assertSame($before, $this->storage->sessionWrites);
        $this->clock->timestamp = 1060;
        $this->guard->preflight($this->context, $policy);
        self::assertSame($before + 1, $this->storage->sessionWrites);
        $this->guard->preflight($this->context, $policy);
        self::assertSame($before + 1, $this->storage->sessionWrites);
    }

    protected function createStorage(): StorageContract
    {
        return new MemoryStorage();
    }
}
