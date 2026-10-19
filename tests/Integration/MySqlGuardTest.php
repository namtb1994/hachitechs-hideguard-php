<?php

declare(strict_types=1);

namespace Hachitech\Antidetect\Tests\Integration;

use Hachitech\Antidetect\Tests\Support\GuardBehavior;
use Hachitech\Antidetect\Tests\Support\UsesMySql;
use Hachitech\Antidetect\Exceptions\FailureReason;
use Hachitech\Antidetect\Guard;
use Hachitech\Antidetect\Verification\DevelopmentVerifier;

final class MySqlGuardTest extends GuardBehavior
{
    use UsesMySql;

    public function testLoggingRunsAfterSecurityCommitAndCannotRollBackRevocation(): void
    {
        $inTransaction = null;
        $logger = $this->createMock(\Psr\Log\LoggerInterface::class);
        $logger->expects(self::once())->method('notice')->willReturnCallback(function () use (&$inTransaction): void {
            $inTransaction = $this->databaseFixture->pdo->inTransaction();
            // Simulate a logger using the caller's connection and failing its rollback.
            $this->databaseFixture->pdo->rollBack();
        });
        $guard = Guard::factory()->withStorage($this->storage)->withClock($this->clock)
            ->withVerifier(new DevelopmentVerifier())->withLogger($logger)->make();
        $this->report($guard, $this->context, $this->policy, $this->payload());
        $this->assertFailure(
            FailureReason::InvalidVerdict,
            fn() => $this->report($guard, $this->context, $this->policy, [])
        );
        self::assertFalse($inTransaction);
        self::assertSame('verification_failed', $guard->inspect($this->context, $this->policy)->status);
    }
}
