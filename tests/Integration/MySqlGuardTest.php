<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Tests\Integration;

use Hachitechs\HideguardPhp\Tests\Support\GuardBehavior;
use Hachitechs\HideguardPhp\Tests\Support\UsesMySql;
use Hachitechs\HideguardPhp\Exceptions\FailureReason;
use Hachitechs\HideguardPhp\Guard;
use Hachitechs\HideguardPhp\Tests\Support\FixtureVerdictVerifier;

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
            ->withVerifier(new FixtureVerdictVerifier())->withLogger($logger)->make();
        $this->report($guard, $this->context, $this->policy, $this->payload());
        $this->assertFailure(
            FailureReason::InvalidVerdict,
            fn() => $this->report($guard, $this->context, $this->policy, [])
        );
        self::assertFalse($inTransaction);
        self::assertSame('verification_failed', $guard->inspect($this->context, $this->policy)->status);
    }
}
