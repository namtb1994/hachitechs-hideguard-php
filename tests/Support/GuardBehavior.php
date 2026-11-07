<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Tests\Support;

use Hachitechs\HideguardPhp\Access\AccessContext;
use Hachitechs\HideguardPhp\Access\AccessDecision;
use Hachitechs\HideguardPhp\Access\BrowserState;
use Hachitechs\HideguardPhp\Access\ResourceRef;
use Hachitechs\HideguardPhp\Access\RateWindow;
use Hachitechs\HideguardPhp\Configuration\ProtectionPolicy;
use Hachitechs\HideguardPhp\Configuration\RateLimits;
use Hachitechs\HideguardPhp\Contracts\AtomicMutationContract;
use Hachitechs\HideguardPhp\Contracts\StorageContract;
use Hachitechs\HideguardPhp\Contracts\VerdictVerifier;
use Hachitechs\HideguardPhp\Exceptions\FailureReason;
use Hachitechs\HideguardPhp\Exceptions\GuardException;
use Hachitechs\HideguardPhp\Guard;
use Hachitechs\HideguardPhp\Verification\DevelopmentVerifier;
use Hachitechs\HideguardPhp\Verification\VerifiedVerdict;
use PHPUnit\Framework\TestCase;

/** Run the same access behavior against each storage implementation. */
abstract class GuardBehavior extends TestCase
{
    protected StorageContract $storage;
    protected FrozenClock $clock;
    protected Guard $guard;
    protected AccessContext $context;
    protected ProtectionPolicy $policy;

    /** Arrange an active attempt for tests of verdict/storage behavior. */
    protected function report(
        Guard $guard,
        AccessContext $context,
        ProtectionPolicy $policy,
        array $payload
    ): AccessDecision {
        $decision = $guard->inspect($context, $policy);
        if (
            $decision->status === 'verification_failed'
            || ($decision->status === 'verification_required' && $decision->verificationId === null)
        ) {
            $decision = $guard->preflight($context, $policy, true);
        }
        return $guard->report($context, $policy, $payload, $decision->verificationId);
    }

    public function testRejectedIdentityDoesNotExhaustScopeBudget(): void
    {
        for ($i = 0; $i < 60; $i++) {
            $this->guard->preflight($this->context, $this->policy);
        }
        for ($i = 0; $i < 540; $i++) {
            $this->assertFailure(
                FailureReason::RateLimited,
                fn() => $this->guard->preflight($this->context, $this->policy)
            );
        }
        self::assertSame(60, $this->storage->rate('site', hash('sha256', 'scope'))->requests);
        self::assertSame(60, $this->storage->rate('site', hash('sha256', 'browser:browser'))->requests);
        $this->guard->preflight(new AccessContext('site', 'other-browser'), $this->policy);
        self::assertSame(61, $this->storage->rate('site', hash('sha256', 'scope'))->requests);
    }

    public function testQuotaRejectionPreservesBothCountersAndLongestDeadline(): void
    {
        $this->storage->run('site', function (): void {
            $this->storage->saveRate('site', hash('sha256', 'scope'), new RateWindow(600, 1030));
            $this->storage->saveRate('site', hash('sha256', 'browser:browser'), new RateWindow(60, 1050));
        });
        $error = $this->assertFailure(
            FailureReason::RateLimited,
            fn() => $this->guard->preflight($this->context, $this->policy)
        );
        self::assertSame(50, $error->retryAfterSeconds);
        self::assertSame(600, $this->storage->rate('site', hash('sha256', 'scope'))->requests);
        self::assertSame(60, $this->storage->rate('site', hash('sha256', 'browser:browser'))->requests);
        $this->clock->timestamp = 1050;
        $this->guard->preflight($this->context, $this->policy);
        self::assertSame(1, $this->storage->rate('site', hash('sha256', 'scope'))->requests);
        self::assertSame(1, $this->storage->rate('site', hash('sha256', 'browser:browser'))->requests);
    }

    public function testScopeRejectionDoesNotChargeNewIdentity(): void
    {
        $this->storage->run('site', function (): void {
            $this->storage->saveRate('site', hash('sha256', 'scope'), new RateWindow(600, 1060));
        });
        $this->assertFailure(
            FailureReason::RateLimited,
            fn() => $this->guard->preflight($this->context, $this->policy)
        );
        self::assertNull($this->storage->rate('site', hash('sha256', 'browser:browser')));
        self::assertSame(600, $this->storage->rate('site', hash('sha256', 'scope'))->requests);
    }

    public function testWarmPreflightsCoalesceLastSeenButStillConsumeQuota(): void
    {
        $policy = new ProtectionPolicy(
            enabled: true,
            publicKey: 'key',
            limits: new RateLimits(scopeRequests: 1000, identityRequests: 1000)
        );
        $this->report($this->guard, $this->context, $policy, $this->payload());
        $this->guard->bindGrant($this->context, $policy, new ResourceRef('quote', '99'));
        $before = $this->storage->session('site', 'browser');
        $this->clock->timestamp = 1001;
        for ($i = 0; $i < 100; $i++) {
            self::assertSame('allowed', $this->guard->preflight($this->context, $policy)->status);
        }
        self::assertEquals($before, $this->storage->session('site', 'browser'));
        self::assertSame(102, $this->storage->rate('site', hash('sha256', 'scope'))->requests);
        $this->clock->timestamp = 1060;
        $this->guard->preflight($this->context, $policy);
        $after = $this->storage->session('site', 'browser');
        self::assertSame(1060, $after->lastSeen);
        $after->lastSeen = $before->lastSeen;
        self::assertEquals($before, $after);
    }

    public function testCleanupGracePreservesSessionsAtTheCoalescingBoundary(): void
    {
        $policy = new ProtectionPolicy(limits: new RateLimits(sessionRetentionSeconds: 50));
        $this->storage->run('site', function (): void {
            $this->storage->saveSession('site', new BrowserState('idle', lastSeen: 1000));
            $this->storage->saveSession('site', new BrowserState('blocked', blockedUntil: 3000, lastSeen: 1));
            $this->storage->saveSession('site', new BrowserState('granted', grantedUntil: 3000, lastSeen: 1));
        });
        $this->clock->timestamp = 1100;
        $this->guard->cleanup('site', $policy);
        self::assertNotNull($this->storage->session('site', 'idle'));
        $this->clock->timestamp = 1101;
        $this->guard->cleanup('site', $policy);
        self::assertNull($this->storage->session('site', 'idle'));
        self::assertNotNull($this->storage->session('site', 'blocked'));
        self::assertNotNull($this->storage->session('site', 'granted'));
    }

    abstract protected function createStorage(): StorageContract;

    protected function setUp(): void
    {
        $this->storage = $this->createStorage();
        $this->clock = new FrozenClock();
        $this->guard = Guard::factory()->withStorage($this->storage)->withClock($this->clock)
            ->withVerifier(new DevelopmentVerifier())->make();
        $this->context = new AccessContext('site', 'browser');
        $this->policy = new ProtectionPolicy(enabled: true, publicKey: 'site-key', accessPoints: ['custom_action']);
    }

    public function testInspectHasNoMutationAndDisabledPolicyDoesNotAuthorize(): void
    {
        self::assertSame('verification_required', $this->guard->inspect($this->context, $this->policy)->status);
        self::assertSame(0, $this->storage->sessionCount('site'));
        self::assertNull($this->storage->rate('site', hash('sha256', 'scope')));
        self::assertSame('disabled', $this->guard->inspect($this->context, new ProtectionPolicy())->status);
        $this->assertFailure(
            FailureReason::Disabled,
            fn() => $this->guard->preflight($this->context, new ProtectionPolicy())
        );
    }

    /** @dataProvider intervals */
    public function testIntervalDeadlineAndRepeatedVerdictDoNotSlide(int $interval, int $lifetime): void
    {
        $policy = new ProtectionPolicy(enabled: true, publicKey: 'key', passDuration: $interval);
        $grant = $this->report($this->guard, $this->context, $policy, $this->payload());
        self::assertSame(1000 + $lifetime, $grant->expiresAt);
        self::assertSame($interval, $grant->passDuration);
        self::assertSame($grant->expiresAt * 1000, $grant->toBrowserArray()['expiresAt']);
        $this->clock->timestamp += 10;
        self::assertSame($grant->expiresAt, $this->guard->preflight($this->context, $policy)->expiresAt);
        self::assertSame(
            $grant->expiresAt,
            $this->report($this->guard, $this->context, $policy, $this->payload())->expiresAt
        );
        $this->clock->timestamp = $grant->expiresAt;
        self::assertSame('verification_required', $this->guard->inspect($this->context, $policy)->status);
        self::assertSame(
            $grant->expiresAt + $lifetime,
            $this->report($this->guard, $this->context, $policy, $this->payload())->expiresAt
        );
    }

    public static function intervals(): array
    {
        return [[60, 60], [300, 300], [900, 900], [3600, 3600]];
    }

    public function testPolicyOrActorChangeCannotReusePass(): void
    {
        $this->report($this->guard, $this->context, $this->policy, $this->payload());
        $actor = new AccessContext('site', 'browser', 'uuid-customer');
        self::assertSame('verification_required', $this->guard->inspect($actor, $this->policy)->status);
        $different = new ProtectionPolicy(enabled: true, publicKey: 'key', accessPoints: ['other']);
        self::assertSame('verification_required', $this->guard->inspect($this->context, $different)->status);
        $this->report($this->guard, $actor, $this->policy, $this->payload());
        self::assertSame('verification_required', $this->guard->inspect($this->context, $this->policy)->status);
    }

    public function testBlockWinsLateAllowAndDoesNotExtendItsDeadline(): void
    {
        $this->report($this->guard, $this->context, $this->policy, $this->payload());
        $resource = new ResourceRef('application', 'resource');
        $this->guard->bindGrant($this->context, $this->policy, $resource);
        $block = $this->report($this->guard, $this->context, $this->policy, $this->payload('block'));
        self::assertSame('blocked', $block->status);
        self::assertSame(4600, $block->expiresAt);
        $this->clock->timestamp = 1100;
        foreach ([$this->payload('allow', 'new_visitor'), $this->payload('block'), []] as $late) {
            $result = $this->report($this->guard, $this->context, $this->policy, $late);
            self::assertSame($block->expiresAt, $result->expiresAt);
            self::assertSame(3500000, $result->toBrowserArray()['retryAfterMs']);
        }
        self::assertSame('blocked', $this->guard->preflight($this->context, $this->policy)->status);
        $this->assertFailure(
            FailureReason::PermissionDenied,
            fn() => $this->guard->assertResourceAllowed('site', $this->policy, $resource)
        );
        $this->clock->timestamp = 4600;
        self::assertSame('verification_required', $this->guard->preflight($this->context, $this->policy)->status);
        self::assertSame(
            'allowed',
            $this->report($this->guard, $this->context, $this->policy, $this->payload())->status
        );
    }

    public function testVisitorBlockTravelsToOtherBrowsersAndScopesRemainIndependent(): void
    {
        $block = $this->report($this->guard, $this->context, $this->policy, $this->payload('block'));
        $other = new AccessContext('site', 'other');
        self::assertSame(
            $block->expiresAt,
            $this->report($this->guard, $other, $this->policy, $this->payload())->expiresAt
        );
        $elsewhere = new AccessContext('other-site', 'browser');
        self::assertSame('allowed', $this->report($this->guard, $elsewhere, $this->policy, $this->payload())->status);
    }

    public function testActorBlockIsPersistedOnNewBrowserBeforeLogout(): void
    {
        $actor = new AccessContext('site', 'browser', '0');
        $block = $this->report($this->guard, $actor, $this->policy, $this->payload('block'));
        $newBrowser = new AccessContext('site', 'new-browser', '0');
        self::assertSame($block->expiresAt, $this->guard->preflight($newBrowser, $this->policy)->expiresAt);
        $loggedOut = new AccessContext('site', 'new-browser');
        self::assertSame('blocked', $this->guard->inspect($loggedOut, $this->policy)->status);
        self::assertSame(
            'blocked',
            $this->report($this->guard, $loggedOut, $this->policy, $this->payload('allow', 'different'))->status
        );
    }

    public function testInvalidVerdictRevokesAllRelatedGrantsAndResourceBinding(): void
    {
        $other = new AccessContext('site', 'other');
        $this->report($this->guard, $this->context, $this->policy, $this->payload());
        $this->report($this->guard, $other, $this->policy, $this->payload());
        $resource = new ResourceRef('form', 'submission');
        $this->guard->bindGrant($this->context, $this->policy, $resource);
        $this->assertFailure(
            FailureReason::InvalidVerdict,
            fn() => $this->report($this->guard, $this->context, $this->policy, [])
        );
        self::assertSame('verification_failed', $this->guard->inspect($this->context, $this->policy)->status);
        self::assertSame('verification_required', $this->guard->inspect($other, $this->policy)->status);
        self::assertNull($this->storage->resource('site', $resource));
    }

    public function testDefaultVerifierFailsClosedAndProductionCannotUseDevelopmentProof(): void
    {
        $default = Guard::factory()->withStorage($this->storage)->withClock($this->clock)->make();
        $this->assertFailure(
            FailureReason::VerificationUnavailable,
            fn() => $this->report($default, $this->context, $this->policy, $this->payload())
        );
        $production = new ProtectionPolicy(
            enabled: true,
            environment: 'production',
            publicKey: 'key',
            signaturePublicKey: 'signature'
        );
        $this->assertFailure(
            FailureReason::VerificationUnavailable,
            fn() => $this->report($this->guard, $this->context, $production, $this->payload())
        );
        $state = new BrowserState(
            'browser',
            grantedUntil: 2000,
            policyHash: $production->fingerprint(),
            verification: 'unverified_test_mode'
        );
        $this->storage->run('site', fn() => $this->storage->saveSession('site', $state));
        self::assertSame('verification_required', $this->guard->inspect($this->context, $production)->status);
    }

    public function testTrustedVerifierAllowsChallengeButRejectsUnsignedProductionVerdicts(): void
    {
        // A trusted deterministic fixture, not an implementation of HideGuard signing.
        $verifier = new class implements VerdictVerifier {
            public bool $verified = true;
            public function verify(array $payload, AccessContext $context, ProtectionPolicy $policy): VerifiedVerdict
            {
                return new VerifiedVerdict($payload['verdict'], $payload['visitorId'], $this->verified);
            }
        };
        $guard = Guard::factory()->withStorage($this->storage)->withClock($this->clock)
            ->withVerifier($verifier)->make();
        $policy = new ProtectionPolicy(
            enabled: true,
            environment: 'production',
            publicKey: 'key',
            signaturePublicKey: 'signature'
        );
        self::assertSame('verified', $this->report($guard, $this->context, $policy, $this->payload())->verification);
        self::assertSame('allowed', $guard->inspect($this->context, $policy)->status);
        $challengeContext = new AccessContext('site', 'challenge-browser');
        self::assertSame('allowed', $this->report(
            $guard,
            $challengeContext,
            $policy,
            $this->payload('challenge', 'challenge-visitor')
        )->status);
        $verifier->verified = false;
        $this->assertFailure(
            FailureReason::InvalidVerdict,
            fn() => $this->report($guard, $this->context, $policy, $this->payload())
        );
        self::assertSame('verification_failed', $guard->inspect($this->context, $policy)->status);
    }

    public function testRevokedScopeAndIdentityAttemptsCannotBeCompletedByLateReports(): void
    {
        self::assertInstanceOf(AtomicMutationContract::class, $this->storage);
        $context = new AccessContext('site', 'browser', 'actor');
        foreach (['scope', 'identity'] as $kind) {
            $attempt = $this->guard->preflight($context, $this->policy);
            if ($kind === 'scope') {
                $this->guard->revokeScope('site');
            } else {
                $this->storage->run('site', fn() => $this->storage->revokeIdentity('site', null, 'actor'));
            }
            self::assertNull($this->storage->session('site', 'browser')->verificationId);
            $this->assertFailure(FailureReason::InvalidVerdict, fn() => $this->guard->report(
                $context,
                $this->policy,
                $this->payload(),
                $attempt->verificationId
            ));
            $next = $this->guard->preflight($context, $this->policy);
            self::assertNotSame($attempt->verificationId, $next->verificationId);
            self::assertSame('verification_required', $this->guard->report(
                $context,
                $this->policy,
                $this->payload(),
                $attempt->verificationId
            )->status);
            self::assertSame('allowed', $this->guard->report(
                $context,
                $this->policy,
                $this->payload(),
                $next->verificationId
            )->status);
            $this->guard->revokeScope('site');
        }
    }

    public function testResourceBindingChecksOwnerTypeScopeAndCurrentGrant(): void
    {
        $actor = new AccessContext('site', 'browser', 'uuid');
        $resource = new ResourceRef('form', 'uuid-resource', 'uuid');
        $this->assertFailure(
            FailureReason::PermissionDenied,
            fn() => $this->guard->bindGrant($actor, $this->policy, $resource)
        );
        $this->report($this->guard, $actor, $this->policy, $this->payload());
        $this->guard->bindGrant($actor, $this->policy, $resource);
        $this->guard->assertResourceAllowed('site', $this->policy, $resource);
        $wrongResources = [new ResourceRef('form', 'uuid-resource'), new ResourceRef('other', 'uuid-resource', 'uuid')];
        foreach ($wrongResources as $wrong) {
            $this->assertFailure(
                FailureReason::PermissionDenied,
                fn() => $this->guard->assertResourceAllowed('site', $this->policy, $wrong)
            );
        }
        $this->assertFailure(
            FailureReason::PermissionDenied,
            fn() => $this->guard->assertResourceAllowed('other-site', $this->policy, $resource)
        );
        $this->assertFailure(
            FailureReason::PermissionDenied,
            fn() => $this->guard->bindGrant($actor, $this->policy, new ResourceRef('form', 'wrong-owner'))
        );
        $this->clock->timestamp = 1300;
        $this->assertFailure(
            FailureReason::PermissionDenied,
            fn() => $this->guard->assertResourceAllowed('site', $this->policy, $resource)
        );
    }

    public function testResourceTransferAndConsumeUseLatestBrowser(): void
    {
        $other = new AccessContext('site', 'other');
        $resource = new ResourceRef('cart', 'cart-id');
        $this->report($this->guard, $this->context, $this->policy, $this->payload());
        $this->guard->bindGrant($this->context, $this->policy, $resource);
        $this->report($this->guard, $other, $this->policy, $this->payload('allow', 'other_visitor'));
        $this->guard->bindGrant($other, $this->policy, $resource);
        self::assertNull($this->storage->session('site', 'browser')->resource);
        self::assertSame('other', $this->storage->resource('site', $resource)->browserId);
        $this->guard->consumeGrant('site', $resource);
        self::assertSame('verification_required', $this->guard->inspect($other, $this->policy)->status);
        self::assertSame('allowed', $this->guard->inspect($this->context, $this->policy)->status);
    }

    public function testResetAndPolicyRevocationDoNotEraseOtherScopeBlocks(): void
    {
        $other = new AccessContext('elsewhere', 'browser');
        $this->report($this->guard, $this->context, $this->policy, $this->payload('block'));
        $this->report($this->guard, $other, $this->policy, $this->payload('block'));
        $this->guard->revokeScope('site');
        self::assertSame('blocked', $this->guard->inspect($this->context, $this->policy)->status);
        self::assertSame(1, $this->guard->resetBlocks('site'));
        self::assertSame('verification_required', $this->guard->inspect($this->context, $this->policy)->status);
        self::assertSame('blocked', $this->guard->inspect($other, $this->policy)->status);
    }

    public function testIdentityAndScopeRateLimitsAndFixedWindowExpiry(): void
    {
        $policy = new ProtectionPolicy(
            enabled: true,
            publicKey: 'key',
            limits: new RateLimits(scopeRequests: 3, identityRequests: 2)
        );
        $this->guard->preflight($this->context, $policy);
        $this->guard->preflight($this->context, $policy);
        $error = $this->assertFailure(
            FailureReason::RateLimited,
            fn() => $this->guard->preflight($this->context, $policy)
        );
        self::assertSame(60, $error->retryAfterSeconds);
        $other = new AccessContext('site', 'other');
        self::assertSame('verification_required', $this->guard->preflight($other, $policy)->status);
        $this->assertFailure(FailureReason::RateLimited, fn() => $this->guard->preflight($other, $policy));
        $this->clock->timestamp = 1060;
        self::assertSame('verification_required', $this->guard->preflight($other, $policy, true)->status);
    }

    public function testActorLimitCannotBeBypassedByChangingBrowser(): void
    {
        $policy = new ProtectionPolicy(enabled: true, publicKey: 'key', limits: new RateLimits(identityRequests: 1));
        $this->guard->preflight(new AccessContext('site', 'one', 'actor'), $policy);
        $this->assertFailure(
            FailureReason::RateLimited,
            fn() => $this->guard->preflight(new AccessContext('site', 'two', 'actor'), $policy)
        );
    }

    public function testSessionCapacityDoesNotLimitExistingBrowserOrAnotherScope(): void
    {
        $policy = new ProtectionPolicy(enabled: true, publicKey: 'key', limits: new RateLimits(sessionCapacity: 1));
        $this->guard->preflight($this->context, $policy);
        $this->guard->preflight($this->context, $policy);
        $this->assertFailure(
            FailureReason::CapacityReached,
            fn() => $this->guard->preflight(new AccessContext('site', 'other'), $policy)
        );
        self::assertSame(1, $this->storage->sessionCount('site'));
        $this->guard->preflight(new AccessContext('elsewhere', 'other'), $policy);
        self::assertSame(1, $this->storage->sessionCount('elsewhere'));
    }

    public function testCleanupDoesNotDeleteActiveBlockOrGrant(): void
    {
        $policy = new ProtectionPolicy(
            enabled: true,
            publicKey: 'key',
            limits: new RateLimits(sessionRetentionSeconds: 1)
        );
        $this->report($this->guard, $this->context, $policy, $this->payload('block'));
        $other = new AccessContext('site', 'other');
        $this->report($this->guard, $other, $policy, $this->payload('allow', 'other_visitor'));
        $this->guard->preflight(new AccessContext('site', 'stale'), $policy);
        $this->clock->timestamp = 1100;
        $this->guard->cleanup('site', $policy);
        self::assertSame(2, $this->storage->sessionCount('site'));
        self::assertSame('blocked', $this->guard->inspect($this->context, $policy)->status);
        self::assertSame('allowed', $this->guard->inspect($other, $policy)->status);
        $this->clock->timestamp = 4600;
        $this->guard->cleanup('site', $policy);
        self::assertSame(0, $this->storage->sessionCount('site'));
    }

    public function testActiveBlockSkipsVerifierAndRateConsumption(): void
    {
        $verifier = new class implements VerdictVerifier {
            public int $calls = 0;
            public function verify(array $payload, AccessContext $context, ProtectionPolicy $policy): VerifiedVerdict
            {
                $this->calls++;
                return (new DevelopmentVerifier())->verify($payload, $context, $policy);
            }
        };
        $guard = Guard::factory()->withStorage($this->storage)->withClock($this->clock)
            ->withVerifier($verifier)->make();
        $this->report($guard, $this->context, $this->policy, $this->payload('block'));
        for ($i = 0; $i < 65; $i++) {
            self::assertSame('blocked', $guard->preflight($this->context, $this->policy)->status);
            self::assertSame('blocked', $this->report($guard, $this->context, $this->policy, [])->status);
        }
        self::assertSame(1, $verifier->calls);
        self::assertSame(2, $this->storage->rate('site', hash('sha256', 'scope'))->requests);
    }

    public function testLoggerFailureCannotRestoreARevokedGrant(): void
    {
        $logger = $this->createMock(\Psr\Log\LoggerInterface::class);
        $logger->expects(self::once())->method('notice')->willThrowException(new \RuntimeException('Logging failed.'));
        $guard = Guard::factory()->withStorage($this->storage)->withClock($this->clock)
            ->withVerifier(new DevelopmentVerifier())->withLogger($logger)->make();
        $this->report($guard, $this->context, $this->policy, $this->payload());
        $this->assertFailure(
            FailureReason::InvalidVerdict,
            fn() => $this->report($guard, $this->context, $this->policy, [])
        );
        self::assertSame('verification_failed', $guard->inspect($this->context, $this->policy)->status);
    }

    public function testVerifierInfrastructureFailureDoesNotCreateGrantOrPersistPartialCounters(): void
    {
        $verifier = new class implements VerdictVerifier {
            public function verify(array $payload, AccessContext $context, ProtectionPolicy $policy): VerifiedVerdict
            {
                throw new \RuntimeException('Verifier service is unavailable.');
            }
        };
        $guard = Guard::factory()->withStorage($this->storage)->withClock($this->clock)
            ->withVerifier($verifier)->make();
        try {
            $this->report($guard, $this->context, $this->policy, $this->payload());
            self::fail('Expected an infrastructure failure.');
        } catch (\RuntimeException $error) {
            self::assertSame('Verifier service is unavailable.', $error->getMessage());
        }
        self::assertSame('verification_required', $guard->inspect($this->context, $this->policy)->status);
        self::assertSame(1, $this->storage->rate('site', hash('sha256', 'scope'))->requests);
    }

    public function testVerificationDeadlineStartsAtServerAndReloadsCannotExtendIt(): void
    {
        $first = $this->guard->preflight($this->context, $this->policy);
        self::assertMatchesRegularExpression('/^[a-f0-9]{32}$/', $first->verificationId);
        self::assertSame(1035, $first->expiresAt);
        self::assertSame(1035000, $first->toBrowserArray()['verificationUntil']);
        $this->clock->timestamp = 1020;
        foreach ([false, true] as $retry) {
            $again = $this->guard->preflight($this->context, $this->policy, $retry);
            self::assertSame($first->verificationId, $again->verificationId);
            self::assertSame($first->expiresAt, $again->expiresAt);
        }
        $this->clock->timestamp = 1035;
        self::assertSame('verification_failed', $this->guard->inspect($this->context, $this->policy)->status);
        self::assertSame('verification_failed', $this->guard->preflight($this->context, $this->policy)->status);
        self::assertSame('verification_failed', $this->guard->report(
            $this->context,
            $this->policy,
            $this->payload(),
            $first->verificationId
        )->status);
        self::assertSame(0, $this->storage->blockExpiry('site', 'visitor', null));
        $retry = $this->guard->preflight($this->context, $this->policy, true);
        self::assertNotSame($first->verificationId, $retry->verificationId);
        self::assertSame(1070, $retry->expiresAt);
    }

    public function testAlwaysRevokesPreviousGrantBeforeRenderingTheNextPage(): void
    {
        $policy = new ProtectionPolicy(enabled: true, publicKey: 'key', passDuration: 0);
        $first = $this->guard->preflight($this->context, $policy);
        $this->guard->report($this->context, $policy, $this->payload(), $first->verificationId);
        $resource = new ResourceRef('custom', 'operation');
        $this->guard->bindGrant($this->context, $policy, $resource);
        $next = $this->guard->preflight($this->context, $policy);
        self::assertSame('verification_required', $next->status);
        self::assertNotSame($first->verificationId, $next->verificationId);
        self::assertNull($this->storage->resource('site', $resource));
        $this->assertFailure(
            FailureReason::PermissionDenied,
            fn() => $this->guard->assertResourceAllowed('site', $policy, $resource)
        );
        // Old SDK reports cannot open the new page or revoke its newer grant.
        self::assertSame('verification_required', $this->guard->report(
            $this->context,
            $policy,
            $this->payload(),
            $first->verificationId
        )->status);
        $grant = $this->guard->report($this->context, $policy, $this->payload(), $next->verificationId);
        self::assertSame('allowed', $grant->status);
        self::assertSame('allowed', $this->guard->report($this->context, $policy, [], $first->verificationId)->status);
        self::assertSame(
            'allowed',
            $this->guard->failVerification($this->context, $policy, $first->verificationId)->status
        );
        self::assertSame(
            'allowed',
            $this->guard->failVerification($this->context, $policy, $next->verificationId)->status
        );
    }

    public function testSdkFailureDeniesAttemptAndRequiresExplicitRetryWithoutBanningVisitor(): void
    {
        $first = $this->guard->preflight($this->context, $this->policy);
        self::assertSame('verification_required', $this->guard->failVerification(
            $this->context,
            $this->policy,
            'incorrect-attempt'
        )->status);
        self::assertSame('verification_failed', $this->guard->failVerification(
            $this->context,
            $this->policy,
            $first->verificationId
        )->status);
        self::assertSame('verification_failed', $this->guard->preflight($this->context, $this->policy)->status);
        self::assertSame(0, $this->storage->blockExpiry('site', 'visitor', null));
        $next = $this->guard->preflight($this->context, $this->policy, true);
        self::assertNotSame($first->verificationId, $next->verificationId);
        self::assertSame('verification_required', $this->guard->failVerification(
            $this->context,
            $this->policy,
            $first->verificationId
        )->status);
        self::assertSame('allowed', $this->guard->report(
            $this->context,
            $this->policy,
            $this->payload(),
            $next->verificationId
        )->status);
    }

    public function testRateLimitedAlwaysCheckCannotReuseTheEarlierResourceGrant(): void
    {
        $policy = new ProtectionPolicy(
            enabled: true,
            publicKey: 'key',
            passDuration: 0,
            limits: new RateLimits(identityRequests: 2)
        );
        $first = $this->guard->preflight($this->context, $policy);
        $this->guard->report($this->context, $policy, $this->payload(), $first->verificationId);
        $resource = new ResourceRef('custom', 'operation');
        $this->guard->bindGrant($this->context, $policy, $resource);
        $this->assertFailure(FailureReason::RateLimited, fn() => $this->guard->preflight($this->context, $policy));
        self::assertNull($this->storage->resource('site', $resource));
        self::assertSame('verification_failed', $this->guard->inspect($this->context, $policy)->status);
    }

    public function testMissingAttemptCannotGrantAccessAndExpiredPassNeedsANewAttempt(): void
    {
        $this->assertFailure(FailureReason::InvalidVerdict, fn() => $this->guard->report(
            $this->context,
            $this->policy,
            $this->payload()
        ));
        $first = $this->guard->preflight($this->context, $this->policy);
        $this->assertFailure(FailureReason::InvalidVerdict, fn() => $this->guard->report(
            $this->context,
            $this->policy,
            $this->payload()
        ));
        $grant = $this->guard->report($this->context, $this->policy, $this->payload(), $first->verificationId);
        self::assertSame(
            $first->verificationId,
            $this->guard->preflight($this->context, $this->policy)->verificationId
        );
        $this->clock->timestamp = $grant->expiresAt;
        $this->assertFailure(FailureReason::InvalidVerdict, fn() => $this->guard->report(
            $this->context,
            $this->policy,
            $this->payload(),
            $first->verificationId
        ));
        $next = $this->guard->preflight($this->context, $this->policy);
        self::assertNotSame($first->verificationId, $next->verificationId);
    }

    protected function payload(string $verdict = 'allow', string $visitor = 'visitor'): array
    {
        return ['verdict' => $verdict, 'visitorId' => $visitor];
    }

    protected function assertFailure(FailureReason $reason, callable $work): GuardException
    {
        try {
            $work();
            self::fail('Expected domain rejection: ' . $reason->value);
        } catch (GuardException $error) {
            self::assertSame($reason, $error->reason);
            return $error;
        }
    }
}
