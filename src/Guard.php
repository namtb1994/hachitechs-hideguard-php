<?php

declare(strict_types=1);

namespace Hachitech\Antidetect;

use Hachitech\Antidetect\Access\AccessContext;
use Hachitech\Antidetect\Access\AccessDecision;
use Hachitech\Antidetect\Access\BrowserState;
use Hachitech\Antidetect\Access\RateWindow;
use Hachitech\Antidetect\Access\ResourceRef;
use Hachitech\Antidetect\Configuration\ProtectionPolicy;
use Hachitech\Antidetect\Contracts\AtomicMutationContract;
use Hachitech\Antidetect\Contracts\GuardContract;
use Hachitech\Antidetect\Contracts\StorageContract;
use Hachitech\Antidetect\Contracts\VerdictVerifier;
use Hachitech\Antidetect\Exceptions\FailureReason;
use Hachitech\Antidetect\Exceptions\GuardException;
use Hachitech\Antidetect\Verification\VerdictPolicy;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;

final class Guard implements GuardContract
{
    public function __construct(
        private readonly StorageContract $storage,
        private readonly AtomicMutationContract $atomic,
        private readonly VerdictVerifier $verifier,
        private readonly ClockInterface $clock,
        private readonly LoggerInterface $logger
    ) {
    }

    public static function factory(): Factory
    {
        return new Factory();
    }

    /** Fast read before rendering or cache lookup; never creates state or consumes rate limits. */
    public function inspect(AccessContext $context, ProtectionPolicy $policy): AccessDecision
    {
        if (!$policy->enabled) {
            return AccessDecision::disabled();
        }
        $state = $this->storage->session($context->scopeId, $context->browserId)
            ?? new BrowserState($context->browserId);
        return $this->decision($context->scopeId, $state, $context->actorId, $policy, $this->now());
    }

    public function preflight(AccessContext $context, ProtectionPolicy $policy, bool $retry = false): AccessDecision
    {
        return $this->atomic->run($context->scopeId, function () use ($context, $policy, $retry): AccessDecision {
            $this->requireEnabled($policy);
            $now = $this->now();
            $state = $this->storage->session($context->scopeId, $context->browserId);
            $decision = $this->decision(
                $context->scopeId,
                $state ?? new BrowserState($context->browserId),
                $context->actorId,
                $policy,
                $now
            );
            if ($decision->status === 'blocked') {
                $this->rememberBlock($context, $policy, $state, $decision->expiresAt, $now);
                return $decision;
            }
            $reuse = (
                ($decision->status === 'allowed' && $policy->passDuration > 0)
                || ($decision->status === 'verification_required' && $decision->verificationId !== null)
                || ($decision->status === 'verification_failed' && !$retry)
            );
            if (!$reuse && $state !== null) {
                $state->revoke();
                $state->verificationUntil = $now;
            }
            try {
                $state = $this->prepare($context, $policy, $state, $now);
            } catch (GuardException $error) {
                // Rate rejection must not leave an earlier Always grant usable.
                if (!$reuse && $state !== null) {
                    $this->storage->saveSession($context->scopeId, $state);
                }
                throw $error;
            }
            if ($reuse) {
                $this->storage->saveSession($context->scopeId, $state);
                return $decision;
            }
            // Starting a required check also revokes the previous resource grant, including Always mode.
            $state->revoke();
            $state->actorId = $context->actorId;
            $state->policyHash = $policy->fingerprint();
            $state->verification = '';
            try {
                $state->verificationId = bin2hex(random_bytes(16));
            } catch (\Throwable) {
                $this->storage->saveSession($context->scopeId, $state);
                throw new GuardException(FailureReason::VerificationUnavailable, 'Cannot start secure verification.');
            }
            $state->verificationUntil = $now + $policy->verificationTimeout;
            $this->storage->saveSession($context->scopeId, $state);
            return AccessDecision::pending($state->verificationId, $state->verificationUntil);
        });
    }

    public function report(
        AccessContext $context,
        ProtectionPolicy $policy,
        array $payload,
        ?string $verificationId = null
    ): AccessDecision {
        try {
            return $this->atomic->run($context->scopeId, function () use (
                $context,
                $policy,
                $payload,
                $verificationId
            ): AccessDecision {
                $this->requireEnabled($policy);
                $now = $this->now();
                $state = $this->storage->session($context->scopeId, $context->browserId);
                $current = $this->decision(
                    $context->scopeId,
                    $state ?? new BrowserState($context->browserId),
                    $context->actorId,
                    $policy,
                    $now
                );
                // An active ban needs neither SDK work nor verification, even for a malformed late report.
                if ($current->status === 'blocked') {
                    $this->rememberBlock($context, $policy, $state, $current->expiresAt, $now);
                    return $current;
                }
                $state = $this->prepare($context, $policy, $state, $now);
                if ($state->verificationId === null || $verificationId === null) {
                    throw new GuardException(
                        FailureReason::InvalidVerdict,
                        'Start verification before reporting a verdict.'
                    );
                }
                if (!hash_equals($state->verificationId, $verificationId)) {
                    // An older tab must not revoke or replace the current verification/grant.
                    return $current;
                }
                if ($current->status === 'verification_failed') {
                    return $current;
                }
                if ($current->status !== 'allowed' && $current->verificationId === null) {
                    throw new GuardException(FailureReason::InvalidVerdict, 'This verification is no longer active.');
                }
                try {
                    $verdict = $this->verifier->verify($payload, $context, $policy);
                    $verdictGroup = VerdictPolicy::groupFor($verdict->verdict);
                    if (
                        $policy->environment !== 'development'
                        && (!$verdict->verified || $verdictGroup === 'challenge')
                    ) {
                        throw new GuardException(
                            FailureReason::InvalidVerdict,
                            'A verified final verdict is required.'
                        );
                    }
                } catch (GuardException $error) {
                    $this->storage->revokeIdentity($context->scopeId, $state->visitorId, $context->actorId);
                    $state->revoke();
                    $state->verificationUntil = $now;
                    $this->storage->saveSession($context->scopeId, $state);
                    throw $error;
                }

                $blockedUntil = $this->storage->blockExpiry($context->scopeId, $verdict->visitorId, $context->actorId);
                if ($blockedUntil > $now || $verdictGroup === 'block') {
                    if ($blockedUntil <= $now) {
                        $blockedUntil = min($now, $verdict->issuedAt ?? $now) + $policy->blockDuration;
                        $this->storage->block($context->scopeId, $verdict->visitorId, $context->actorId, $blockedUntil);
                    }
                    $this->storage->revokeIdentity($context->scopeId, $verdict->visitorId, $context->actorId);
                    $state->revoke();
                    $state->visitorId = $verdict->visitorId;
                    $state->actorId = $context->actorId;
                    $state->blockedUntil = $blockedUntil;
                    $state->verificationId = null;
                    $state->verificationUntil = 0;
                    $this->storage->saveSession($context->scopeId, $state);
                    return AccessDecision::blocked($blockedUntil, $now);
                }

                $until = $state->visitorId === $verdict->visitorId && $policy->grants($state, $context->actorId, $now)
                    ? $state->grantedUntil : $now + $policy->grantSeconds();
                $until = min($until, ($verdict->issuedAt ?? $now) + $policy->grantSeconds());
                $state->visitorId = $verdict->visitorId;
                $state->actorId = $context->actorId;
                $state->blockedUntil = 0;
                $state->grantedUntil = $until;
                $state->policyHash = $policy->fingerprint();
                $state->verification = $verdict->verified ? 'verified' : 'unverified_test_mode';
                $state->resource = null;
                $state->verificationUntil = 0;
                $this->storage->saveSession($context->scopeId, $state);
                return AccessDecision::allowed(
                    $until,
                    $policy->passDuration,
                    $state->verification,
                    $state->verificationId
                );
            });
        } catch (GuardException $error) {
            if (
                in_array($error->reason, [FailureReason::InvalidVerdict, FailureReason::VerificationUnavailable], true)
            ) {
                $this->logRejection($error);
            }
            throw $error;
        }
    }

    /** SDK/network failures deny this attempt, without creating a visitor ban. */
    public function failVerification(
        AccessContext $context,
        ProtectionPolicy $policy,
        string $verificationId
    ): AccessDecision {
        return $this->atomic->run($context->scopeId, function () use (
            $context,
            $policy,
            $verificationId
        ): AccessDecision {
            $this->requireEnabled($policy);
            $now = $this->now();
            $state = $this->storage->session($context->scopeId, $context->browserId);
            $current = $this->decision(
                $context->scopeId,
                $state ?? new BrowserState($context->browserId),
                $context->actorId,
                $policy,
                $now
            );
            if (
                $current->status !== 'verification_required' || $current->verificationId === null
                || !hash_equals($current->verificationId, $verificationId)
            ) {
                return $current;
            }
            $state = $this->prepare($context, $policy, $state, $now);
            $state->revoke();
            $state->verificationUntil = $now;
            $this->storage->saveSession($context->scopeId, $state);
            return AccessDecision::failed($state->verificationId);
        });
    }

    public function bindGrant(AccessContext $context, ProtectionPolicy $policy, ResourceRef $resource): void
    {
        $this->atomic->run($context->scopeId, function () use ($context, $policy, $resource): void {
            if ($context->actorId !== $resource->actorId || $this->inspect($context, $policy)->status !== 'allowed') {
                throw new GuardException(
                    FailureReason::PermissionDenied,
                    'Verify access before binding this resource.'
                );
            }
            $this->storage->bindResource($context->scopeId, $context->browserId, $resource);
        });
    }

    /** For headless/business actions, use resource ownership from trusted server data. */
    public function assertResourceAllowed(string $scopeId, ProtectionPolicy $policy, ResourceRef $resource): void
    {
        AccessContext::validateId($scopeId);
        $this->atomic->run($scopeId, function () use ($scopeId, $policy, $resource): void {
            $state = $this->storage->resource($scopeId, $resource);
            if (
                $state === null || $this->decision($scopeId, $state, $resource->actorId, $policy, $this->now())
                ->status !== 'allowed'
            ) {
                throw new GuardException(FailureReason::PermissionDenied, 'This resource has no valid access grant.');
            }
        });
    }

    public function consumeGrant(string $scopeId, ResourceRef $resource): void
    {
        AccessContext::validateId($scopeId);
        $this->atomic->run($scopeId, fn() => $this->storage->revokeResource($scopeId, $resource));
    }

    public function revokeScope(string $scopeId): void
    {
        AccessContext::validateId($scopeId);
        $this->atomic->run($scopeId, fn() => $this->storage->revokeScope($scopeId));
    }

    public function resetBlocks(string $scopeId): int
    {
        AccessContext::validateId($scopeId);
        return $this->atomic->run($scopeId, fn(): int => $this->storage->resetBlocks($scopeId));
    }

    public function cleanup(string $scopeId, ProtectionPolicy $policy): void
    {
        AccessContext::validateId($scopeId);
        $this->atomic->run($scopeId, function () use ($scopeId, $policy): void {
            $now = $this->now();
            $this->storage->cleanup($scopeId, $now, $now - $policy->limits->sessionRetentionSeconds);
        });
    }

    private function now(): int
    {
        return $this->clock->now()->getTimestamp();
    }

    private function requireEnabled(ProtectionPolicy $policy): void
    {
        if (!$policy->enabled) {
            throw new GuardException(FailureReason::Disabled, 'Access protection is disabled.');
        }
    }

    /** Consume fixed-window counters while holding the scope lock. */
    private function consumeRate(AccessContext $context, ProtectionPolicy $policy, int $now): void
    {
        $limits = [
            'scope' => $policy->limits->scopeRequests,
            ($context->actorId !== null ? 'actor:' . $context->actorId : 'browser:' . $context->browserId)
                => $policy->limits->identityRequests,
        ];
        foreach ($limits as $key => $limit) {
            $hash = hash('sha256', $key);
            $window = $this->storage->rate($context->scopeId, $hash);
            if ($window === null || $window->expiresAt <= $now) {
                $window = new RateWindow(0, $now + $policy->limits->windowSeconds);
            }
            if ($window->requests >= $limit) {
                throw new GuardException(
                    FailureReason::RateLimited,
                    'Too many access requests.',
                    $window->expiresAt - $now
                );
            }
            $this->storage->saveRate(
                $context->scopeId,
                $hash,
                new RateWindow($window->requests + 1, $window->expiresAt)
            );
        }
    }

    private function prepare(
        AccessContext $context,
        ProtectionPolicy $policy,
        ?BrowserState $state,
        int $now
    ): BrowserState {
        $this->consumeRate($context, $policy, $now);
        if ($state === null && $this->storage->sessionCount($context->scopeId) >= $policy->limits->sessionCapacity) {
            throw new GuardException(FailureReason::CapacityReached, 'Browser session storage is at capacity.');
        }
        $state ??= new BrowserState($context->browserId);
        $state->lastSeen = $now;
        return $state;
    }

    /** Keep a discovered visitor/actor ban sticky in this browser, including after logout. */
    private function rememberBlock(
        AccessContext $context,
        ProtectionPolicy $policy,
        ?BrowserState $state,
        int $until,
        int $now
    ): void {
        if ($state === null && $this->storage->sessionCount($context->scopeId) >= $policy->limits->sessionCapacity) {
            throw new GuardException(FailureReason::CapacityReached, 'Browser session storage is at capacity.');
        }
        $state ??= new BrowserState($context->browserId);
        $state->blockedUntil = $until;
        $state->lastSeen = $now;
        $state->revoke();
        $state->verificationId = null;
        $state->verificationUntil = 0;
        $this->storage->saveSession($context->scopeId, $state);
    }

    private function logRejection(GuardException $error): void
    {
        try {
            $this->logger->notice('Antidetect verdict rejected.', ['reason' => $error->reason->value]);
        } catch (\Throwable) {
            // Diagnostics must neither roll back a security revocation nor replace its domain error.
        }
    }

    private function decision(
        string $scopeId,
        BrowserState $state,
        ?string $actorId,
        ProtectionPolicy $policy,
        int $now
    ): AccessDecision {
        $until = max($state->blockedUntil, $this->storage->blockExpiry($scopeId, $state->visitorId, $actorId));
        if ($until > $now) {
            return AccessDecision::blocked($until, $now);
        }
        if ($policy->grants($state, $actorId, $now)) {
            return AccessDecision::allowed(
                $state->grantedUntil,
                $policy->passDuration,
                $state->verification,
                $state->verificationId
            );
        }
        if (
            $state->verificationId !== null && $state->verificationUntil > 0 && $state->actorId === $actorId
            && $state->policyHash !== null && hash_equals($policy->fingerprint(), $state->policyHash)
        ) {
            return $state->verificationUntil > $now
                ? AccessDecision::pending($state->verificationId, $state->verificationUntil)
                : AccessDecision::failed($state->verificationId);
        }
        return AccessDecision::pending();
    }
}
