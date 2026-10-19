<?php

declare(strict_types=1);

namespace Hachitech\Antidetect\Verification;

use Hachitech\Antidetect\Access\AccessContext;
use Hachitech\Antidetect\Configuration\ProtectionPolicy;
use Hachitech\Antidetect\Contracts\VerdictVerifier;
use Hachitech\Antidetect\Exceptions\FailureReason;
use Hachitech\Antidetect\Exceptions\GuardException;

/** Explicit opt-in for development; browser payloads are forgeable in this mode. */
final class DevelopmentVerifier implements VerdictVerifier
{
    public function verify(array $payload, AccessContext $context, ProtectionPolicy $policy): VerifiedVerdict
    {
        if ($policy->environment !== 'development') {
            throw new GuardException(
                FailureReason::VerificationUnavailable,
                'Development verification cannot authorize signed environments.'
            );
        }
        if (!is_string($payload['verdict'] ?? null) || !is_string($payload['visitorId'] ?? null)) {
            throw new GuardException(FailureReason::InvalidVerdict, 'A known verdict and visitor ID are required.');
        }
        return new VerifiedVerdict($payload['verdict'], $payload['visitorId'], false);
    }
}
