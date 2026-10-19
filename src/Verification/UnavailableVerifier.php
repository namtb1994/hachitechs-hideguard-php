<?php

declare(strict_types=1);

namespace Hachitech\Antidetect\Verification;

use Hachitech\Antidetect\Access\AccessContext;
use Hachitech\Antidetect\Configuration\ProtectionPolicy;
use Hachitech\Antidetect\Contracts\VerdictVerifier;
use Hachitech\Antidetect\Exceptions\FailureReason;
use Hachitech\Antidetect\Exceptions\GuardException;

final class UnavailableVerifier implements VerdictVerifier
{
    public function verify(array $payload, AccessContext $context, ProtectionPolicy $policy): VerifiedVerdict
    {
        throw new GuardException(FailureReason::VerificationUnavailable, 'HideGuard verification is unavailable.');
    }
}
