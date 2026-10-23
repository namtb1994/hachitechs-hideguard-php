<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Verification;

use Hachitechs\HideguardPhp\Access\AccessContext;
use Hachitechs\HideguardPhp\Configuration\ProtectionPolicy;
use Hachitechs\HideguardPhp\Contracts\VerdictVerifier;
use Hachitechs\HideguardPhp\Exceptions\FailureReason;
use Hachitechs\HideguardPhp\Exceptions\GuardException;

final class UnavailableVerifier implements VerdictVerifier
{
    public function verify(array $payload, AccessContext $context, ProtectionPolicy $policy): VerifiedVerdict
    {
        throw new GuardException(FailureReason::VerificationUnavailable, 'HideGuard verification is unavailable.');
    }
}
