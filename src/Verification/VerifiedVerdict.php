<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Verification;

use Hachitechs\HideguardPhp\Exceptions\FailureReason;
use Hachitechs\HideguardPhp\Exceptions\GuardException;

/** Created only by the trusted verifier supplied by the application. */
final class VerifiedVerdict
{
    public function __construct(
        public readonly string $verdict,
        public readonly string $visitorId,
        public readonly bool $verified = true,
        public readonly ?int $issuedAt = null
    ) {
        if (
            VerdictPolicy::groupFor($verdict) === null
            || !preg_match('/^[A-Za-z0-9_.:-]{1,128}$/D', $visitorId)
            || ($issuedAt !== null && $issuedAt < 1)
        ) {
            throw new GuardException(FailureReason::InvalidVerdict, 'A known verdict and visitor ID are required.');
        }
    }
}
