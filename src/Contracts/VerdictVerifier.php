<?php

declare(strict_types=1);

namespace Hachitech\Antidetect\Contracts;

use Hachitech\Antidetect\Access\AccessContext;
use Hachitech\Antidetect\Configuration\ProtectionPolicy;
use Hachitech\Antidetect\Verification\VerifiedVerdict;

interface VerdictVerifier
{
    /**
     * Authenticate signed fields and enforce the provider's supported binding/freshness rules.
     * Document replay/session guarantees that its signed format cannot provide.
     * Expected invalid payloads throw GuardException; infrastructure failures do not.
     *
     * @param array<string, mixed> $payload
     */
    public function verify(array $payload, AccessContext $context, ProtectionPolicy $policy): VerifiedVerdict;
}
