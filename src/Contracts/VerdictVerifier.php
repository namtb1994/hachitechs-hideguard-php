<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Contracts;

use Hachitechs\HideguardPhp\Access\AccessContext;
use Hachitechs\HideguardPhp\Configuration\ProtectionPolicy;
use Hachitechs\HideguardPhp\Verification\VerifiedVerdict;

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
