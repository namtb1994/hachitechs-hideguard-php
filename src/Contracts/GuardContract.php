<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Contracts;

use Hachitechs\HideguardPhp\Access\AccessContext;
use Hachitechs\HideguardPhp\Access\AccessDecision;
use Hachitechs\HideguardPhp\Access\ResourceRef;
use Hachitechs\HideguardPhp\Configuration\ProtectionPolicy;

interface GuardContract
{
    public function inspect(AccessContext $context, ProtectionPolicy $policy): AccessDecision;
    /** Begin before rendering protected content. Retry failed attempts only on an explicit user action. */
    public function preflight(AccessContext $context, ProtectionPolicy $policy, bool $retry = false): AccessDecision;
    /** @param array<string, mixed> $payload */
    public function report(
        AccessContext $context,
        ProtectionPolicy $policy,
        array $payload,
        ?string $verificationId = null
    ): AccessDecision;
    public function failVerification(
        AccessContext $context,
        ProtectionPolicy $policy,
        string $verificationId
    ): AccessDecision;
    public function bindGrant(AccessContext $context, ProtectionPolicy $policy, ResourceRef $resource): void;
    public function assertResourceAllowed(string $scopeId, ProtectionPolicy $policy, ResourceRef $resource): void;
    public function consumeGrant(string $scopeId, ResourceRef $resource): void;
    public function revokeScope(string $scopeId): void;
    public function resetBlocks(string $scopeId): int;
    public function cleanup(string $scopeId, ProtectionPolicy $policy): void;
}
