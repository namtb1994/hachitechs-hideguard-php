<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Contracts;

use Hachitechs\HideguardPhp\Access\CleanupResult;
use Hachitechs\HideguardPhp\Configuration\ProtectionPolicy;

interface BatchGuardContract
{
    public function supportsBatchCleanup(): bool;
    public function cleanupBatch(string $scopeId, ProtectionPolicy $policy, int $limit = 500): CleanupResult;
}
