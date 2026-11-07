<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Contracts;

use Hachitechs\HideguardPhp\Access\CleanupResult;

/** Called inside an exclusive scope mutation. Limit is total rows, not rows per table. */
interface BatchCleanupContract
{
    public function cleanupBatch(string $scopeId, int $now, int $inactiveBefore, int $limit): CleanupResult;
}
