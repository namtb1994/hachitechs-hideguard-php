<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Contracts;

interface SessionCounterContract
{
    /** Explicit repair, inside an exclusive scope mutation. */
    public function reconcileSessionCount(string $scopeId): int;
}
