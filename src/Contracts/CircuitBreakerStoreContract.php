<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Contracts;

use Hachitechs\HideguardPhp\Access\CircuitPermit;
use Hachitechs\HideguardPhp\Configuration\CircuitBreakerPolicy;

interface CircuitBreakerStoreContract
{
    /** Denied/Open raises ApiException; never hold its DB transaction during HTTP. */
    public function acquire(string $key, int $now, CircuitBreakerPolicy $policy): CircuitPermit;
    public function record(
        string $key,
        CircuitPermit $permit,
        bool $failed,
        int $now,
        CircuitBreakerPolicy $policy
    ): void;
}
