<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Configuration;

final class CircuitBreakerPolicy
{
    public function __construct(
        public readonly int $threshold = 5,
        public readonly int $windowSeconds = 60,
        public readonly int $openSeconds = 30,
        public readonly int $probeLeaseSeconds = 15
    ) {
        foreach (get_object_vars($this) as $value) {
            if ($value < 1 || $value > 86400) {
                throw new \InvalidArgumentException('Circuit settings must be 1..86400.');
            }
        }
    }
}
