<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Access;

final class CleanupResult
{
    public function __construct(
        public readonly int $blocks,
        public readonly int $rates,
        public readonly int $sessions,
        public readonly bool $hasMore
    ) {
    }
    public function total(): int
    {
        return $this->blocks + $this->rates + $this->sessions;
    }
}
