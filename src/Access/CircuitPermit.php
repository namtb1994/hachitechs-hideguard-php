<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Access;

final class CircuitPermit
{
    public function __construct(public readonly int $generation, public readonly ?string $probeToken = null)
    {
    }
}
