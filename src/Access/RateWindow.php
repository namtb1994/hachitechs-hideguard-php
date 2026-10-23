<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Access;

final class RateWindow
{
    public function __construct(public readonly int $requests, public readonly int $expiresAt)
    {
    }
}
