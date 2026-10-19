<?php

declare(strict_types=1);

namespace Hachitech\Antidetect\Access;

final class RateWindow
{
    public function __construct(public readonly int $requests, public readonly int $expiresAt)
    {
    }
}
