<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Tests\Support;

use Psr\Clock\ClockInterface;

final class FrozenClock implements ClockInterface
{
    public function __construct(public int $timestamp = 1000)
    {
    }

    public function now(): \DateTimeImmutable
    {
        return new \DateTimeImmutable('@' . $this->timestamp);
    }
}
