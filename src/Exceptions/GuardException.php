<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Exceptions;

/** Expected domain failures commit intentional revocations and rate counters. */
final class GuardException extends \RuntimeException
{
    public function __construct(
        public readonly FailureReason $reason,
        string $message,
        public readonly int $retryAfterSeconds = 0
    ) {
        parent::__construct($message);
    }
}
