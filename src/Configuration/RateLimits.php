<?php

declare(strict_types=1);

namespace Hachitech\Antidetect\Configuration;

use Hachitech\Antidetect\Exceptions\FailureReason;
use Hachitech\Antidetect\Exceptions\GuardException;

final class RateLimits
{
    public function __construct(
        public readonly int $scopeRequests = 600,
        public readonly int $identityRequests = 60,
        public readonly int $windowSeconds = 60,
        public readonly int $sessionCapacity = 10000,
        public readonly int $sessionRetentionSeconds = 2592000
    ) {
        foreach (get_object_vars($this) as $value) {
            if ($value < 1) {
                throw new GuardException(FailureReason::InvalidConfiguration, 'Limits must be positive integers.');
            }
        }
    }
}
