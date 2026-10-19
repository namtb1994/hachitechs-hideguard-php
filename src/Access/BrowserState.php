<?php

declare(strict_types=1);

namespace Hachitech\Antidetect\Access;

/** Storage record. Adapters must return detached instances and persist changes explicitly. */
final class BrowserState
{
    public function __construct(
        public readonly string $browserId,
        public ?string $actorId = null,
        public ?string $visitorId = null,
        public int $blockedUntil = 0,
        public int $grantedUntil = 0,
        public ?string $policyHash = null,
        public ?ResourceRef $resource = null,
        public int $lastSeen = 0,
        public string $verification = '',
        public ?string $verificationId = null,
        public int $verificationUntil = 0
    ) {
    }

    public function revoke(): void
    {
        $this->grantedUntil = 0;
        $this->resource = null;
    }
}
