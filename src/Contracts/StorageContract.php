<?php

declare(strict_types=1);

namespace Hachitech\Antidetect\Contracts;

use Hachitech\Antidetect\Access\BrowserState;
use Hachitech\Antidetect\Access\RateWindow;
use Hachitech\Antidetect\Access\ResourceRef;

/** Writes occur inside AtomicMutationContract::run on the same connection. */
interface StorageContract
{
    public function session(string $scopeId, string $browserId): ?BrowserState;
    public function saveSession(string $scopeId, BrowserState $state): void;
    public function sessionCount(string $scopeId): int;
    public function blockExpiry(string $scopeId, ?string $visitorId, ?string $actorId): int;
    public function block(string $scopeId, string $visitorId, ?string $actorId, int $until): void;
    public function revokeIdentity(string $scopeId, ?string $visitorId, ?string $actorId): void;

    /** Bind one resource per browser, transferring that resource from any previous browser. */
    public function bindResource(string $scopeId, string $browserId, ResourceRef $resource): void;
    public function resource(string $scopeId, ResourceRef $resource): ?BrowserState;
    public function revokeResource(string $scopeId, ResourceRef $resource): void;
    public function revokeScope(string $scopeId): void;

    /** Clear blocks, retaining fields unrelated to blocking; return persisted block row count. */
    public function resetBlocks(string $scopeId): int;
    public function rate(string $scopeId, string $bucketHash): ?RateWindow;
    public function saveRate(string $scopeId, string $bucketHash, RateWindow $window): void;
    public function cleanup(string $scopeId, int $now, int $inactiveBefore): void;
}
