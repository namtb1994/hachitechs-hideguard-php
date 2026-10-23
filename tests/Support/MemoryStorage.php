<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Tests\Support;

use Hachitechs\HideguardPhp\Access\BrowserState;
use Hachitechs\HideguardPhp\Access\RateWindow;
use Hachitechs\HideguardPhp\Access\ResourceRef;
use Hachitechs\HideguardPhp\Contracts\AtomicMutationContract;
use Hachitechs\HideguardPhp\Contracts\StorageContract;
use Hachitechs\HideguardPhp\Exceptions\GuardException;

/** Test fixture only. This implementation cannot protect concurrent application processes. */
final class MemoryStorage implements StorageContract, AtomicMutationContract
{
    public int $sessionWrites = 0;

    /** @var array<string, array<string, BrowserState>> */
    private array $sessions = [];
    /** @var array<string, array<string, int>> */
    private array $blocks = [];
    /** @var array<string, array<string, RateWindow>> */
    private array $rates = [];
    private bool $running = false;

    public function run(string $scopeId, callable $work): mixed
    {
        if ($this->running) {
            throw new \LogicException('Nested mutations are unsupported.');
        }
        $sessions = [];
        foreach ($this->sessions as $scope => $states) {
            $sessions[$scope] = array_map(fn(BrowserState $state) => clone $state, $states);
        }
        $blocks = $this->blocks;
        $rates = $this->rates;
        $this->running = true;
        try {
            return $work();
        } catch (GuardException $error) {
            throw $error;
        } catch (\Throwable $error) {
            $this->sessions = $sessions;
            $this->blocks = $blocks;
            $this->rates = $rates;
            throw $error;
        } finally {
            $this->running = false;
        }
    }

    public function session(string $scopeId, string $browserId): ?BrowserState
    {
        $state = $this->sessions[$scopeId][$browserId] ?? null;
        return $state !== null ? clone $state : null;
    }

    public function saveSession(string $scopeId, BrowserState $state): void
    {
        $this->sessionWrites++;
        $this->sessions[$scopeId][$state->browserId] = clone $state;
    }

    public function sessionCount(string $scopeId): int
    {
        return count($this->sessions[$scopeId] ?? []);
    }

    public function blockExpiry(string $scopeId, ?string $visitorId, ?string $actorId): int
    {
        $expiry = 0;
        foreach ($this->identities($visitorId, $actorId) as $identity) {
            $expiry = max($expiry, $this->blocks[$scopeId][$identity] ?? 0);
        }
        return $expiry;
    }

    public function block(string $scopeId, string $visitorId, ?string $actorId, int $until): void
    {
        foreach ($this->identities($visitorId, $actorId) as $identity) {
            $this->blocks[$scopeId][$identity] = $until;
        }
    }

    public function revokeIdentity(string $scopeId, ?string $visitorId, ?string $actorId): void
    {
        foreach ($this->sessions[$scopeId] ?? [] as $state) {
            if (
                ($visitorId !== null && $state->visitorId === $visitorId)
                || ($actorId !== null && $state->actorId === $actorId)
            ) {
                $state->revoke();
            }
        }
    }

    public function bindResource(string $scopeId, string $browserId, ResourceRef $resource): void
    {
        foreach ($this->sessions[$scopeId] ?? [] as $state) {
            if ($state->resource?->type === $resource->type && $state->resource->id === $resource->id) {
                $state->resource = null;
            }
        }
        if (isset($this->sessions[$scopeId][$browserId])) {
            $this->sessions[$scopeId][$browserId]->resource = $resource;
        }
    }

    public function resource(string $scopeId, ResourceRef $resource): ?BrowserState
    {
        foreach ($this->sessions[$scopeId] ?? [] as $state) {
            if ($state->resource?->type === $resource->type && $state->resource->id === $resource->id) {
                return clone $state;
            }
        }
        return null;
    }

    public function revokeResource(string $scopeId, ResourceRef $resource): void
    {
        foreach ($this->sessions[$scopeId] ?? [] as $state) {
            if ($state->resource?->type === $resource->type && $state->resource->id === $resource->id) {
                $state->revoke();
            }
        }
    }

    public function revokeScope(string $scopeId): void
    {
        foreach ($this->sessions[$scopeId] ?? [] as $state) {
            $state->revoke();
        }
    }

    public function resetBlocks(string $scopeId): int
    {
        $count = count($this->blocks[$scopeId] ?? []);
        unset($this->blocks[$scopeId]);
        foreach ($this->sessions[$scopeId] ?? [] as $state) {
            $state->blockedUntil = 0;
        }
        return $count;
    }

    public function rate(string $scopeId, string $bucketHash): ?RateWindow
    {
        return $this->rates[$scopeId][$bucketHash] ?? null;
    }

    public function saveRate(string $scopeId, string $bucketHash, RateWindow $window): void
    {
        $this->rates[$scopeId][$bucketHash] = $window;
    }

    public function cleanup(string $scopeId, int $now, int $inactiveBefore): void
    {
        foreach ($this->sessions[$scopeId] ?? [] as $browser => $state) {
            if ($state->lastSeen < $inactiveBefore && $state->blockedUntil <= $now && $state->grantedUntil <= $now) {
                unset($this->sessions[$scopeId][$browser]);
            }
        }
        foreach ($this->blocks[$scopeId] ?? [] as $identity => $until) {
            if ($until <= $now) {
                unset($this->blocks[$scopeId][$identity]);
            }
        }
        foreach ($this->rates[$scopeId] ?? [] as $hash => $window) {
            if ($window->expiresAt <= $now) {
                unset($this->rates[$scopeId][$hash]);
            }
        }
    }

    /** @return list<string> */
    private function identities(?string $visitorId, ?string $actorId): array
    {
        $ids = [];
        if ($visitorId !== null) {
            $ids[] = 'visitor:' . $visitorId;
        }
        if ($actorId !== null) {
            $ids[] = 'actor:' . $actorId;
        }
        return $ids;
    }
}
