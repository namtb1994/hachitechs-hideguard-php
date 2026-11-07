<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Contracts;

use Hachitechs\HideguardPhp\Access\ResourceRef;

/**
 * Optional capability; run() fences both methods exclusively for the entire scope.
 * Preserve run() commit/rollback semantics. Browser work must serialize its browser,
 * the supplied resource AND the browser's persisted binding, including transfers.
 * Resource work must serialize the same (scope,type,id) key as browser work.
 * Shared quota/capacity admission must remain atomic in the storage implementation.
 */
interface PartitionedAtomicMutationContract extends AtomicMutationContract
{
    /**
     * @template T
     * @param callable(): T $work
     * @return T
     */
    public function runBrowser(string $scopeId, string $browserId, ?ResourceRef $resource, callable $work): mixed;
    /**
     * @template T
     * @param callable(): T $work
     * @return T
     */
    public function runResource(string $scopeId, ResourceRef $resource, callable $work): mixed;
}
