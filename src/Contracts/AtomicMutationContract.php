<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Contracts;

interface AtomicMutationContract
{
    /**
     * Serialize the whole scope on the storage connection. Commit GuardException
     * security mutations; rollback all other failures. Reject unsupported nesting.
     *
     * @template T
     * @param callable(): T $work
     * @return T
     */
    public function run(string $scopeId, callable $work): mixed;
}
