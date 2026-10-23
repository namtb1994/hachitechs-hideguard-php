<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Tests\Contract;

use Hachitechs\HideguardPhp\Contracts\StorageContract;
use Hachitechs\HideguardPhp\Tests\Support\MemoryStorage;
use Hachitechs\HideguardPhp\Tests\Support\StorageBehavior;

final class MemoryStorageTest extends StorageBehavior
{
    protected function createStorage(): StorageContract
    {
        return new MemoryStorage();
    }
}
