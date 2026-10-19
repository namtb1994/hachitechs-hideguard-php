<?php

declare(strict_types=1);

namespace Hachitech\Antidetect\Tests\Contract;

use Hachitech\Antidetect\Contracts\StorageContract;
use Hachitech\Antidetect\Tests\Support\MemoryStorage;
use Hachitech\Antidetect\Tests\Support\StorageBehavior;

final class MemoryStorageTest extends StorageBehavior
{
    protected function createStorage(): StorageContract
    {
        return new MemoryStorage();
    }
}
