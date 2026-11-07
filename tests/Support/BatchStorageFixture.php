<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Tests\Support;

use Hachitechs\HideguardPhp\Contracts\StorageContract;
use Hachitechs\HideguardPhp\Contracts\BatchCleanupContract;

abstract class BatchStorageFixture implements StorageContract, BatchCleanupContract
{
}
