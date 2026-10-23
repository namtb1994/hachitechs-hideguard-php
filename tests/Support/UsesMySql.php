<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Tests\Support;

use Hachitechs\HideguardPhp\Contracts\StorageContract;
use Hachitechs\HideguardPhp\Storage\PdoMySqlStorage;

trait UsesMySql
{
    protected ?MySqlFixture $databaseFixture = null;

    protected function createStorage(): StorageContract
    {
        if (!getenv('HG_TEST_MYSQL_DSN')) {
            self::markTestSkipped('Set HG_TEST_MYSQL_DSN/USER/PASSWORD to run MySQL integration.');
        }
        $this->databaseFixture = new MySqlFixture();
        return new PdoMySqlStorage($this->databaseFixture->pdo, $this->databaseFixture->prefix);
    }

    protected function tearDown(): void
    {
        $this->databaseFixture?->dispose();
        parent::tearDown();
    }
}
