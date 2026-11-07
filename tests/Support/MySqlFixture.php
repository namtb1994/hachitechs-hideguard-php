<?php

declare(strict_types=1);

namespace Hachitechs\HideguardPhp\Tests\Support;

use Hachitechs\HideguardPhp\Storage\PdoMySqlStorage;
use PDO;

/** Creates only randomly named test tables. Never points at an application's guard tables. */
final class MySqlFixture
{
    public readonly string $prefix;
    public readonly PDO $pdo;

    public function __construct()
    {
        $this->prefix = 'hg_test_' . bin2hex(random_bytes(6)) . '_';
        $this->pdo = self::connect();
        (new PdoMySqlStorage($this->pdo, $this->prefix))->initializeSchema();
    }

    public static function connect(): PDO
    {
        return new PDO(
            (string)getenv('HG_TEST_MYSQL_DSN'),
            (string)getenv('HG_TEST_MYSQL_USER'),
            (string)getenv('HG_TEST_MYSQL_PASSWORD'),
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
        );
    }

    public function dispose(): void
    {
        foreach (['session', 'block', 'rate', 'control'] as $suffix) {
            $this->pdo->exec('DROP TABLE `' . $this->prefix . $suffix . '`');
        }
    }
}
