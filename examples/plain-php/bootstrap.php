<?php

declare(strict_types=1);

use Hachitechs\HideguardPhp\Configuration\ProtectionPolicy;
use Hachitechs\HideguardPhp\Guard;
use Hachitechs\HideguardPhp\Storage\PdoMySqlStorage;
use Hachitechs\HideguardPhp\Verification\DevelopmentVerifier;

require dirname(__DIR__, 2) . '/vendor/autoload.php';

if (PHP_SAPI !== 'cli') {
    throw new RuntimeException('This demonstration is a CLI example.');
}
$dsn = getenv('HG_MYSQL_DSN');
if (!$dsn) {
    throw new RuntimeException('Set HG_MYSQL_DSN, HG_MYSQL_USER and HG_MYSQL_PASSWORD.');
}
$pdo = new PDO($dsn, (string)getenv('HG_MYSQL_USER'), (string)getenv('HG_MYSQL_PASSWORD'));
$storage = new PdoMySqlStorage($pdo, (string)(getenv('HG_TABLE_PREFIX') ?: 'hideguard_'));
$guard = Guard::factory()->withStorage($storage)->withVerifier(new DevelopmentVerifier())->make();
$policy = new ProtectionPolicy(enabled: true, publicKey: 'development-demo', accessPoints: ['form.submit']);

return ['guard' => $guard, 'policy' => $policy, 'storage' => $storage];
