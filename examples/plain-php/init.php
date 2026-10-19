<?php

declare(strict_types=1);

use Hachitech\Antidetect\Storage\PdoMySqlStorage;

$app = require __DIR__ . '/bootstrap.php';
/** @var PdoMySqlStorage $storage */
$storage = $app['storage'];
$storage->initializeSchema();
echo "Created the example storage tables.\n";
