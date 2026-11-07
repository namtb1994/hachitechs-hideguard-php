<?php

declare(strict_types=1);

use Hachitechs\HideguardPhp\Access\{AccessContext, ResourceRef};
use Hachitechs\HideguardPhp\Configuration\{ProtectionPolicy, RateLimits, CircuitBreakerPolicy};
use Hachitechs\HideguardPhp\Exceptions\{GuardException, FailureReason, ApiException};
use Hachitechs\HideguardPhp\Guard;
use Hachitechs\HideguardPhp\Storage\{PdoMySqlStorage, PdoCircuitBreakerStore};
use Hachitechs\HideguardPhp\Tests\Support\{MySqlFixture, FrozenClock};

require dirname(__DIR__, 2) . '/vendor/autoload.php';
[$script, $prefix, $mode, $id, $directory] = $argv;
$pdo = MySqlFixture::connect();
$storage = new PdoMySqlStorage($pdo, $prefix);
$guard = Guard::factory()->withStorage($storage)->withClock(new FrozenClock())->make();
$circuit = new PdoCircuitBreakerStore($pdo, $prefix . 'circuit');
file_put_contents($directory . '/' . $id, 'ready');
$deadline = microtime(true) + 20;
while (!is_file($directory . '/go')) {
    if (microtime(true) > $deadline) {
        throw new RuntimeException('Barrier timeout.');
    }
    usleep(10000);
}
try {
    if ($mode === 'probe') {
        $circuit->acquire(hash('sha256', 'shared'), 1030, new CircuitBreakerPolicy(threshold: 2));
    } elseif ($mode === 'capacity') {
        $guard->preflight(
            new AccessContext('concurrency', 'worker-' . $id),
            new ProtectionPolicy(enabled: true, publicKey: 'key', limits: new RateLimits(sessionCapacity: 2))
        );
    } elseif ($mode === 'bind') {
        $guard->bindGrant(
            new AccessContext('concurrency', 'worker-' . $id),
            new ProtectionPolicy(enabled: true, publicKey: 'key'),
            new ResourceRef('quote', '99')
        );
    } else {
        throw new RuntimeException('Unknown fixture operation.');
    }
    echo '1';
} catch (ApiException $error) {
    if ($mode !== 'probe' || $error->statusCode !== 503) {
        throw $error;
    }
    echo '0';
} catch (GuardException $error) {
    if ($mode !== 'capacity' || $error->reason !== FailureReason::CapacityReached) {
        throw $error;
    }
    echo '0';
}
