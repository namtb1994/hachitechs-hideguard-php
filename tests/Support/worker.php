<?php

declare(strict_types=1);

use Hachitech\Antidetect\Access\AccessContext;
use Hachitech\Antidetect\Configuration\ProtectionPolicy;
use Hachitech\Antidetect\Exceptions\FailureReason;
use Hachitech\Antidetect\Exceptions\GuardException;
use Hachitech\Antidetect\Guard;
use Hachitech\Antidetect\Storage\PdoMySqlStorage;
use Hachitech\Antidetect\Tests\Support\FrozenClock;
use Hachitech\Antidetect\Tests\Support\MySqlFixture;
use Hachitech\Antidetect\Verification\DevelopmentVerifier;

require dirname(__DIR__, 2) . '/vendor/autoload.php';

$storage = new PdoMySqlStorage(MySqlFixture::connect(), $argv[1]);
$guard = Guard::factory()->withStorage($storage)->withClock(new FrozenClock())
    ->withVerifier(new DevelopmentVerifier())->make();
$policy = new ProtectionPolicy(enabled: true, publicKey: 'key');
$mode = $argv[2];
$context = new AccessContext('concurrency', $mode === 'rate' ? 'worker-' . $argv[3] : 'reports', 'shared');
$attempt = $mode === 'rate' ? null : $guard->preflight($context, $policy);
$accepted = 0;
$limited = 0;
for ($i = 0; $i < 25; $i++) {
    try {
        if ($mode === 'rate') {
            $guard->preflight($context, $policy);
        } else {
            $guard->report(
                $context,
                $policy,
                ['verdict' => $mode, 'visitorId' => 'visitor'],
                $attempt?->verificationId
            );
        }
        $accepted++;
    } catch (GuardException $error) {
        if ($error->reason !== FailureReason::RateLimited) {
            throw $error;
        }
        $limited++;
    }
}
echo json_encode(['accepted' => $accepted, 'limited' => $limited], JSON_THROW_ON_ERROR);
