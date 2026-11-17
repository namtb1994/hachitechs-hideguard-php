<?php

declare(strict_types=1);

use Hachitechs\HideguardPhp\Access\AccessContext;
use Hachitechs\HideguardPhp\Configuration\ProtectionPolicy;
use Hachitechs\HideguardPhp\Exceptions\FailureReason;
use Hachitechs\HideguardPhp\Exceptions\GuardException;
use Hachitechs\HideguardPhp\Guard;
use Hachitechs\HideguardPhp\Storage\PdoMySqlStorage;
use Hachitechs\HideguardPhp\Tests\Support\FrozenClock;
use Hachitechs\HideguardPhp\Tests\Support\MySqlFixture;
use Hachitechs\HideguardPhp\Verification\DevelopmentVerifier;

require dirname(__DIR__, 2) . '/vendor/autoload.php';

$storage = new PdoMySqlStorage(MySqlFixture::connect(), $argv[1]);
$guard = Guard::factory()->withStorage($storage)->withClock(new FrozenClock())
    ->withVerifier(new DevelopmentVerifier())->make();
$policy = new ProtectionPolicy(enabled: true, environment: 'development', publicKey: 'key');
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
