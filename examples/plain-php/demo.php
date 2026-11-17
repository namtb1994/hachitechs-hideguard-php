<?php

declare(strict_types=1);

use Hachitechs\HideguardPhp\Access\AccessContext;
use Hachitechs\HideguardPhp\Access\ResourceRef;
use Hachitechs\HideguardPhp\Configuration\ProtectionPolicy;
use Hachitechs\HideguardPhp\Guard;

if ($argc !== 2) {
    throw new InvalidArgumentException('Usage: php examples/plain-php/demo.php signed-verdict.json');
}
$app = require __DIR__ . '/bootstrap.php';
/** @var Guard $guard */
$guard = $app['guard'];
/** @var ProtectionPolicy $policy */
$policy = $app['policy'];
// Fixed server-selected identities for this demo, not IDs supplied by a web client.
$context = new AccessContext('plain-php-demo', 'demo-browser', 'demo-user');
$resource = new ResourceRef('form', 'demo-submission', 'demo-user');
$decision = $guard->preflight($context, $policy, true);
if ($decision->status === 'blocked') {
    echo json_encode($decision->toBrowserArray(), JSON_THROW_ON_ERROR) . "\n";
    return;
}
if ($decision->status !== 'allowed') {
    $json = file_get_contents($argv[1], false, null, 0, 65537);
    if ($json === false || strlen($json) > 65536) {
        throw new InvalidArgumentException('Supply a signed verdict JSON file of at most 64 KiB.');
    }
    $payload = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
    if (!is_array($payload)) {
        throw new InvalidArgumentException('The signed verdict must be a JSON object.');
    }
    $decision = $guard->report($context, $policy, $payload, $decision->verificationId);
}
if ($decision->status === 'allowed') {
    $guard->bindGrant($context, $policy, $resource);
    $guard->assertResourceAllowed($context->scopeId, $policy, $resource);
    // Perform the protected application operation here, then consume its grant after success.
    $guard->consumeGrant($context->scopeId, $resource);
}
echo json_encode($decision->toBrowserArray(), JSON_THROW_ON_ERROR) . "\n";
