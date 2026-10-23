<?php

declare(strict_types=1);

use Hachitechs\HideguardPhp\Access\AccessContext;
use Hachitechs\HideguardPhp\Access\ResourceRef;
use Hachitechs\HideguardPhp\Configuration\ProtectionPolicy;
use Hachitechs\HideguardPhp\Guard;

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
if ($decision->status !== 'allowed' || in_array('--block', $argv, true)) {
    // Simulates an SDK payload only in development; no real HideGuard verification is claimed.
    $decision = $guard->report($context, $policy, [
        'verdict' => in_array('--block', $argv, true) ? 'block' : 'allow',
        'visitorId' => 'demo_visitor',
    ], $decision->verificationId);
}
if ($decision->status === 'allowed') {
    $guard->bindGrant($context, $policy, $resource);
    $guard->assertResourceAllowed($context->scopeId, $policy, $resource);
    // Perform the protected application operation here, then consume its grant after success.
    $guard->consumeGrant($context->scopeId, $resource);
}
echo json_encode($decision->toBrowserArray(), JSON_THROW_ON_ERROR) . "\n";
