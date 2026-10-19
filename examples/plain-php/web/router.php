<?php

declare(strict_types=1);

use Hachitech\Antidetect\Access\AccessContext;
use Hachitech\Antidetect\Access\ResourceRef;
use Hachitech\Antidetect\Configuration\ProtectionPolicy;
use Hachitech\Antidetect\Exceptions\FailureReason;
use Hachitech\Antidetect\Exceptions\GuardException;
use Hachitech\Antidetect\Guard;
use Hachitech\Antidetect\Rules\PathMatcher;
use Hachitech\Antidetect\Storage\PdoMySqlStorage;
use Hachitech\Antidetect\Verification\DevelopmentVerifier;

// This example owns HTTP, sessions, CSRF and routing. None of these belong to core.
if (PHP_SAPI !== 'cli-server') {
    throw new RuntimeException('Run this development example with PHP -S on localhost.');
}
$host = parse_url('http://' . ($_SERVER['HTTP_HOST'] ?? ''), PHP_URL_HOST);
if (!in_array($host, ['localhost', '127.0.0.1', '[::1]'], true)) {
    http_response_code(400);
    exit('Use localhost for this development example.');
}
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
if ($path === '/runtime.js') {
    header('Content-Type: text/javascript; charset=UTF-8');
    readfile(dirname(__DIR__, 3) . '/browser/dist/runtime.js');
    return;
}
require dirname(__DIR__, 3) . '/vendor/autoload.php';
header('Cache-Control: private, no-store, max-age=0');
session_start(['cookie_httponly' => true, 'cookie_samesite' => 'Strict', 'use_strict_mode' => true]);
$_SESSION['browser'] ??= bin2hex(random_bytes(32));
$_SESSION['csrf'] ??= bin2hex(random_bytes(32));

/** @param array<string,mixed> $data */
$reply = static function (array $data, int $status = 200): never {
    http_response_code($status);
    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode($data, JSON_THROW_ON_ERROR);
    exit;
};

try {
    $dsn = getenv('HG_MYSQL_DSN');
    if (!$dsn) {
        throw new RuntimeException('Set the HG_MYSQL connection variables.');
    }
    $storage = new PdoMySqlStorage(
        new PDO($dsn, (string)getenv('HG_MYSQL_USER'), (string)getenv('HG_MYSQL_PASSWORD')),
        (string)(getenv('HG_TABLE_PREFIX') ?: 'hideguard_')
    );
    $policy = new ProtectionPolicy(enabled: true, publicKey: (string)(getenv('HG_SITE_KEY') ?: 'development-demo'));
    $guard = Guard::factory()->withStorage($storage)->withVerifier(new DevelopmentVerifier())->make();
    $context = new AccessContext('plain-web-demo', $_SESSION['browser']);
    $resource = new ResourceRef('submission', $_SESSION['browser']);
    $isEndpoint = in_array($path, ['/access', '/verdict', '/fail', '/submit'], true);
    if ($isEndpoint) {
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
            header('Allow: POST');
            $reply(['error' => 'Use POST.'], 405);
        }
        if (
            (int)($_SERVER['CONTENT_LENGTH'] ?? 0) > 65536
            || strlen((string)file_get_contents('php://input', false, null, 0, 65537)) > 65536
        ) {
            $reply(['error' => 'Request body is too large.'], 413);
        }
        if (!is_string($_POST['csrf'] ?? null) || !hash_equals($_SESSION['csrf'], $_POST['csrf'])) {
            $reply(['error' => 'Invalid CSRF token.'], 400);
        }
        $decision = $guard->inspect($context, $policy);
        if ($decision->status === 'blocked') {
            header('Retry-After: ' . max(1, $decision->retryAfterSeconds));
            $reply($decision->toBrowserArray(), 401);
        }
        if ($path === '/submit') {
            $guard->assertResourceAllowed($context->scopeId, $policy, $resource);
            // A sample application operation; resource identity is chosen by the server.
            $_SESSION['submissions'] = ($_SESSION['submissions'] ?? 0) + 1;
            $guard->consumeGrant($context->scopeId, $resource);
            $reply(['submitted' => $_SESSION['submissions']]);
        }
        $verificationId = is_string($_POST['verificationId'] ?? null) ? $_POST['verificationId'] : '';
        $responsePayload = $_POST['response'] ?? null;
        $payload = $responsePayload === null ? $_POST
            : (is_string($responsePayload) && strlen($responsePayload) <= 16384
                ? json_decode($responsePayload, true, 16) : null);
        $decision = match ($path) {
            '/verdict' => $guard->report($context, $policy, is_array($payload) ? $payload : [], $verificationId),
            '/fail' => $guard->failVerification($context, $policy, $verificationId),
            default => $guard->preflight($context, $policy, ($_POST['retry'] ?? '') === '1'),
        };
        if ($decision->status === 'allowed') {
            $guard->bindGrant($context, $policy, $resource);
        }
        if ($decision->status === 'blocked') {
            header('Retry-After: ' . max(1, $decision->retryAfterSeconds));
        }
        $reply($decision->toBrowserArray(), match ($decision->status) {
            'blocked' => 401, 'verification_failed' => 403, default => 200,
        });
    }
    if (!in_array($path, ['/', '/protected', '/gate'], true) || ($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') {
        $reply(['error' => 'Page not found.'], 404);
    }
    $protected = (new PathMatcher())->matches($path, ['protected']);
    $decision = $protected ? $guard->preflight($context, $policy) : $guard->inspect($context, $policy);
    if ($protected && $decision->status === 'verification_failed') {
        header('Location: /gate?failed=1', true, 302);
        exit;
    }
    $gate = $path === '/gate';
    $blocked = ($protected || $gate) && $decision->status === 'blocked';
    $failed = $gate && $decision->status !== 'allowed' && !$blocked
        && ($decision->status === 'verification_failed' || ($_GET['failed'] ?? '') === '1');
    if ($blocked) {
        http_response_code(401);
        header('Retry-After: ' . max(1, $decision->retryAfterSeconds));
    }
    if ($failed) {
        http_response_code(403);
    }
    $config = [
        'enabled' => true, 'pageProtected' => $protected, 'page' => $gate ? 'gate' : '',
        'initialState' => $blocked ? 'blocked' : ($failed ? 'error' : 'pending'), 'publicKey' => $policy->publicKey,
        'accessUrl' => '/access', 'verdictUrl' => '/verdict', 'csrfToken' => $_SESSION['csrf'],
        'verificationId' => $decision->verificationId, 'failUrl' => '/fail',
        'gateUrl' => '/gate', 'deniedUrl' => '/gate?failed=1', 'returnUrl' => '/protected',
    ];
} catch (GuardException $error) {
    if ($error->retryAfterSeconds > 0) {
        header('Retry-After: ' . $error->retryAfterSeconds);
    }
    $reply(['error' => $error->getMessage()], match ($error->reason) {
        FailureReason::PermissionDenied => 403,
        FailureReason::RateLimited => 429,
        FailureReason::VerificationUnavailable => 501,
        FailureReason::Busy, FailureReason::CapacityReached => 503,
        default => 400,
    });
} catch (Throwable) {
    $reply(['error' => 'Unable to verify access. Check the example configuration.'], 503);
}
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>HideGuard plain PHP example</title></head>
<body <?= $protected || $gate ? 'inert data-hachitech-ab-inert' : '' ?>>
<?php if ($blocked || $gate) : ?>
<section id="hachitech-ab-gate" class="hachitech-ab-gate"
         data-page="<?= $gate ? 'gate' : '' ?>"
         data-state="<?= $blocked ? 'blocked' : ($failed ? 'error' : 'pending') ?>">
    <div class="hachitech-ab-message">
    <h2><?= $blocked ? 'Access temporarily blocked' : 'Unable to verify access' ?></h2>
    <p role="status">Please try again.</p>
    <button type="button" class="hachitech-ab-retry" data-action="retry">Try again</button>
    </div>
</section>
<?php else : ?>
<h1><?= $protected ? 'Protected example content' : 'Public example page' ?></h1>
<p>This demo uses unsigned development verdicts. Use a real development site key for the SDK.</p>
<a href="/">Public page</a> <a href="/protected">Protected page</a>
<form action="/submit" method="post">
    <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf'], ENT_QUOTES, 'UTF-8') ?>">
    <button type="submit">Perform protected operation</button>
</form>
<?php endif; ?>
<script type="module">
import {initialize, styleText} from '/runtime.js';
const config = <?= json_encode($config, JSON_THROW_ON_ERROR | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_QUOT) ?>;
const style = document.createElement('style');
style.textContent = styleText;
document.head.appendChild(style);
initialize(config, {
    prepareBody: data => data.set('csrf', config.csrfToken),
    isProtectedAction: (target, path) => path === '/submit'
});
</script>
</body>
</html>
