# hachitech/antidetect-php

Framework independent access-control core for HideGuard, PHP **8.1+**. This local
package is extracted from `Hachitech_AntidetectBrowser`.
It has not been published to a Composer registry.

Production dependencies are only PHP, `psr/clock` and `psr/log`. No Magento,
WordPress, Laravel, Symfony, container, third-party HTTP client or ORM is required.
The optional server-side verdict client uses `ext-curl` by default, or an injected
HTTP transport supplied by the application.
The shared browser runtime ships as prebuilt ESM/AMD. The Magento module now
uses this core through native adapters. A separate
[WordPress plugin](../antidetect-wordpress/README.md) and
[Laravel example](../antidetect-laravel-example/README.md) demonstrate native
integration without adding platform dependencies to the core.

## Install for development

From this package directory:

```bash
composer install
```

For an application's Composer project, add a local path repository pointing at
this directory, pin its development version, and require the library:

```json
{
    "repositories": [{
        "type": "path",
        "url": "/absolute/path/to/packages/antidetect-php",
        "options": {"versions": {"hachitech/antidetect-php": "0.1.0"}}
    }],
    "require": {"hachitech/antidetect-php": "^0.1"}
}
```

Use the eventual registry/repository release instead of this path configuration
when distributing adapters. Installation does not initialize tables or assets.

## Call the verdict API from any PHP application

`VerdictClient` needs only the base URL, server-side API key and visitor ID. It
does not require Guard, database storage, a session or a framework bootstrap.

```php
use Hachitech\Antidetect\Exceptions\ApiException;
use Hachitech\Antidetect\VerdictClient;

require_once __DIR__ . '/vendor/autoload.php';

$client = new VerdictClient(
    baseUrl: 'https://dev.hideguard.io',
    apiKey: $apiKeyFromServerConfiguration
);

try {
    $response = $client->getVerdict('a313d75f78dc6dabb6e5138cbf341fe4');
    // $response is the entire API response as an associative PHP array.
    // Nested JSON objects are arrays too; no response fields are discarded.
} catch (ApiException $error) {
    // null for transport failures; the HTTP status for HTTP/response failures.
    $httpStatus = $error->statusCode;
    // Let the application decide how to handle an unavailable verdict.
}
```

Each call sends `POST {baseUrl}/api/v1/verdict` with `x-api-key`,
`Content-Type: application/json`, `Accept: application/json` and
`{"visitorId":"..."}`. Supply an HTTPS origin, optionally with a port/root slash;
do not include `/api/v1/verdict` in `baseUrl`. Keep the API key in server-side
configuration. The visitor ID is an opaque, non-empty UTF-8 string without
control characters. Invalid URL/key/visitor arguments throw `GuardException`.

Successful 2xx JSON objects/lists become PHP arrays. Invalid JSON, scalar/empty
responses, HTTP errors, redirects and network failures throw `ApiException`.
Large JSON integers outside PHP's integer range remain strings. The default
transport verifies TLS, supports gzip/deflate, does not follow redirects or retry,
and uses a 3-second connect timeout and 10-second total timeout. To change them:

```php
$client = new VerdictClient($baseUrl, $apiKey, new \Hachitech\Antidetect\Http\CurlTransport(
    timeoutSeconds: 15,
    connectTimeoutSeconds: 5
));
```

Use the same client in a **Magento module** after requiring this package in the
Magento Composer project. Construct it in the module's service/factory with
values from the module's server-side configuration, or configure those constructor
arguments through Magento DI, then call `getVerdict($visitorId)` in that service.

For a **WordPress plugin**, require this package in the plugin's Composer project,
load its `vendor/autoload.php` once from the plugin bootstrap, then use the same
constructor and method in the plugin's PHP code. Both platforms can use the
default cURL transport directly.

If a platform must use its own HTTP client, implement
`Hachitech\Antidetect\Contracts\HttpTransport::post()` and pass it as the third
constructor argument. It receives the URL, header map and JSON string, and returns
`Http\HttpResponse($statusCode, $body)`. Enforce TLS verification, finite timeouts,
no redirects and no automatic retries; translate transport failures to
`ApiException`. The library handles HTTP status validation and JSON decoding.
No Magento/WordPress HTTP dependency is added to the package.

This method fetches a verdict only. It does not change Guard grants, blocks or
signature verification; the application chooses how to use the returned data.

## Use from plain PHP

```php
use Hachitech\Antidetect\Access\AccessContext;
use Hachitech\Antidetect\Access\ResourceRef;
use Hachitech\Antidetect\Configuration\ProtectionPolicy;
use Hachitech\Antidetect\Guard;
use Hachitech\Antidetect\Storage\PdoMySqlStorage;
use Hachitech\Antidetect\Verification\Ed25519Verifier;

require __DIR__ . '/vendor/autoload.php';

// MySQL 8.0/InnoDB; use a dedicated non-persistent connection.
$storage = new PdoMySqlStorage($pdo);
// Explicit setup only: $storage->initializeSchema();
$guard = Guard::factory()
    ->withStorage($storage)
    ->withVerifier(new Ed25519Verifier()) // Requires ext-sodium.
    ->make();

$policy = new ProtectionPolicy(
    enabled: true,
    environment: 'production',
    publicKey: 'your-sdk-site-key',
    signaturePublicKey: $siteEd25519PemPublicKey,
    endpointUrl: 'https://hideguard.io'
);
$context = new AccessContext('site-id', $serverManagedBrowserId, $authenticatedUserId);
$decision = $guard->preflight($context, $policy);

// Run preflight BEFORE rendering a protected page, even if JavaScript may be disabled.
// Send its verificationId/verificationUntil to the browser, then receive an SDK verdict.
// Submit a payload only when a fresh check is required; skip SDK for active blocks.
$decision = $guard->report($context, $policy, $sdkPayload, $verificationIdFromRequest);

if ($decision->status === 'allowed') {
    $resource = new ResourceRef('form', $serverSelectedFormId, $authenticatedUserId);
    $guard->bindGrant($context, $policy, $resource);
    $guard->assertResourceAllowed($context->scopeId, $policy, $resource);
    // Perform the protected operation. Consume only after success.
    $guard->consumeGrant($context->scopeId, $resource);
}
```

Pass nullable actor IDs for guests and strings for authenticated users, including
UUIDs. The application selects routes/rules, manages identity/CSRF and enforces
the returned decision. The package does not automatically intercept PHP pages.

Run the persistent CLI demo with connection settings supplied through
`HG_MYSQL_DSN`, `HG_MYSQL_USER`, `HG_MYSQL_PASSWORD` and optional `HG_TABLE_PREFIX`:

```bash
php examples/plain-php/init.php
php examples/plain-php/demo.php
php examples/plain-php/demo.php --block
```

Use a dedicated demo database/prefix. The demo simulates unsigned verdicts; it
does not contact HideGuard. Re-running after Block preserves its original
deadline. See [the web example](examples/plain-php/web/README.md) for native session/CSRF,
protected pages and backend actions with the shared runtime.

## Verification lifecycle (framework independent)

`preflight(context, policy, retry: false)` starts a server-owned attempt before
protected HTML is sent. It returns `verification_required`, a random
`verificationId` and a fixed deadline (`verificationUntil` in browser milliseconds).
The default wait is 35 seconds; PHP callers may set `verificationTimeout` to 5–120
seconds. Repeated preflight/reload calls reuse an unfinished attempt and cannot
extend its deadline. `inspect` remains read-only for business requests/cache checks.

While pending, an application may render its public page with a transparent
interaction lock, but must deny protected operations. A cached timed pass is
reused until its original expiry. In Always mode, preflight revokes the previous
browser/resource grant before starting another attempt.

Forward the attempt ID as the **fourth argument** to `report`, separately from the
signed SDK payload. Reports require a started, current attempt. A valid Allow
grants access, Block creates the configured timed ban, and an invalid verdict
revokes permission and fails the attempt. The client cannot choose server browser,
actor, scope or resource identity. A mismatched old attempt cannot change the
current grant. An expired/completed attempt cannot renew an expired pass.

`failVerification(context, policy, verificationId)` records an SDK/network failure
only for the matching unfinished attempt. It cannot revoke a completed grant or
create a timed visitor ban. The server independently derives `verification_failed`
after the deadline, even if no client notification arrives. Only an explicit,
CSRF-protected retry should call `preflight(..., retry: true)` after failure.
Use HTTP 401 for a confirmed active block, 403 for failed/unverified access, and
503 for infrastructure unavailability. HTTP mapping belongs to the adapter.

Storage adapters must persist the appended `BrowserState::verificationId` and
`verificationUntil` fields (SQL: nullable `verification_id` CHAR(32) and
`verification_until` unsigned integer default 0). Existing custom adapters need
an explicit schema upgrade. Run PDO `initializeSchema()` during deployment to
apply its additive upgrade, never during a web request. Magento uses declarative
schema; WordPress uses its activation/setup `dbDelta`.

This protocol needs no framework, router, PHP session implementation, HTTP library
or database engine. WordPress hooks, Laravel middleware and plain PHP routing
own those concerns. Implement the storage/atomic contracts for another backend;
PDO/MySQL is an optional supplied adapter, not a core requirement.

The attempt ID correlates browser callbacks; it is **not part of HideGuard's
signature** and does not add cryptographic single-use or cross-browser replay
protection. A new browser session also has its own preview window. Public HTML
already sent cannot be revoked; keep sensitive data/operations behind server checks.
A browser that disables all JavaScript cannot be forced to navigate, but subsequent
protected requests can still be denied by the server.

## Extension points and verification

Implement `StorageContract` and `AtomicMutationContract` using your application's
storage, on the same connection. A default storage is never selected implicitly.
Inject a PSR-20 clock or PSR-3 logger through the factory, or use the explicit
Guard constructor. Memory storage exists only under `tests/Support`.

Use `Ed25519Verifier` with the Ed25519 PEM public key issued for the active site
and environment. It verifies HideGuard collect v2 signed fields, timestamp and
canonical signature encoding using `ext-sodium`; PHP core remains independent
of every framework. Inject the same PSR clock into Guard and verifier when overriding time.

Without a supplied verifier, reports fail closed using `UnavailableVerifier`.
`DevelopmentVerifier` remains an explicit unsigned demo option and refuses
staging/production. Magento uses Ed25519 verification in every environment.
The current signed response has no browser/actor nonce: signatures and bounded
deadlines do not provide single-use or browser-session binding. See the contract
for the supported payload, per-site key assumption and replay limits.

See [the API/storage/verification contract](docs/CONTRACT.md),
[browser integration/build guide](docs/BROWSER.md) and
[extraction progress](docs/PROGRESS.md). Factories, injectable contracts and typed
results follow the design approach of [openai-php/client](https://github.com/openai-php/client).

## Checks

```bash
composer test
composer analyse
composer lint
composer validate --strict
```

Set `HG_TEST_MYSQL_DSN`, `HG_TEST_MYSQL_USER` and `HG_TEST_MYSQL_PASSWORD` to
include MySQL tests. Otherwise those tests are explicitly skipped. Integration
creates/drops only randomly named `hg_test_*` tables and tests real process
concurrency; never point it at application guard table names.

The workflow under `.github/workflows` runs when this directory is extracted
into its own repository. It does not register a workflow in the enclosing
Magento repository. Local results and limitations are recorded in PROGRESS.md.
