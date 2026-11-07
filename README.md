# hachitechs/hideguard-php

Framework-independent access protection for PHP **8.1+**. Production dependencies
are only PHP, `psr/clock` and `psr/log`. No Magento, Laravel, WordPress, Symfony,
container, framework HTTP client or ORM is required. Optional supplied adapters
use cURL, Sodium or PDO MySQL as described below.

## Version and installation

**1.0.0 is the first stable distribution.** This source includes the traffic/storage
capabilities and two-mode endpoint defaults used by the matching Magento module.
Publish the `v1.0.0` Git tag before installing it through VCS. Composer derives the
version from that tag; no hardcoded `version` field is needed in the library
manifest. Preparing these files does not itself commit, tag or publish a release.

Configure the private VCS repository in the application's root `composer.json`:

```json
{
    "type": "vcs",
    "url": "https://github.com/namtb1994/hachitechs-hideguard-php.git",
    "only": ["hachitechs/hideguard-php"]
}
```

After the matching release is available, run from the application root:

```sh
composer require hachitechs/hideguard-php:^1.0
```

Keep repository credentials outside committed files. Composer uses repositories
from the root project, not those declared by a dependency. Commit the application
lockfile for reproducible installations. Installation does not initialize database
tables, intercept routes or publish browser assets.

For local development **before release**, use an explicit path repository and a
local development alias in the application root:

```json
{
    "repositories": [{
        "type": "path",
        "url": "../hachitechs-hideguard-php",
        "options": {
            "symlink": true,
            "versions": {"hachitechs/hideguard-php": "dev-master"}
        }
    }],
    "require": {"hachitechs/hideguard-php": "dev-master as 1.0.0"}
}
```

Adjust the path to your checkout and keep existing root repositories/requirements.
The alias satisfies a module's `^1.0` constraint for local work; it does not create
a release, include uncommitted files in a remote tag or prove remote availability.
Do not use a development alias as a substitute for a production release.

To work on this package itself, run `composer install` from its source checkout.
Its test and browser build dependencies are development-only.

## PHP namespace

All package classes use the `Hachitechs\HideguardPhp` namespace. When upgrading,
update application imports and fully qualified class names from
`Hachitech\Antidetect` to `Hachitechs\HideguardPhp`, then regenerate the Composer
autoloader with `composer dump-autoload`.

## Call the verdict API from any PHP application

`VerdictClient` needs only the base URL, server-side API key and visitor ID. It
does not require Guard, database storage, a session or a framework bootstrap.

```php
use Hachitechs\HideguardPhp\Exceptions\ApiException;
use Hachitechs\HideguardPhp\VerdictClient;

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
and uses a 3-second connect timeout and 10-second total timeout. Downloaded and
decompressed bodies are limited to 64 KiB; the client checks this limit before
JSON parsing even with a custom transport. Both constructors accept a positive
`maxResponseBytes` argument. To change the timeouts:

```php
$client = new VerdictClient($baseUrl, $apiKey, new \Hachitechs\HideguardPhp\Http\CurlTransport(
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
`Hachitechs\HideguardPhp\Contracts\HttpTransport::post()` and pass it as the third
constructor argument. It receives the URL, header map and JSON string, and returns
`Http\HttpResponse($statusCode, $body)`. Enforce TLS verification, finite timeouts,
no redirects and no automatic retries; translate transport failures to
`ApiException`. The library handles HTTP status validation and JSON decoding.
No Magento/WordPress HTTP dependency is added to the package.

This method fetches a verdict only. It does not change Guard grants, blocks or
signature verification; the application chooses how to use the returned data.

For a response just received from this private client, use
`Verification\PrivateVerdictChecker::check($response, $expectedVisitorId)` to
validate its schema and match the visitor selected by trusted server state.
It accepts `allow`, `challenge` and `block`, validates scores/reason codes, and
returns `VerifiedVerdict` using a PSR clock. It is not a signature verifier and
must never be used to trust payloads supplied by a browser.

HideGuard validates the registered domain and SDK public key, plus the secret
API key for private backend requests. Signed collect responses are checked with
the trusted signature public key, environment and freshness policy.

## Environment endpoint defaults

`ProtectionPolicy::ENVIRONMENTS` offers two modes: `development` (Testing) and
`production`. Omitting `endpointUrl` selects `https://dev.hideguard.io` for Testing
and `https://hideguard.io` for Production. Use
`ProtectionPolicy::defaultEndpointUrl($environment)` when an adapter needs the
same host for its SDK, CSP and backend verdict client. `DEFAULT_ENDPOINT_URL`
remains the production-origin constant; it is not the default for every mode.

An explicitly supplied HTTPS `endpointUrl` remains supported for PHP applications
that require another origin. The package has no framework or deployment-config
dependency. Existing adapters may still construct a policy with legacy `staging`
(defaults to the testing host); new UI should offer only the two supported modes.
Signature verification rules are unchanged. Existing grants tied to a different
endpoint have a different policy fingerprint and require verification again;
active blocks keep their deadlines. The standalone VerdictClient still takes an
explicit baseUrl; pass the policy endpoint to share its mode selection.

## Use from plain PHP

```php
use Hachitechs\HideguardPhp\Access\AccessContext;
use Hachitechs\HideguardPhp\Access\ResourceRef;
use Hachitechs\HideguardPhp\Configuration\ProtectionPolicy;
use Hachitechs\HideguardPhp\Guard;
use Hachitechs\HideguardPhp\Storage\PdoMySqlStorage;
use Hachitechs\HideguardPhp\Verification\Ed25519Verifier;

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
apply its additive upgrade, never during a web request. Framework adapters own their schema migrations; the Magento adapter uses
declarative schema instead of the standalone initializer.

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
deadlines do not provide single-use or browser-session binding. See `src/Verification/Ed25519Verifier.php` and the verification tests for the
supported payload, per-site key assumption and replay limits.

## Traffic, storage and optional capabilities

Default `RateLimits` are 600 scope admissions and 60 identity admissions per
60-second window, 10,000 stored sessions per scope and 30 days of inactive-session
retention. Identity is the authenticated actor when available, otherwise the
server-owned browser identity. These are policy parameters rather than framework
configuration. Applications can pass a `RateLimits` instance to `ProtectionPolicy`.

`preflight` still accounts for each rate admission while coalescing unchanged
last-seen writes for `min(60, retention)` seconds. New verification state,
revocations, blocks, grants and resource bindings are persisted immediately.
An active persisted block can return without creating repeated browser rows.

`PdoMySqlStorage` provides MySQL 8/InnoDB storage and atomic mutations on one
dedicated, non-persistent PDO connection. `initializeSchema()` creates/additively
upgrades `session`, `block`, `rate` and `control` tables under the supplied prefix.
Run it explicitly during setup, never inside a web request or business transaction.
Counters update transactionally. Run explicit `reconcileSessionCount($scopeId)`
repairs inside `$storage->run($scopeId, ...)` under the exclusive scope fence;
do not delete stored sessions to reset capacity.

The optional capabilities are:

| Contract / implementation | Purpose |
| --- | --- |
| `PartitionedAtomicMutationContract` / `MySqlCoordinator` | Browser/resource work may use narrower locks under a shared scope fence; report/revocation/maintenance retain exclusive fencing. Shared quotas and capacity still require atomic admission. |
| `SessionCounterContract` / `MySqlControl` | Maintain capacity counts transactionally instead of recounting the entire session table on each admission. |
| `BatchCleanupContract` / `BatchGuardContract` | Bound cleanup work and expose `CleanupResult::hasMore` so a scheduler can choose its work budget. |
| `CircuitBreakerStoreContract` / `CircuitBreakingTransport` | Shared upstream failure state, single recovery probe, no automatic retry or cached Allow fallback. |

Existing adapters implementing only the base storage/atomic contracts keep the
conservative whole-scope fallback. Custom adapters must preserve serialization,
resource transfer, quota/capacity and commit/rollback contracts. Domain-denial
security mutations must commit; infrastructure failures roll back. Unsupported
nested/external transactions are rejected by the supplied MySQL coordinator.

For bounded scheduled cleanup, check `supportsBatchCleanup()` and call
`cleanupBatch($scopeId, $policy, $limit)` repeatedly within your scheduler budget.
With batch support, `Guard::cleanup()` attempts at most ten batches of 500 rows.
Low-level `PdoMySqlStorage::cleanup()` drains its batches, so schedulers needing a
strict row budget should use the batch API. Adapters without batch support retain
their existing cleanup contract.
Active grant/block state remains protected from inactivity cleanup.

The circuit decorator is opt-in for PHP applications. `CircuitBreakerPolicy`
defaults to threshold 5, failure window 60 seconds, open duration 30 seconds and
probe lease 15 seconds. The lease must exceed the wrapped HTTP total timeout.
`PdoCircuitBreakerStore` has its own explicit `initializeSchema()`; use a connection
separate from the Guard and business transactions. Framework adapters decide
whether and how to enable the decorator. The Magento module fixes it on; the PHP
core does not read Magento configuration or force it on other applications.

## Browser runtime and examples

`browser/src` contains the shared runtime and interaction lock. `browser/dist`
contains ready-to-use ESM, AMD, LESS and generated style exports. The runtime starts
the HideGuard SDK when needed, reports through adapter-provided endpoints and
waits for a backend-confirmed decision before unlocking interactions. Supply the
policy's `endpointUrl`; a caller omitting browser configuration must not assume
that the JavaScript fallback selects its PHP environment automatically.

The application owns identity, CSRF, HTTP endpoints, page selection, denial mapping
and business authorization. Browser code cannot replace a server-side action
check. A server-only `VerdictClient` consumer does not need browser assets.

Build from a source checkout when changing the shared runtime:

```sh
cd browser
npm ci --ignore-scripts
npm run build
npm run check
npm test
```

Publish/check the prebuilt AMD and LESS files into an existing Magento module:

```sh
node browser/publish-magento.mjs /path/to/module-hideguard
node browser/publish-magento.mjs /path/to/module-hideguard --check
```

Run these publish commands from the package root. Node/esbuild/LESS are development
build tools, not PHP or browser-runtime dependencies. Source/build scripts may be
excluded from distribution archives; prebuilt `browser/dist` remains available.
Do not edit generated AMD/ESM bundles independently of their source.

`examples/plain-php` demonstrates native PHP CLI and web integration. It is not
loaded by Composer's production autoloader and Magento does not execute it. The
CLI demo simulates verdicts; the [web example](examples/plain-php/web/README.md)
shows local sessions, CSRF, protected pages and resource-bound forms. These demos
explicitly use `DevelopmentVerifier` and are not production signature verification
examples. Use the Ed25519 integration shown above for production browser reports.

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

The workflow in `.github/workflows/tests.yml` configures PHP 8.1/8.2 and MySQL
checks plus a separate Node 22 browser job when run in this package repository.
It is not a workflow of a parent Magento checkout, and its presence is not evidence
that a particular remote run passed. Local runtime verification has used PHP 8.5;
production capacity, a full PHP-version matrix and real payment E2E are not inferred
from those checks.
