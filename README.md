# HideGuard PHP SDK for Bot Protection and Checkout Access Control

PHP SDK for [HideGuard](https://hideguard.io/) bot protection, signed verdict
verification, and checkout access control. Fetch bot verification results from
your backend, verify Ed25519-signed browser responses, and enforce access grants
for checkout workflows, forms, and protected pages.

The `hachitechs/hideguard-php` Composer package supports PHP **8.1+** and works
without a framework. Integrate it into plain PHP applications, Magento modules,
Laravel middleware, WordPress plugins, or Symfony services.

[Composer package](https://packagist.org/packages/hachitechs/hideguard-php) ·
[Release notes](https://github.com/namtb1994/hachitechs-hideguard-php/releases)

## Features

- **Bot verification API:** retrieve visitor verdicts through an authenticated
  server-side HTTP client.
- **Signed verdict verification:** validate HideGuard collect v2 responses with
  Ed25519 public keys, environment matching, and freshness checks.
- **Checkout and form protection:** bind access grants to resources selected by
  your application and check them before protected operations.
- **Access lifecycle:** manage verification attempts, timed passes, blocks,
  retries, and grant expiry.
- **Persistent storage:** use the supplied MySQL adapter with atomic mutations,
  configurable rate limits, session capacity, and batch cleanup.
- **Browser integration:** use prebuilt ESM or AMD assets for interaction locking
  and backend-confirmed access decisions.

## Installation

Install the latest stable release from Packagist with Composer:

```sh
composer require hachitechs/hideguard-php
```

### Requirements

| Requirement | Used for |
| --- | --- |
| PHP 8.1+ | All package functionality |
| `ext-curl` | Default `VerdictClient` HTTP transport |
| `ext-sodium` | Ed25519 signature verification |
| `ext-pdo_mysql` and MySQL 8.0/InnoDB | Supplied persistent storage adapter |

Composer installs `psr/clock` and `psr/log` as production dependencies. Extensions
are needed only for the features listed above; custom HTTP and storage adapters
can replace the supplied implementations.

## Quick start: fetch a bot verdict

Use `VerdictClient` when your application needs a HideGuard verdict without the
access-control lifecycle or a database. Supply your API key from server-side
configuration and the visitor ID associated with the request.

```php
use Hachitechs\HideguardPhp\VerdictClient;

require_once __DIR__ . '/vendor/autoload.php';

$client = new VerdictClient(
    baseUrl: 'https://hideguard.io',
    apiKey: $apiKeyFromServerConfiguration
);

$response = $client->getVerdict($visitorId);
```

The client sends `POST /api/v1/verdict` with an `x-api-key` header and a
`{"visitorId":"..."}` JSON body. Successful JSON objects or lists are returned as
PHP arrays, including nested data. Keep the API key on the server.

HTTP errors, redirects, network failures, oversized responses, and invalid JSON
throw `Exceptions\ApiException`. Its `statusCode` is available when an HTTP status
was received. Invalid configuration or visitor IDs throw
`Exceptions\GuardException`. Decide how your application handles these failures
before allowing a protected operation.

The default cURL transport verifies TLS, uses a 3-second connection timeout and a
10-second total timeout, and limits responses to 64 KiB. It does not follow
redirects or automatically retry requests. To customize timeouts:

```php
use Hachitechs\HideguardPhp\Http\CurlTransport;

$client = new VerdictClient(
    baseUrl: 'https://hideguard.io',
    apiKey: $apiKeyFromServerConfiguration,
    transport: new CurlTransport(timeoutSeconds: 15, connectTimeoutSeconds: 5)
);
```

For a response just received by this authenticated client,
[`PrivateVerdictChecker`](src/Verification/PrivateVerdictChecker.php) validates the
response schema and matches the expected visitor ID. It is not a signature
verifier and must not be used to trust browser-supplied payloads.

## Checkout and form access control

Use `Guard` to manage verification attempts and persistent access grants.
Configure an Ed25519 public key for your HideGuard site and environment, and
provide persistent storage. All classes use the `Hachitechs\HideguardPhp` namespace.

### 1. Configure the guard

The example uses an application-managed, dedicated, non-persistent PDO
connection. Initialize its schema once during deployment with
`$storage->initializeSchema()`, before serving requests.

```php
use Hachitechs\HideguardPhp\Access\AccessContext;
use Hachitechs\HideguardPhp\Access\ResourceRef;
use Hachitechs\HideguardPhp\Configuration\ProtectionPolicy;
use Hachitechs\HideguardPhp\Guard;
use Hachitechs\HideguardPhp\Storage\PdoMySqlStorage;
use Hachitechs\HideguardPhp\Verification\Ed25519Verifier;

require_once __DIR__ . '/vendor/autoload.php';

$storage = new PdoMySqlStorage($pdo);
$guard = Guard::factory()
    ->withStorage($storage)
    ->withVerifier(new Ed25519Verifier())
    ->make();

$policy = new ProtectionPolicy(
    enabled: true,
    environment: 'production',
    publicKey: $sdkSiteKey,
    signaturePublicKey: $siteEd25519PemPublicKey
);

$context = new AccessContext(
    'site-id',
    $serverManagedBrowserId,
    $authenticatedUserId
);
```

Use server-managed values for the scope, browser identity, authenticated user,
and resource ownership. The actor ID can be `null` for guests.

### 2. Start verification before rendering

```php
$decision = $guard->preflight($context, $policy);
$browserState = $decision->toBrowserArray();
```

When the status is `verification_required`, pass the browser state to your
frontend integration and start the SDK check. The serialized state includes the
`verificationId` and a `verificationUntil` deadline in milliseconds. Enforce
blocked or failed decisions on the server; pending verification must not allow
protected operations.

An existing timed pass is reused until expiry. The default verification timeout
is 35 seconds and can be configured from 5 to 120 seconds with
`ProtectionPolicy::verificationTimeout`.

### 3. Verify the browser response

In a separate CSRF-protected callback, rebuild the same trusted context and
policy, then pass the signed SDK payload and the attempt ID to `report()`:

```php
$decision = $guard->report(
    $context,
    $policy,
    $sdkPayload,
    $verificationIdFromRequest
);

if ($decision->status === 'allowed') {
    $resource = new ResourceRef('checkout', $serverSelectedCheckoutId, $authenticatedUserId);
    $guard->bindGrant($context, $policy, $resource);
}
```

The attempt ID is the **fourth argument**, separate from the signed payload.
Invalid or expired verdicts do not grant access. For an SDK or network failure,
call `failVerification($context, $policy, $verificationId)` for the current
attempt. Start a retry with `preflight($context, $policy, retry: true)` only after
an explicit, CSRF-protected user action.

### 4. Check the protected operation

In your checkout or form submission endpoint, reconstruct the resource from
trusted server state and validate its grant before executing the operation:

```php
$resource = new ResourceRef('checkout', $serverSelectedCheckoutId, $authenticatedUserId);
$guard->assertResourceAllowed($context->scopeId, $policy, $resource);

// Execute the protected application operation here.
// Consume the grant only after the operation succeeds.
$guard->consumeGrant($context->scopeId, $resource);
```

The application owns routing, sessions, CSRF protection, business authorization,
and HTTP responses. A browser interaction lock complements these server checks;
it cannot replace them. See the [plain PHP web example](examples/plain-php/web/README.md)
for a complete request flow.

## Environments and signature verification

`ProtectionPolicy` selects the default endpoint from its environment:

| Environment | Default endpoint |
| --- | --- |
| `development` | `https://dev.hideguard.io` |
| `production` | `https://hideguard.io` |

Use `ProtectionPolicy::defaultEndpointUrl($environment)` to share the same origin
across your backend client and frontend configuration. An explicit HTTPS
`endpointUrl` is also supported. `VerdictClient` always requires a `baseUrl`.

`Ed25519Verifier` requires the Ed25519 PEM public key issued for the active site
and environment. It validates signed fields, signature encoding, environment,
and freshness. Configure it explicitly: the default `UnavailableVerifier` fails
closed. `DevelopmentVerifier` accepts unsigned demo payloads and is for local
development only.

Verification attempt IDs correlate callbacks; they are not included in the
HideGuard signature. Signed responses and expiry checks do not provide
cryptographic single-use or browser-session binding. Keep identity and resource
selection under server control.

## Framework integration

The SDK has no Magento, Laravel, WordPress, or Symfony dependency. Require the
Composer package in your application and call its services from the integration
points your framework provides:

| Application | Integration approach |
| --- | --- |
| Plain PHP | Load `vendor/autoload.php`; wire sessions, routes, and callbacks in your application. |
| Magento | Construct the client or guard through a module service, factory, or dependency injection. |
| Laravel | Register services in the container and enforce decisions in middleware or controllers. |
| WordPress | Load the Composer autoloader from your plugin bootstrap and call the SDK from plugin hooks. |
| Symfony | Configure services and enforce access through controllers or request listeners. |

To use a framework HTTP client, implement
[`Contracts\HttpTransport`](src/Contracts/HttpTransport.php) and inject it into
`VerdictClient`. The adapter must enforce TLS verification, finite timeouts,
response-size limits, and no redirects or automatic retries; transport failures
should throw `ApiException`.

## Storage and advanced configuration

[`PdoMySqlStorage`](src/Storage/PdoMySqlStorage.php) provides persistent sessions,
blocks, resource grants, and rate accounting with atomic mutations. Run schema
initialization during deployment, outside web requests and business transactions.
For another backend, implement [`StorageContract`](src/Contracts/StorageContract.php)
and [`AtomicMutationContract`](src/Contracts/AtomicMutationContract.php).

Configure [`RateLimits`](src/Configuration/RateLimits.php) through
`ProtectionPolicy::limits`. Defaults are 600 scope admissions and 60 identity
admissions per 60 seconds, 10,000 sessions per scope, and 30 days of inactive
session retention. For scheduled cleanup, use `supportsBatchCleanup()` and
`cleanupBatch($scopeId, $policy, $limit)` when the storage supports batching.

[`CircuitBreakingTransport`](src/Http/CircuitBreakingTransport.php) optionally
wraps the HTTP transport with a shared circuit breaker. Its
[`PdoCircuitBreakerStore`](src/Storage/PdoCircuitBreakerStore.php) needs a separate
PDO connection and explicit schema initialization. Configure thresholds and
recovery timing with [`CircuitBreakerPolicy`](src/Configuration/CircuitBreakerPolicy.php);
the probe lease must exceed the wrapped HTTP timeout.

Inject a PSR-20 clock or PSR-3 logger through `Guard::factory()->withClock()` or
`withLogger()` when your application needs custom time or logging services.

## Browser runtime and examples

Prebuilt browser assets are in [`browser/dist`](browser/dist): ESM and AMD
modules, LESS, and generated style exports. The runtime starts verification when
needed and waits for a backend-confirmed result before unlocking interactions.
Pass the policy's `endpointUrl` into the browser configuration.

The [web demo](examples/plain-php/web/README.md) demonstrates sessions, CSRF,
protected pages, and resource grants. The [CLI demo](examples/plain-php/demo.php)
demonstrates persistent access decisions. Both use `DevelopmentVerifier` and
must be adapted to use Ed25519 verification for production.

For the CLI demo, set `HG_MYSQL_DSN`, `HG_MYSQL_USER`, `HG_MYSQL_PASSWORD`, and
optionally `HG_TABLE_PREFIX`, using a dedicated demo database:

```sh
php examples/plain-php/init.php
php examples/plain-php/demo.php
php examples/plain-php/demo.php --block
```

## Development and testing

From a source checkout:

```sh
composer install
composer validate --strict
composer lint
composer analyse
composer test
```

Set `HG_TEST_MYSQL_DSN`, `HG_TEST_MYSQL_USER`, and `HG_TEST_MYSQL_PASSWORD` to run
MySQL integration tests; otherwise they are skipped. Use a dedicated test
database, as tests create and drop randomly named `hg_test_*` tables.

To build and check browser assets, run from `browser/`:

```sh
npm ci --ignore-scripts
npm run build
npm run check
npm test
```

The [GitHub Actions workflow](.github/workflows/tests.yml) runs PHP 8.1–8.5 checks
with MySQL and a separate Node 22 browser job.

## License

Proprietary, as declared in [`composer.json`](composer.json).
