# PHP core contract

The package supports PHP 8.1 syntax and has no platform lifecycle. Construction
and autoloading do not create tables, start sessions, emit HTTP responses or
contact HideGuard. Configuration, identity and storage come from the application.

## API and units

| Operation | Contract |
| --- | --- |
| `inspect(context, policy)` | Read-only decision before render/cache; no session allocation or rate counter writes |
| `preflight(context, policy, retry = false)` | Start/reuse a fixed-deadline attempt before render; reuse timed passes, revoke Always grants; no verifier invocation |
| `report(context, policy, payload, verificationId)` | Atomic verification and grant/block mutation; existing active blocks skip verification and rate consumption |
| `bindGrant(context, policy, resource)` | Requires an unexpired matching grant, no block, and identical trusted actor ownership |
| `assertResourceAllowed(scopeId, policy, resource)` | Reads the bound grant and checks owner, scope, policy, expiry and block; works for backend/headless actions |
| `consumeGrant(scopeId, resource)` | Revoke after the protected operation succeeds |
| `revokeScope(scopeId)` | Revoke grants and bindings while retaining block state |
| `resetBlocks(scopeId)` | Clear persisted identity/session blocks in that scope; unrelated grants are retained |
| `cleanup(scopeId, policy)` | Remove expired block/rate records and stale sessions without deleting active grants/blocks |

Domain deadlines are Unix **seconds**, from an injected PSR-20 clock.
`AccessDecision::toBrowserArray()` converts deadline/retry values to milliseconds
and preserves the existing browser protocol: `verification_required`, `allowed`,
`blocked`, `verification_failed`. It contains no session secrets, internal actor IDs or verification keys.
The `disabled` decision is for inspection; preflight/report on a disabled policy
reject with `FailureReason::Disabled`.

The application chooses protected pages/actions before calling Guard. Arbitrary
business point names are supported, such as `document.download` or `form.submit`.
`PathMatcher` supports `*`, strips query strings and preserves case and `+`.
Bracket and question-mark characters in rules are literals, unlike `fnmatch`.
Platform route/SEO normalization stays in its adapter.

## Identity and ownership

Scope, browser and actor IDs are opaque, case-sensitive strings of 1–128 bytes;
NUL is rejected. Actor `null` means guest. String `"0"` is a valid authenticated
ID and must not be treated as guest. Never derive actor/resource ownership from
untrusted request parameters. Store browser identity on the server and keep it
stable when the platform regenerates its session ID.

`BrowserState::actorId` is the actor who earned its grant, not necessarily the
current logged-in actor. Changing actor invalidates that grant. A block discovered
for an actor is recorded in the current browser during preflight/report, so logout
does not clear a block already recorded there. Clearing anonymous browser state
can remove its identity link; this package does not implement an IP ban.

One browser has one bound resource in this first version, matching the existing
Magento quote model. Binding a resource to a new browser clears its old binding;
resource type and ID identify it within a scope. Multiple-resource grants would
require a new, explicit storage contract and migration.

## Policy and grant lifetime

Policies are typed, validated and immutable. A canonical fingerprint includes
active environment keys, access points, page rules, durations and rate/storage
limits. Reordering the same rules does not invalidate a grant. Migrating from the
old Magento or pre-signature fingerprint requires re-verification of passes; block deadlines must
be preserved by the Magento storage adapter.

`ProtectionPolicy::endpointUrl` selects the HideGuard HTTPS origin, defaulting to
`https://hideguard.io`. It accepts an optional port and root slash, normalizes host
case and port 443, and rejects paths, credentials, queries, fragments and URLs over
2048 bytes. PHP accepts ASCII hosts (use punycode for international domain names).
Changing this origin invalidates existing passes through the policy fingerprint.
Supply the same `endpointUrl` to the browser initializer: it loads `/sdk/v1.js`
from that origin and sets `data-endpoint` so SDK requests use it too. PHP performs
local response verification; it does not send an HTTP request to this URL.

Pass interval presets are 0/60/300/900/3600 seconds; default **300**. Interval 0
means a fresh SDK check on every protected page load, with a 300-second grant for
the current page's protected actions. PHP preflight revokes that action grant when a new check begins; business requests
use `inspect`/resource assertions rather than starting another preflight. Expiry and repeated accepted Allow
responses do not slide the deadline of the same valid grant.

Block presets are 900/3600/21600/86400 seconds. A Block report revokes related
grants and resource bindings. An active session/visitor/actor block wins over
later Allow, malformed or duplicate reports. Expiry is checked on requests,
independently of cleanup. Default limits are 600/scope and 60/browser-or-actor
per fixed 60-second window, 10,000 sessions/scope and 30-day inactivity retention.

## Storage and atomic mutation

`StorageContract` is persistence only. `AtomicMutationContract` must serialize
the scope and use the same transaction connection as storage. Inject both
explicitly, or supply a storage object implementing both. Returned state must
be detached; mutations are persisted only through storage methods.

All writes performed by Guard run in an atomic mutation. A `GuardException`
commits intentional security changes, including invalid-verdict revocation and
consumed rate counters. Other exceptions roll back partial state. Custom adapters
must not wrap infrastructure failures in GuardException, which would commit them.
Nested mutation is rejected in the PDO implementation. The caller must treat all
failures as a refusal to issue new permission.

Rejection logging runs after the atomic mutation has committed and released its
lock. Logging is best effort: logger failure cannot restore a revoked grant or
replace the original domain rejection. Payloads, keys and identity secrets are
not logged.

The initial PDO driver targets **MySQL 8.0/InnoDB**. A dedicated non-persistent
PDO connection is required; do not reuse a checkout/business transaction.
Named locks include database/prefix/scope and are released explicitly after the
transaction. MySQL locks are connection scoped and survive transaction commit;
see [MySQL locking functions](https://dev.mysql.com/doc/refman/8.0/en/locking-functions.html).

Run `initializeSchema()` explicitly during setup, never in a request or inside a
transaction. MySQL DDL can implicitly commit; see [PDO transactions](https://www.php.net/manual/en/pdo.begintransaction.php).
The application owns migration/versioning and must use the driver's InnoDB schema.
Binary ID columns preserve exact bytes and resource binding has a unique index.
The PDO schema is independent of Magento; its adapter retains the existing
Magento tables rather than creating these tables beside them.

## Verification and HTTP boundaries

The default `UnavailableVerifier` always rejects new reports. This lets an
application inspect/enforce persisted blocks without installing a permissive
verifier. `DevelopmentVerifier` requires explicit injection and rejects staging
and production. Unsigned development payloads are forgeable; local verdict groups
still apply, according to the configured verdict groups.

`Ed25519Verifier` implements the collect v2 format from the Shopify source
`extensions/storefront-payment/assets/hideguard-signature.js`, checked against
its real HideGuard response and independent Node.js signing vectors. It accepts
an SDK response array containing `signature`, `siteId`, `environment`, `requestId`,
`visitorId`, `verdict`, integer `score`, and a list of `reasons` objects with `code`.
Only reason codes are signed; description/heartbeat fields are ignored. It uses
PHP's [Ed25519 detached verifier](https://www.php.net/manual/en/function.sodium-crypto-sign-verify-detached.php)
with `ext-sodium`. Missing crypto support refuses verification.

The exact header is `v=2,alg=ed25519,kid=TOKEN,t=TIMESTAMP,sig=BASE64URL`.
The signature covers these UTF-8 lines, joined by LF with no trailing LF:

```text
hideguard-collect-ed25519-v2
alg=ed25519
kid=<header kid>
t=<header timestamp>
site=<siteId>
environment=<environment>
request=<requestId>
visitor=<visitorId>
verdict=<verdict>
score=<integer>
reasons=<compact JSON array of reason codes>
```

Tokens start with an ASCII letter/digit, followed by letters/digits/`._:-`,
maximum 128 bytes. Header timestamp is a positive canonical integer of up to
12 digits; signature is canonical unpadded base64url encoding of 64 bytes.
Score is 0–9007199254740991, and at most 64 reason codes are accepted. The
header plus canonical message is limited to 12288 bytes. The PEM must contain
an Ed25519 SPKI key (44 DER bytes with the standard 12-byte prefix).

The configured public key is assumed to belong to exactly one HideGuard site,
as in the Shopify implementation; site ID is signed, but this version has no
separate configured site-ID allowlist. Environment must match the active policy.
`VerdictPolicy::BLOCK_VERDICTS`, `CHALLENGE_VERDICTS` and `ALLOW_VERDICTS`
define the three groups; `groupFor()` uses strict membership. Validation and
Guard decisions share these groups. The local groups are deliberately configurable through these constants.
The Ed25519 verifier normalizes a signed verdict outside the block group to Allow;
a raw unresolved Challenge returned by a custom verifier is rejected outside
development. The signature contract matches Shopify. A valid signature authenticates a verdict before these groups determine
access; it does not override a block rule or implement a CAPTCHA.

Fresh reports allow at most 30 seconds of future clock skew and must be younger
than `grantSeconds()` (Always uses 300 seconds). A fresh Block must also be younger
than its configured block duration. An active stored block skips verification,
so signature expiry cannot shorten its persisted deadline. A new block deadline
starts at the signed timestamp, capped at server time; a pass deadline is capped
at signed timestamp plus grant lifetime. Repeated accepted responses do not
slide the same grant or ban. Expired signatures cannot restart their original
period. Policy fingerprint v2 invalidates passes created before this rollout
while retaining existing block deadlines; no schema migration is required.

Request ID is authenticated but not consumed in a replay store. The signed
format contains no server challenge/nonce or browser/actor identity. Reuse in
another browser within the freshness window remains possible; native CSRF and
server-selected quote ownership do not add a cryptographic binding to the SDK
request. Single-use/session binding requires an upstream signed field and an
explicit storage/API extension, rather than inventing a signature contract.

Core exceptions have a `FailureReason`, not an HTTP status. Each adapter maps
them to its native HTTP/exception model. Web behavior to preserve:

- Active Block: HTTP 401 and `Retry-After`, before original action/cache HTML.
- Pending protected action: HTTP 403; pending page UI remains transparent/inert.
- Rate limit: HTTP 429 and retry interval; verification unavailable: HTTP 501.
- Infrastructure/storage error: refuse new access, typically HTTP 503.
- Protected HTML/endpoints: `private, no-store`; verification endpoints have
  narrowly scoped exemptions and native CSRF/body-size checks.

PHP cannot enforce a request answered by CDN/proxy/page cache before PHP runs.
Adapters must implement cache bypass/integration and protect backend actions,
in addition to browser interaction locking.

## Server verification attempts

The lifecycle is described in the README's Verification lifecycle section.
`preflight` accepts an optional `bool $retry = false`; `report` now requires the
current attempt ID as its fourth argument. `failVerification` is a core operation
for a matching unfinished attempt. Update custom `GuardContract` implementations
and storage mappings together when upgrading. `inspect` never starts/retries an
attempt. Pending/failed results contain an attempt ID, and pending browser results
also contain the fixed `verificationUntil` deadline. Domain times remain Unix seconds.

A failed attempt is distinct from a visitor ban and persists until explicit retry,
a policy/actor change, or session cleanup. Concurrent tabs reuse a pending attempt;
starting a later Always cycle rotates its ID. Stale callbacks return the current
decision without mutating it. A late SDK failure cannot revoke a completed pass.
