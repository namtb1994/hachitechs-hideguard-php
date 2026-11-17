# Changelog

This changelog starts with **1.0.0**, the first stable distribution of
`hachitechs/hideguard-php`.

## Unreleased

- Default PHP policies and verdict requests to the live API at `https://hideguard.io`.
- Require signed production verification by default; local unsigned demos now opt
  into their verification mode explicitly.
- Remove environment selection and obsolete endpoint instructions from the README.

## 1.0.0

### Included

- Framework-independent PHP 8.1+ access-control core with typed policies, contexts,
  decisions, server-owned verification attempts, grants, blocks and resource binding.
- Environment-aware policies with explicit HTTPS endpoint overrides and legacy
  staging construction for PHP adapters.
- Standalone authenticated `VerdictClient` for `POST /api/v1/verdict`, injectable
  HTTP transport, bounded responses, TLS verification and explicit API errors.
- Ed25519 collect-v2 verification with canonical signed fields, trusted public keys,
  freshness checks and shared verdict classification. Private backend responses use
  a separate trusted response checker; unsigned browser payloads are not trusted.
- MySQL 8/InnoDB PDO storage with transactional security state, rate accounting,
  capacity counters, scoped browser/resource coordination and explicit reconciliation.
- Optional capability contracts with conservative fallback for custom adapters,
  bounded cleanup batches and continuation results.
- Coalesced unchanged last-seen writes, atomic scope/identity quota admission and
  sticky block reuse while retaining immediate security-state persistence.
- Optional shared circuit breaker with leased recovery probes, stale-result fencing,
  bounded waits and fail-closed errors; no HTTP retries or cached Allow fallback.
- Prebuilt ESM/AMD browser runtime and styles for interaction locking, backend-confirmed
  access, expiry/retry, cross-tab notification and browser navigation handling.
- Plain PHP CLI/web examples and unit, contract, HTTP, storage and process-concurrency
  regression coverage. Production dependencies are PHP, `psr/clock` and `psr/log`.

### Installation and boundaries

- Install through the `v1.0.0` Git tag after it has been published. Composer derives
  the package version from the tag; the library manifest does not pin a version field.
- Initialize standalone PDO schemas explicitly during deployment. Framework adapters
  own their migrations and must be deployed with a compatible package version.
- When replacing an existing development installation, drain old writers and apply
  required verification/control/circuit schema updates before resuming traffic.
  Retain security records and active block deadlines; incompatible grants reverify.
- Browser verification still needs the application's identity, CSRF, routing and
  server-side authorization integration. Verification IDs do not add signed
  browser/resource nonce binding or complete replay prevention.
- The CLI/web demos use an explicit development verifier and are not production
  signature-verification configurations.
