# Changelog

## 0.1.0 — Unreleased

- Add a framework-independent `VerdictClient` for `POST /api/v1/verdict`, with
  configurable HTTPS base URL/API key, visitor ID input, complete array responses,
  explicit API errors and an optional cURL or application-provided HTTP transport.
- Extract framework-independent PHP 8.1 contracts, factory, typed policy/context/
  decision, access checks, grant/block deadlines and trusted resource enforcement.
- Add explicit PDO MySQL 8/InnoDB storage, atomic scope locking, rate/capacity
  limits and shared storage/Guard contract tests.
- Ship prebuilt native browser ESM/AMD and LESS-derived style artifacts; preserve
  transparent pending locks, confirmed block UI, timed/Always rechecks and tab/BFcache handling.
- Provide plain PHP CLI/web examples; document separate Magento/WordPress adapters
  and a Laravel example. No framework dependency is added to the PHP core.
- Add HideGuard collect Ed25519 v2 verification using ext-sodium, canonical signed
  fields and PEM public keys, matching the Shopify source and real HideGuard vector.
  Magento verifies every environment, forwards signed SDK fields and validates admin keys.
- Bound grants/blocks by signed timestamps and invalidate old policy fingerprints;
  expired signatures cannot restart their original grant/block period.
- Match wildcard paths without regex backtracking limits, preserving literal
  characters and anchored matching even for rules with many wildcards.
- Persist each report's final session once, retaining atomic revocation and rollback.
- Centralize Block/Challenge/Allow verdict groups in public VerdictPolicy constants
  shared by validation, signature verification and Guard decisions.

This is a development version for local Composer path installation; no public
release has been published. See [progress and limits](docs/PROGRESS.md).
