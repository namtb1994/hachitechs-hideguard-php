# Local PHP web demo

Run `composer install` in the package directory. Supply `HG_MYSQL_DSN`,
`HG_MYSQL_USER`, `HG_MYSQL_PASSWORD`, `HG_TABLE_PREFIX` and your HideGuard
`HG_SITE_KEY` in the environment for live SDK calls.
Initialize the dedicated example tables once:

```bash
php examples/plain-php/init.php
php -S 127.0.0.1:8085 examples/plain-php/web/router.php
```

Visit the localhost URL. `/` is public and defers SDK work until the protected
form action. `/protected` locks interactions transparently while checking.
`/submit` checks a server-selected resource grant and consumes it after success.
An active block returns HTTP 401 before protected HTML/action execution, and
check/verdict endpoints also return 401 without verifying another verdict.

Native PHP sessions own browser identity and a CSRF token. The browser loads
prebuilt ESM/style exports; it needs no framework, jQuery, Node or LESS compiler
at runtime. MySQL schema setup is explicit and never runs in the router.

This example is restricted to the local PHP development server. It deliberately
uses `DevelopmentVerifier`; unsigned payloads can be forged and are unsuitable
for production protection. Automated HTTP checks simulate those development
payloads; live SDK checks need your real site key. Use the application's native
HTTP/session/cache/security integration when adapting this flow to a project.
