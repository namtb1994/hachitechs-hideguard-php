# Shared browser runtime

Source lives in `browser/src`. Native browser APIs implement SDK loading,
preflight/report, interaction locking, deadline/revision handling, BFcache and
cross-tab block signals. The application injects translations, CSRF fields and
protected action detection. The runtime imports no framework or jQuery code.

```javascript
import {initialize, styleText} from '/assets/runtime.js';

const style = document.createElement('style');
style.textContent = styleText;
document.head.appendChild(style);
initialize({
    enabled: true,
    pageProtected: true,
    page: '',
    initialState: 'pending',
    publicKey: publicSiteKey,
    accessUrl: '/access',
    verdictUrl: '/verdict',
    failUrl: '/fail',
    gateUrl: '/access-denied',
    deniedUrl: '/access-denied?failed=1',
    returnUrl: '/protected',
    verificationId: serverDecision.verificationId
}, {
    prepareBody: data => data.set('csrf', serverIssuedCsrfToken),
    isProtectedAction: (target, path) => path === '/submit'
});
```

The server must render `inert data-hachitech-ab-inert` on the body of protected
pages before JavaScript starts. The runtime hands that lock to page children,
while retaining inert attributes owned by other components. Pending on a normal
page stays transparent; a confirmed Block uses the white gate. Error never grants access.
Protect backend actions and cache paths separately through Guard.

`pageProtected` is an authoritative application route decision. Generic runtime
has no built-in product/cart/checkout rules. `page: 'gate'` denotes a standalone
verification page; supply a safe server-validated `returnUrl` for that case.
Render `data-page="gate"` on its `.hachitech-ab-gate` element so the white
background and message card remain visible before JavaScript initializes.
The standalone card stays visible during rechecks and after Allow until the
destination document replaces it; normal protected pages unlock immediately.
The initialized API is `window.HideGuardAccess`, with `getState()` and
`whenReady()`. Magento also exposes its existing `window.HachitechAntidetectBrowser`
name through the thin AMD adapter. Initialize once per page, after DOM readiness.

HTTP requests use native fetch, same-origin credentials and an 8-second timeout.
SDK starts only after preflight requires a fresh verdict; active blocks do not
load it. Timed passes use backend expiry, while interval 0 checks each protected
page. SDK errors/timeouts retain the interaction lock, notify `failUrl`, and navigate
to `deniedUrl`. A confirmed block navigates to `gateUrl`. Gate destinations must
be on the same origin. Supply these URLs to enable navigation; integrations
without them retain an in-place locked error. A gate with initial state `error`
waits for its `data-action="retry"` button and sends `retry=1`; it does not
automatically loop through retries. Gate HTML must contain an h2 and a p for messages. The backend is authoritative
for every submitted verdict and protected operation.

Each SDK event is snapshotted before queuing. The form-encoded `response` field
contains JSON with all signed fields and reason codes, excluding unsigned reason
descriptions. A signed adapter must decode that field and pass its array to
`Guard::report` with the separate form `verificationId` as its fourth argument; reading only `verdict`/`visitorId` loses the signature. Those two
legacy form fields remain for explicit development adapters. Invalid payloads
still reach the server for revocation; the UI unlocks only after backend approval.
Magento limits the encoded body to 64 KiB and decoded response to 16 KiB; the
larger body allowance accommodates URL encoding of the signed payload.

## Build and Magento publication

```bash
cd browser
npm ci --ignore-scripts
npm run build
npm run check
npm test
node publish-magento.mjs /absolute/path/to/Hachitech/AntidetectBrowser
node publish-magento.mjs /absolute/path/to/Hachitech/AntidetectBrowser --check
```

[esbuild](https://esbuild.github.io/api/#format) bundles ESM and wraps its IIFE
output in an anonymous AMD module for RequireJS. [LESS](https://lesscss.org/usage/#programmatic-usage)
compiles the shared `browser/dist/runtime.less` into the ESM/AMD `styleText`
export and the JSON-encoded CSS string `browser/dist/runtime.styles.json` at
build time. PHP adapters can use the JSON artifact with native inline-style
APIs without parsing JavaScript or compiling LESS during a request.
Prebuilt artifacts ship with Composer; PHP consumers need
neither Node nor browser build dependencies installed.

Publication copies the AMD asset and shared LESS into the Magento module. Its
`_module.less` imports `runtime.less` inside Magento's media guard; the native
theme compiler handles styles. Magento does not inject the `styleText` export.
The module entry adds form key, translation and commerce selectors, then calls
core initialization through `text/x-magento-init`. Generated assets must match
package output; do not edit the module's runtime copy by hand.

See [the plain PHP web example](../examples/plain-php/web/README.md) for native
session/CSRF/routing/resource enforcement. It uses an explicit unsigned
development verifier and is not a production signing implementation.

The [WordPress guide](../../antidetect-wordpress/README.md) documents native
script-module enqueue and explicit publication. The
[Laravel example](../../antidetect-laravel-example/README.md) serves the core
ESM directly and uses Blade/native session and CSRF. Both use the same prebuilt
runtime and LESS-derived styles; Node is only a development build dependency.

## Server integration order

1. Match enabled protected routes using the platform's router/rules.
2. Before rendering a protected GET, call `preflight`; for business requests use
   `inspect`/`assertResourceAllowed` so a request never resets a completed Always grant.
3. Render normal public HTML only for allowed/pending decisions. Return/redirect
   to a gate for failed decisions; active blocks return 401 without original HTML.
4. Check, verdict, failure and explicit retry endpoints must remain reachable,
   use native CSRF validation, size/rate limits and `private, no-store` responses.
5. `/fail` maps to `failVerification`; `/access` forwards `retry === '1'` to
   preflight. Do not trust frontend state as authorization or an arbitrary client
   reason as a timed ban. Pass `verification_failed` decisions as JSON with HTTP 403.
6. A gate with a valid timed pass returns to a validated internal `returnUrl`.
   Active blocks skip SDK until expiry; failed attempts wait for explicit retry.
