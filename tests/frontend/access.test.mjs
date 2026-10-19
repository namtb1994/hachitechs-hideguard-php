import {test} from 'node:test';
import assert from 'node:assert/strict';
import {browser} from './browser.mjs';
const flush = () => new Promise(resolve => setImmediate(resolve));

test('signed SDK fields are snapshotted and forwarded to backend with reason codes only', async () => {
  const allowed = {status: 'allowed', allowed: true, passDuration: 300, expiresAt: Date.now() + 300000};
  const app = browser({page: '', report: () => allowed});
  await flush();
  const detail = {signature: 'v2-signature', siteId: 'site', environment: 'production',
    requestId: 'request', visitorId: 'visitor', verdict: 'challenge', score: 35,
    reasons: [{code: 'inspectorAttached', detail: 'display text'}], heartbeatIntervalMs: 15000};
  app.listeners.get('fpc:verdict')({detail});
  detail.verdict = 'allow';
  detail.reasons[0].code = 'changed';
  assert.equal(app.locked, true);
  await flush();
  assert.deepEqual(JSON.parse(app.requests.at(-1).body.response), {
    signature: 'v2-signature', siteId: 'site', environment: 'production', requestId: 'request',
    visitorId: 'visitor', verdict: 'challenge', score: 35, reasons: [{code: 'inspectorAttached'}]
  });
  assert.equal(app.locked, false);
});

test('unserializable SDK payloads still reach the server to revoke earlier permission', async () => {
  const app = browser({report: () => ({error: 'Invalid signature'}), responseCode: result => result.error ? 400 : 200});
  await flush();
  app.listeners.get('fpc:verdict')({detail: {score: 1n}});
  await flush();
  assert.equal(app.requests.at(-1).body.response, '');
  assert.equal(app.locked, true);
  assert.equal(app.window.HideGuardAccess.getState().status, 'error');
});

test('unlocking access preserves a body lock owned by another component', async () => {
  const app = browser({page: '', bodyAlreadyInert: true,
    report: () => ({status: 'allowed', allowed: true, passDuration: 0, expiresAt: Date.now() + 300000})});
  await flush();
  app.verdict('allow');
  await flush();
  assert.equal(app.window.HideGuardAccess.getState().status, 'allowed');
  assert.equal(app.document.body.hasAttribute('inert'), true);
});

test('existing block stays locked and never loads the SDK or redirects to content', async () => {
  const app = browser({responseCode: 401, preflight: {status: 'blocked', blocked: true, blockedUntil: Date.now() + 60000}});
  await flush();
  assert.equal(app.locked, true);
  assert.equal(app.window.HideGuardAccess.getState().status, 'blocked');
  assert.equal(app.gate.getAttribute('data-state'), 'blocked');
  assert.equal(app.scripts.length, 0);
  assert.equal(app.redirects.length, 0);
});

test('existing permission still loads SDK and waits for a fresh confirmed verdict before leaving gate', async () => {
  const allowed = {status: 'allowed', allowed: true, passDuration: 0, expiresAt: Date.now() + 300000};
  const app = browser({preflight: allowed, report: () => allowed});
  assert.equal(app.redirects.length, 0);
  await flush();
  assert.equal(app.locked, true);
  assert.equal(app.scripts.length, 1);
  assert.equal(app.scripts[0].src, 'https://hideguard.io/sdk/v1.js');
  assert.equal(app.scripts[0].dataset.siteKey, 'public-sdk-key');
  assert.equal(app.window.HideGuardAccess.getState().status, 'pending');
  assert.equal(app.window.HideGuardAccess.getState().expiresAt, 0);
  assert.equal(app.redirects.length, 0);
  let ready = false;
  const readyPromise = app.window.HideGuardAccess.whenReady().then(() => { ready = true; });
  await flush();
  assert.equal(ready, false);
  app.verdict('allow');
  await flush();
  await readyPromise;
  assert.equal(ready, true);
  assert.equal(app.locked, true);
  assert.equal(app.gate.hidden, false);
  assert.deepEqual(app.redirects, ['/protected-page']);
  assert.equal(app.scripts.length, 1);
  assert.equal(app.content.hasAttribute('inert'), true);
  assert.equal(app.preserved.hasAttribute('inert'), true);
});

test('passed users are scanned again on each new page without reusing the old grant to unlock', async () => {
  const allowed = {status: 'allowed', allowed: true, passDuration: 0, expiresAt: Date.now() + 300000};
  for (let pageLoad = 0; pageLoad < 2; pageLoad++) {
    const app = browser({page: '', preflight: allowed, report: () => allowed});
    await flush();
    assert.equal(app.requests[0].url, '/access');
    assert.equal(app.scripts.length, 1);
    assert.equal(app.locked, true);
    app.verdict('allow');
    await flush();
    assert.equal(app.requests[1].url, '/verdict');
    assert.equal(app.locked, false);
    assert.equal(app.scripts.length, 1);
    assert.equal(app.reloads, 0);
  }
});

test('timed passes skip SDK on later protected pages until the original expiry', async () => {
  for (const duration of [60, 300, 900, 3600]) {
    const allowed = {status: 'allowed', allowed: true, passDuration: duration, expiresAt: Date.now() + duration * 1000};
    for (let pageLoad = 0; pageLoad < 2; pageLoad++) {
      const app = browser({page: 'product', points: ['product'], preflight: allowed});
      assert.equal(app.locked, true);
      await flush();
      await app.window.HideGuardAccess.whenReady();
      assert.equal(app.locked, false);
      assert.equal(app.scripts.length, 0);
      assert.equal(app.requests.length, 1);
      assert.equal(app.window.HideGuardAccess.getState().expiresAt, allowed.expiresAt);
      const timers = app.timers.filter(timer => timer.active);
      assert.equal(timers.length, 1);
      assert.ok(timers[0].ms > duration * 1000 - 1000 && timers[0].ms <= duration * 1000);
      assert.equal(app.reloads, 0);
    }
  }
});

test('expired timed pass locks the page and loads SDK again', async () => {
  const allowed = {status: 'allowed', allowed: true, passDuration: 60, expiresAt: Date.now() + 60000};
  let preflight = allowed;
  const app = browser({page: 'product', points: ['product'], preflight: () => preflight,
    report: () => ({...allowed, expiresAt: Date.now() + 60000})});
  await flush();
  assert.equal(app.scripts.length, 0);
  assert.equal(app.locked, false);
  preflight = {status: 'verification_required'};
  app.timers.find(timer => timer.active).callback();
  assert.equal(app.locked, true);
  await flush();
  assert.equal(app.scripts.length, 1);
  assert.equal(app.requests.length, 2);
  assert.equal(app.window.HideGuardAccess.getState().status, 'pending');
  app.verdict('allow');
  await flush();
  assert.equal(app.locked, false);
  assert.equal(app.scripts.length, 1);
});

test('fresh timed pass uses backend expiry then reloads once to restart an already loaded SDK', async () => {
  const preflight = {status: 'verification_required'};
  const allowed = {status: 'allowed', allowed: true, passDuration: 900, expiresAt: Date.now() + 900000};
  const app = browser({page: 'product', points: ['product'], preflight: () => preflight, report: () => allowed});
  await flush();
  assert.equal(app.scripts.length, 1);
  app.verdict('challenge');
  await flush();
  assert.equal(app.locked, false);
  assert.equal(app.window.HideGuardAccess.getState().expiresAt, allowed.expiresAt);
  app.timers.find(timer => timer.active).callback();
  await flush();
  assert.equal(app.locked, true);
  assert.equal(app.reloads, 1);
  assert.equal(app.scripts.length, 1);
});

test('timed pass resumes from gate without SDK when backend confirms unexpired access', async () => {
  const app = browser({preflight: {status: 'allowed', allowed: true, passDuration: 3600, expiresAt: Date.now() + 3600000}});
  await flush();
  assert.equal(app.scripts.length, 0);
  assert.deepEqual(app.redirects, ['/protected-page']);
  assert.equal(app.gate.hidden, false);
  assert.equal(app.locked, true);
  assert.equal(app.heading.textContent, 'Verifying access');
});

test('expired block keeps the standalone gate visible until the allowed destination loads', async () => {
  const app = browser({initialState: 'blocked', preflight: {status: 'verification_required'},
    report: () => ({status: 'allowed', allowed: true, passDuration: 300, expiresAt: Date.now() + 300000})});
  assert.equal(app.gate.getAttribute('data-state'), 'blocked');
  await flush();
  assert.equal(app.gate.getAttribute('data-page'), 'gate');
  assert.equal(app.gate.hidden, false);
  assert.equal(app.heading.textContent, 'Verifying access');
  assert.equal(app.locked, true);
  assert.equal(app.scripts.length, 1);
  app.verdict('allow');
  await flush();
  assert.equal(app.window.HideGuardAccess.getState().status, 'allowed');
  assert.deepEqual(app.redirects, ['/protected-page']);
  assert.equal(app.gate.hidden, false);
  assert.equal(app.gate.getAttribute('data-state'), 'pending');
  assert.equal(app.heading.textContent, 'Verifying access');
  assert.equal(app.content.hasAttribute('inert'), true);
  assert.equal(app.locked, true);
});

test('active blocks skip SDK for every recheck interval', async () => {
  for (const passDuration of [0, 60, 300, 900, 3600]) {
    const app = browser({page: 'product', points: ['product'], responseCode: 401,
      preflight: {status: 'blocked', blocked: true, blockedUntil: Date.now() + 60000, passDuration}});
    await flush();
    assert.equal(app.scripts.length, 0);
    assert.equal(app.locked, true);
    assert.equal(app.window.HideGuardAccess.getState().status, 'blocked');
  }
});

test('missing or invalid interval metadata cannot skip SDK using an earlier pass', async () => {
  for (const passDuration of [undefined, null, '300', -1, 60.5, Infinity]) {
    const app = browser({preflight: {status: 'allowed', allowed: true, passDuration, expiresAt: Date.now() + 300000}});
    await flush();
    assert.equal(app.scripts.length, 1);
    assert.equal(app.locked, true);
    assert.equal(app.redirects.length, 0);
  }
});

test('a fresh SDK block overrides an earlier passed grant and never opens content', async () => {
  const app = browser({page: '', preflight: {status: 'allowed', allowed: true, passDuration: 0, expiresAt: Date.now() + 300000},
    report: () => ({status: 'blocked', blocked: true, blockedUntil: Date.now() + 60000})});
  await flush();
  assert.equal(app.scripts.length, 1);
  assert.equal(app.locked, true);
  app.verdict('block');
  await flush();
  assert.equal(app.window.HideGuardAccess.getState().status, 'blocked');
  assert.equal(app.gate.getAttribute('data-state'), 'blocked');
  assert.equal(app.locked, true);
  assert.equal(app.redirects.length, 0);
  assert.equal(app.reloads, 1);
});

test('SDK failure or timeout keeps a previously passed user locked', async () => {
  for (const failure of ['error', 'timeout']) {
    const app = browser({page: '', preflight: {status: 'allowed', allowed: true, passDuration: 0, expiresAt: Date.now() + 300000}});
    await flush();
    assert.equal(app.scripts.length, 1);
    if (failure === 'error') {
      app.scripts[0].onerror();
    } else {
      app.timers.find(timer => timer.active && timer.ms === 35000).callback();
    }
    assert.equal(app.window.HideGuardAccess.getState().status, 'error');
    assert.equal(app.locked, true);
    assert.equal(app.redirects.length, 0);
  }
});

test('disabled configuration does not create access requests or SDK state', async () => {
  const app = browser({enabled: false, page: '', pageProtected: false, points: []});
  await flush();
  assert.equal(app.requests.length, 0);
  assert.equal(app.scripts.length, 0);
  assert.equal(app.window.HideGuardAccess, undefined);
  assert.equal(app.locked, false);
});

test('SDK resumes after block expiry even if the backend reports an existing permission', async () => {
  const allowed = {status: 'allowed', allowed: true, passDuration: 0, expiresAt: Date.now() + 300000};
  let state = {status: 'blocked', blocked: true, blockedUntil: Date.now() + 60000};
  const app = browser({page: '', initialState: 'blocked', preflight: () => state,
    responseCode: result => result.status === 'blocked' ? 401 : 200, report: () => allowed});
  await flush();
  assert.equal(app.scripts.length, 0);
  state = allowed;
  app.timers.find(timer => timer.active).callback();
  await flush();
  assert.equal(app.scripts.length, 1);
  assert.equal(app.locked, true);
  assert.equal(app.window.HideGuardAccess.getState().status, 'pending');
  app.verdict('challenge');
  await flush();
  assert.equal(app.locked, false);
});

test('allow and challenge wait for the backend before unlocking', async () => {
  for (const verdict of ['allow', 'challenge']) {
    let resolve;
    const delayed = new Promise(done => { resolve = done; });
    const app = browser({page: '', report: () => delayed});
    await flush();
    app.verdict(verdict);
    await flush();
    assert.equal(app.locked, true);
    resolve({status: 'allowed', allowed: true, passDuration: 0, expiresAt: Date.now() + 300000});
    await flush();
    assert.equal(app.locked, false);
    assert.equal(app.requests[1].body.verdict, verdict);
    assert.equal('sessionId' in app.requests[1].body, false);
    assert.equal('accessToken' in app.requests[1].body, false);
  }
});

test('block verdict immediately closes UI and reloads once to stop SDK', async () => {
  const app = browser({report: () => ({status: 'blocked', blocked: true, blockedUntil: Date.now() + 60000})});
  await flush();
  app.verdict('block');
  assert.equal(app.locked, true);
  assert.equal(app.gate.getAttribute('data-state'), 'pending');
  await flush();
  assert.equal(app.window.HideGuardAccess.getState().status, 'blocked');
  assert.equal(app.gate.getAttribute('data-state'), 'blocked');
  assert.equal(app.reloads, 1);
  assert.equal(app.redirects.length, 0);
});

test('a later block cannot be overwritten by a slow allow response', async () => {
  let resolve;
  const delayed = new Promise(done => { resolve = done; });
  const app = browser({report: body => body.verdict === 'allow' ? delayed :
    {status: 'blocked', blocked: true, blockedUntil: Date.now() + 60000}});
  await flush();
  app.verdict('allow');
  await flush();
  app.verdict('block');
  resolve({status: 'allowed', allowed: true, passDuration: 0, expiresAt: Date.now() + 300000});
  await flush();
  assert.equal(app.window.HideGuardAccess.getState().status, 'blocked');
  assert.equal(app.redirects.length, 0);
});

test('network error, SDK timeout and malformed or expired grants stay locked', async () => {
  for (const preflight of [{status: 'allowed', allowed: true},
    {status: 'allowed', allowed: true, passDuration: 0, expiresAt: Date.now() - 1000}]) {
    const app = browser({preflight});
    await flush();
    assert.equal(app.locked, true);
    assert.equal(app.window.HideGuardAccess.getState().status, 'error');
  }
  const failed = browser({fail: true, preflight: {error: 'Network failed'}});
  await flush();
  assert.equal(failed.locked, true);
  const timeout = browser();
  await flush();
  timeout.timers.find(timer => timer.active && timer.ms === 35000).callback();
  assert.equal(timeout.window.HideGuardAccess.getState().status, 'error');
  assert.equal(timeout.locked, true);
});

test('arbitrary custom protected paths also lock the frontend and load SDK', async () => {
  const app = browser({points: [], page: '', pageProtected: true});
  assert.equal(app.locked, true);
  await flush();
  assert.equal(app.requests.length, 1);
  assert.equal(app.scripts.length, 1);
});

test('empty page selection leaves unselected pages interactive without checking', async () => {
  const app = browser({points: [], page: '', pageProtected: false});
  assert.equal(app.locked, false);
  await flush();
  assert.equal(app.requests.length, 0);
  assert.equal(app.scripts.length, 0);
});

test('pending and errors block mouse, keyboard and submit without showing a confirmed block', async () => {
  const app = browser({fail: true, preflight: {error: 'Network failed'}});
  for (const type of ['click', 'pointerdown', 'keydown', 'submit', 'touchstart']) {
    assert.deepEqual(app.interaction(type), {prevented: true, stopped: true});
  }
  assert.equal(app.gate.getAttribute('data-state'), 'pending');
  await flush();
  assert.equal(app.gate.getAttribute('data-state'), 'error');
  assert.equal(app.content.hasAttribute('inert'), true);
});

test('late page elements become inert while pending and are restored after allow', async () => {
  let resolve;
  const app = browser({page: '', report: () => new Promise(done => { resolve = done; })});
  await flush();
  const attributes = new Set();
  const added = {id: 'late-content', contains: () => false, hasAttribute: name => attributes.has(name),
    setAttribute: name => attributes.add(name), removeAttribute: name => attributes.delete(name)};
  app.document.body.appendChild(added);
  assert.equal(added.hasAttribute('inert'), true);
  app.verdict('allow');
  await flush();
  resolve({status: 'allowed', allowed: true, passDuration: 0, expiresAt: Date.now() + 300000});
  await flush();
  assert.equal(added.hasAttribute('inert'), false);
  assert.equal(app.gate.hidden, true);
});

test('a server-confirmed initial block stays visible during preflight', async () => {
  const app = browser({initialState: 'blocked', responseCode: 401,
    preflight: {status: 'blocked', blocked: true, blockedUntil: Date.now() + 60000}});
  assert.equal(app.gate.getAttribute('data-state'), 'blocked');
  await flush();
  assert.equal(app.gate.getAttribute('data-state'), 'blocked');
  assert.equal(app.scripts.length, 0);
});

test('401 without a valid blocked result remains an error rather than a white block screen', async () => {
  const app = browser({responseCode: 401, preflight: {error: 'Unauthorized'}});
  await flush();
  assert.equal(app.gate.getAttribute('data-state'), 'error');
  assert.equal(app.locked, true);
});

test('restoring a page from browser back-forward cache rechecks via reload', () => {
  const app = browser();
  app.listeners.get('pageshow')({persisted: true});
  assert.equal(app.reloads, 1);
});


test('SDK blocking redirects to denial and notifies backend using the current attempt', async () => {
  for (const failure of ['error', 'timeout']) {
    const app = browser({page: '', failUrl: '/fail', deniedUrl: '/gate?failed=1',
      preflight: {status: 'verification_required', verificationId: 'attempt-a', verificationUntil: Date.now() + 35000}});
    await flush();
    if (failure === 'error') app.scripts[0].onerror();
    else app.timers.find(timer => timer.active && timer.ms > 30000).callback();
    await flush();
    assert.equal(app.locked, true);
    assert.equal(app.requests.at(-1).url, '/fail');
    assert.equal(app.requests.at(-1).body.verificationId, 'attempt-a');
    assert.deepEqual(app.redirects, ['https://store.test/gate?failed=1']);
  }
});

test('invalid backend response redirects even when failure notification cannot reach the server', async () => {
  const app = browser({page: '', failUrl: '/fail', deniedUrl: '/gate?failed=1', verificationId: 'attempt-a',
    preflight: {error: 'Unavailable'}, responseCode: 503, failResult: () => {throw new Error('offline');}});
  await flush();
  assert.equal(app.locked, true);
  assert.deepEqual(app.redirects, ['https://store.test/gate?failed=1']);
});

test('both preflight and fresh block results navigate to gate without opening content', async () => {
  const blocked = {status: 'blocked', blocked: true, blockedUntil: Date.now() + 60000};
  const preflight = browser({page: '', gateUrl: '/gate', preflight: blocked, responseCode: 401});
  await flush();
  assert.equal(preflight.scripts.length, 0);
  assert.deepEqual(preflight.redirects, ['https://store.test/gate']);
  const fresh = browser({page: '', gateUrl: '/gate', report: () => blocked,
    responseCode: result => result.blocked ? 401 : 200});
  await flush(); fresh.verdict('block'); await flush();
  assert.equal(fresh.locked, true);
  assert.deepEqual(fresh.redirects, ['https://store.test/gate']);
});

test('failed gate waits for explicit retry then sends a retry POST instead of looping', async () => {
  const app = browser({initialState: 'error', preflight: {status: 'verification_required',
    verificationId: 'retry-attempt', verificationUntil: Date.now() + 35000}});
  await flush();
  assert.equal(app.requests.length, 0);
  assert.equal(app.scripts.length, 0);
  assert.equal(app.locked, true);
  app.interaction('click', app.retry);
  await flush();
  assert.equal(app.requests[0].body.retry, '1');
  assert.equal(app.scripts.length, 1);
});

test('server deadline limits SDK wait after a slow initial response', async () => {
  const app = browser({preflight: {status: 'verification_required', verificationId: 'attempt-a',
    verificationUntil: Date.now() + 12000}});
  await flush();
  assert.ok(app.timers.some(timer => timer.active && timer.ms > 10000 && timer.ms <= 12000));
  assert.equal(app.timers.some(timer => timer.active && timer.ms === 35000), false);
});

test('a late SDK failure cannot undo a grant already confirmed in another tab', async () => {
  const app = browser({page: '', failUrl: '/fail', deniedUrl: '/gate?failed=1',
    preflight: {status: 'verification_required', verificationId: 'attempt-a'},
    failResult: {status: 'allowed', allowed: true, passDuration: 300, expiresAt: Date.now() + 300000}});
  await flush(); app.scripts[0].onerror(); await flush();
  assert.equal(app.locked, false);
  assert.equal(app.redirects.length, 0);
});


test('retry waits until a slow failure notification has settled the previous attempt', async () => {
  let finishFailure;
  const app = browser({failUrl: '/fail',
    preflight: {status: 'verification_required', verificationId: 'attempt-a'},
    failResult: () => new Promise(resolve => {finishFailure = resolve;})});
  await flush();
  app.scripts[0].onerror();
  await flush();
  assert.equal(app.gate.getAttribute('data-state'), 'pending');
  app.interaction('click', app.retry);
  await flush();
  assert.equal(app.requests.filter(request => request.url === '/access').length, 1);
  finishFailure({status: 'verification_failed'});
  await flush();
  assert.equal(app.gate.getAttribute('data-state'), 'error');
  app.interaction('click', app.retry);
  await flush();
  assert.equal(app.requests.at(-1).body.retry, '1');
});
