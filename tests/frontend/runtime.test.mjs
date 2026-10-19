import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {browser} from './browser.mjs';
const flush = () => new Promise(resolve => setImmediate(resolve));

test('SDK script and collection endpoint use the configured HTTPS origin', async () => {
    for (const [endpointUrl, expected] of [[undefined, 'https://hideguard.io'],
        [' HTTPS://DEV.HIDEGUARD.EXAMPLE:443/ ', 'https://dev.hideguard.example'],
        ['https://stage.hideguard.example:8443/', 'https://stage.hideguard.example:8443']]) {
        const app = browser({endpointUrl});
        await flush();
        assert.equal(app.scripts.length, 1);
        assert.equal(app.scripts[0].src, expected + '/sdk/v1.js');
        assert.equal(app.scripts[0].dataset.endpoint, expected);
    }
});

test('invalid HideGuard URLs keep access locked and never load a script', async () => {
    for (const endpointUrl of ['', 'http://hideguard.example', '//hideguard.example',
        'https://user:pass@hideguard.example', 'https://@hideguard.example',
        'https://hideguard.example/path', 'https://hideguard.example/.',
        'https://hideguard.example?query', 'https://hideguard.example?',
        'https://hideguard.example#fragment', 'https://hideguard.example#',
        'https://hideguard.example\\path', 'https://hide\nguard.example', 'https://hideguard.example\0',
        {}, 'x'.repeat(2049)]) {
        const app = browser({endpointUrl});
        await flush();
        assert.equal(app.scripts.length, 0);
        assert.equal(app.locked, true);
        assert.equal(app.window.HideGuardAccess.getState().status, 'error');
    }
});

test('plain browser starts inert then waits for server permission without platform dependencies', async () => {
    const app = browser({page: '', report: () => ({status: 'allowed', allowed: true,
        passDuration: 300, expiresAt: Date.now() + 300000})});
    assert.equal(app.locked, true);
    await flush();
    assert.equal(app.scripts.length, 1);
    assert.equal('form_key' in app.requests[0].body, false);
    app.verdict('allow');
    await flush();
    assert.equal(app.locked, false);
    assert.equal(app.window.HideGuardAccess.getState().status, 'allowed');
});

test('plain browser honors cached pass and active block without loading SDK', async () => {
    for (const status of ['allowed', 'blocked']) {
        const preflight = status === 'allowed'
            ? {status, allowed: true, passDuration: 300, expiresAt: Date.now() + 300000}
            : {status, blocked: true, blockedUntil: Date.now() + 60000};
        const app = browser({page: '', preflight, responseCode: status === 'blocked' ? 401 : 200});
        await flush();
        assert.equal(app.scripts.length, 0);
        assert.equal(app.locked, status === 'blocked');
        assert.equal(app.reloads, 0);
    }
});

test('unprotected plain page has no implicit commerce rules or SDK work', async () => {
    const app = browser({page: '', pageProtected: false, points: ['all_pages']});
    await flush();
    assert.equal(app.requests.length, 0);
    assert.equal(app.scripts.length, 0);
    assert.equal(app.locked, false);
});

test('SDK/network failures keep generic UI locked', async () => {
    const app = browser({fail: true, preflight: {error: 'Unavailable'}});
    await flush();
    assert.equal(app.window.HideGuardAccess.getState().status, 'error');
    assert.equal(app.locked, true);
});

test('source contains no framework globals, imports or commerce route decisions', () => {
    for (const file of ['runtime.js', 'interaction-lock.js']) {
        const source = readFileSync(new URL('../../browser/src/' + file, import.meta.url), 'utf8');
        assert.doesNotMatch(source, /jquery|mage\/|checkout\/|WordPress|Laravel|\$\.mage/);
    }
});

test('prebuilt ESM exports the same native API and LESS-derived styles', async () => {
    const {initialize, styleText} = await import('../../browser/dist/runtime.js');
    assert.equal(typeof initialize, 'function');
    assert.match(styleText, /background: transparent/);
    assert.match(styleText, /data-state='blocked'/);
    assert.match(styleText, /background: #fff/);
    assert.equal(JSON.parse(readFileSync(new URL('../../browser/dist/runtime.styles.json', import.meta.url), 'utf8')), styleText);
});
