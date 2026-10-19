import {createInteractionLock} from './interaction-lock.js';

/** Native browser runtime. Platform behavior is injected by the application. */
export function initialize(config, options = {}) {
    var status = 'pending',
        expiresAt = 0,
        revision = 0,
        verificationStarted = false,
        verificationId = config.verificationId || '',
        verificationUntil = 0,
        queue = Promise.resolve(),
        timer,
        sdkTimer,
        gate = document.getElementById('hachitech-ab-gate'),
        channel,
        recheck,
        pageProtected,
        waiters = [];

    if (!config.enabled || window.HideGuardAccess) {
        return;
    }
    pageProtected = Boolean(config.pageProtected || config.page === 'gate');
    const interactionLock = createInteractionLock();
    const $t = options.translate || (value => value);

    function updateGate(next, forceGate) {
        // Keep the standalone gate covered until navigation replaces the document.
        var displayState = config.page === 'gate' && next === 'allowed' ? 'pending' : next,
            messages = {
                pending: [$t('Verifying access'), $t('Please wait for verification before continuing.')],
                blocked: [$t('Access temporarily blocked'), $t('Please try again after the block period.')],
                error: [$t('Unable to verify access'), $t('Access could not be verified. Please try again.')],
                allowed: ['', '']
            };

        if ((pageProtected || forceGate) && !gate) {
            gate = document.createElement('section');
            gate.id = 'hachitech-ab-gate';
            gate.className = 'hachitech-ab-gate';
            gate.setAttribute('role', 'dialog');
            gate.setAttribute('aria-modal', 'true');
            gate.setAttribute('aria-labelledby', 'hachitech-ab-heading');
            gate.setAttribute('aria-describedby', 'hachitech-ab-description');
            gate.innerHTML = '<div class="hachitech-ab-message">' +
                '<div class="hachitech-ab-icon" aria-hidden="true">' +
                '<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
                'stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" focusable="false">' +
                '<path d="M12 3 4 6v5c0 5.2 3.4 8.6 8 10 4.6-1.4 8-4.8 8-10V6l-8-3Z"/>' +
                '<rect x="9" y="10" width="6" height="5" rx="1"/>' +
                '<path d="M10 10V8a2 2 0 0 1 4 0v2"/></svg></div>' +
                '<span class="hachitech-ab-eyebrow"></span>' +
                '<h2 id="hachitech-ab-heading"></h2>' +
                '<p id="hachitech-ab-description" role="status" aria-live="polite"></p>' +
                '<div class="hachitech-ab-guidance"><span class="hachitech-ab-guidance-title"></span>' +
                '<span class="hachitech-ab-guidance-text"></span></div>' +
                '<button type="button" class="hachitech-ab-retry" data-action="retry"></button></div>';
            gate.querySelector('.hachitech-ab-retry').textContent = $t('Try again');
            gate.querySelector('.hachitech-ab-eyebrow').textContent = $t('Protected access');
            gate.querySelector('.hachitech-ab-guidance-title').textContent = $t('What happens next');
            gate.querySelector('.hachitech-ab-guidance-text').textContent =
                $t('This page will check your access again automatically when the restriction ends.');
            document.body.appendChild(gate);
        }
        if (!gate) {
            return;
        }
        gate.hidden = displayState === 'allowed';
        gate.setAttribute('data-page', config.page === 'gate' ? 'gate' : '');
        gate.setAttribute('data-state', displayState);
        interactionLock.setLocked(displayState !== 'allowed', gate);
        gate.querySelector('h2').textContent = messages[displayState][0];
        gate.querySelector('p').textContent = messages[displayState][1];
    }

    function settleWaiter(waiter) {
        if (status === 'allowed') {
            waiter.resolve();
        } else {
            waiter.reject(new Error('HideGuard access is ' + status + '.'));
        }
    }

    function transition(next, forceGate) {
        status = next;
        if (next !== 'pending') {
            clearTimeout(sdkTimer);
        }
        updateGate(next, forceGate);
        window.dispatchEvent(new CustomEvent('hachitech:access-state', {detail: {status: next}}));
        if (next !== 'pending') {
            waiters.splice(0).forEach(settleWaiter);
        }
    }

    async function request(url, body) {
        var controller = new AbortController(),
            deadline = setTimeout(function () {
                controller.abort();
            }, 8000),
            data = new URLSearchParams(body || {}),
            response,
            result;

        if (options.prepareBody) {
            options.prepareBody(data);
        }
        try {
            response = await window.fetch(url, {
                method: 'POST',
                credentials: 'same-origin',
                signal: controller.signal,
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    Accept: 'application/json'
                },
                body: data.toString()
            });
            result = await response.json();
            if (!response.ok &&
                !(response.status === 401 && result.status === 'blocked' && result.blocked === true) &&
                !(response.status === 403 && result.status === 'verification_failed')) {
                throw new Error(result.error || 'Unable to verify access.');
            }
            return result;
        } finally {
            clearTimeout(deadline);
        }
    }

    function sdkFailed() {
        if (status === 'pending') {
            handleFailure(revision);
        }
    }

    function navigateToGate(failed, restartGate = false) {
        var destination = failed ? config.deniedUrl : config.gateUrl;

        if (config.page === 'gate' && !restartGate) {
            return;
        }
        if (destination) {
            const url = new URL(destination, window.location.href);
            if (url.origin !== new URL(window.location.href).origin) {
                throw new Error('The verification gate must be on the same origin.');
            }
            window.location.replace(url.href);
        } else if (!failed) {
            window.location.reload();
        }
    }

    async function handleFailure(current) {
        if (current !== revision) {
            return;
        }
        expiresAt = 0;
        // Keep retry hidden until the server has settled this attempt.
        transition('pending', true);
        clearTimeout(sdkTimer);
        if (config.failUrl && verificationId) {
            try {
                const result = await request(config.failUrl, {verificationId});
                if (current !== revision) {
                    return;
                }
                // A late timeout must not revoke permission already granted by another tab.
                if (result.status === 'allowed' || result.status === 'blocked') {
                    accept(result, current, true);
                    return;
                }
            } catch (error) {
                // The server deadline still denies later requests if this notification cannot arrive.
            }
        }
        if (current === revision) {
            transition('error', true);
            navigateToGate(true);
        }
    }

    function loadSdk() {
        var script,
            endpointValue = config.endpointUrl ?? 'https://hideguard.io',
            endpoint;

        if (!config.publicKey.trim()) {
            throw new Error('A Public key is required to verify access.');
        }
        if (typeof endpointValue !== 'string' || endpointValue.length > 2048) {
            throw new Error('HideGuard URL must be an HTTPS origin.');
        }
        endpointValue = endpointValue.trim();
        endpoint = new URL(endpointValue);
        if (!/^https:\/\/[^/?#@]+\/?$/i.test(endpointValue) || /[\s\\\x00-\x1f\x7f]/.test(endpointValue) ||
            endpoint.protocol !== 'https:' || endpoint.username || endpoint.password ||
            endpoint.pathname !== '/' || endpoint.search || endpoint.hash) {
            throw new Error('HideGuard URL must be an HTTPS origin without a path, credentials, query or fragment.');
        }
        if (document.getElementById('hachitech-hideguard-sdk')) {
            if (config.page === 'gate' && config.gateUrl) {
                navigateToGate(false, true);
            } else {
                window.location.reload();
            }
            return;
        }
        script = document.createElement('script');
        script.id = 'hachitech-hideguard-sdk';
        script.src = endpoint.origin + '/sdk/v1.js';
        script.dataset.endpoint = endpoint.origin;
        script.dataset.siteKey = config.publicKey;
        script.async = true;
        script.onerror = sdkFailed;
        document.head.appendChild(script);
        sdkTimer = setTimeout(sdkFailed, verificationUntil ? Math.max(1, verificationUntil - Date.now()) : 35000);
    }

    function acceptAllowed(result, fromVerdict) {
        if (!fromVerdict && !(Number.isInteger(result.passDuration) && result.passDuration > 0)) {
            // Always (or an older response) requires a fresh SDK verdict on each page.
            expiresAt = 0;
            transition('pending');
            loadSdk();
            return;
        }
        expiresAt = result.expiresAt;
        transition('allowed');
        if (config.page === 'gate') {
            window.location.replace(config.returnUrl);
        } else {
            timer = setTimeout(recheck, Math.max(1, expiresAt - Date.now()));
        }
    }

    function acceptBlocked(result, fromVerdict) {
        transition('blocked');
        timer = setTimeout(recheck, Math.max(1000, result.blockedUntil - Date.now()));
        if (fromVerdict && channel) {
            channel.postMessage({type: 'block'});
        }

        // Stop the SDK that produced the block; preflight on the next page skips it.
        if (fromVerdict && config.page === 'gate') {
            window.location.reload();
        } else if (config.gateUrl || fromVerdict) {
            navigateToGate(false);
        }
    }

    function accept(result, current, fromVerdict) {
        if (current !== revision) {
            return;
        }
        clearTimeout(timer);
        if (typeof result.verificationId === 'string') {
            verificationId = result.verificationId;
        }
        if (result.status === 'allowed' && result.allowed === true && Number.isFinite(result.expiresAt) &&
            result.expiresAt > Date.now()) {
            acceptAllowed(result, fromVerdict);
            return;
        }
        expiresAt = 0;
        if (result.status === 'blocked' && result.blocked === true && Number.isFinite(result.blockedUntil)) {
            acceptBlocked(result, fromVerdict);
            return;
        }
        if (result.status === 'verification_required') {
            verificationUntil = Number.isFinite(result.verificationUntil) ? result.verificationUntil : 0;
            transition('pending');
            loadSdk();
            return;
        }
        if (result.status === 'verification_failed') {
            transition('error', true);
            navigateToGate(true);
            return;
        }
        throw new Error('The backend did not confirm access permission.');
    }

    function enqueue(work, current) {
        queue = queue.catch(function () {
            // A failed check must not prevent a later retry from reaching the server.
        }).then(work).catch(function () {
            if (current === revision) {
                return handleFailure(current);
            }
        });
        return queue;
    }

    recheck = function (retry = false) {
        var current = ++revision;

        verificationStarted = true;
        if (status !== 'blocked') {
            transition('pending');
        }
        return enqueue(async function () {
            accept(await request(config.accessUrl, retry ? {retry: '1'} : {}), current, false);
        }, current);
    };

    window.addEventListener('fpc:verdict', function (event) {
        var detail = event.detail || {},
            body,
            current;

        if (!verificationStarted) {
            return;
        }
        // Snapshot signed fields before queuing; reason descriptions are not signed.
        try {
            body = {
                verdict: typeof detail.verdict === 'string' ? detail.verdict : 'invalid',
                visitorId: typeof detail.visitorId === 'string' ? detail.visitorId : '',
                response: JSON.stringify({
                    signature: detail.signature, siteId: detail.siteId, environment: detail.environment,
                    requestId: detail.requestId, visitorId: detail.visitorId, verdict: detail.verdict,
                    score: detail.score,
                    reasons: Array.isArray(detail.reasons) && detail.reasons.length <= 64
                        ? detail.reasons.map(reason => ({code: reason && reason.code})) : null
                })
            };
        } catch (error) {
            body = {response: ''};
        }
        body.verificationId = verificationId;
        current = ++revision;
        expiresAt = 0;
        transition('pending');
        enqueue(async function () {
            // Forward malformed verdicts too: the server revokes any earlier grant.
            accept(await request(config.verdictUrl, body), current, true);
        }, current);
    });

    function guardAction(event) {
        var target = event.target.closest && event.target.closest('a,button,input,form'),
            form = target && target.closest('form'),
            href = target && (target.getAttribute('href') || target.getAttribute('formaction')) ||
                form && form.getAttribute('action') || '',
            url;

        try {
            url = new URL(href, window.location.href);
        } catch (error) {
            return;
        }
        if (!(options.isProtectedAction && options.isProtectedAction(target, url.pathname)) || status === 'allowed' && expiresAt > Date.now()) {
            return;
        }
        event.preventDefault();
        event.stopImmediatePropagation();
        transition(status === 'allowed' ? 'pending' : status, true);
        if (status === 'pending') {
            recheck();
        }
    }

    document.addEventListener('click', guardAction, true);
    document.addEventListener('submit', guardAction, true);
    document.addEventListener('click', function (event) {
        const target = event.target.closest && event.target.closest('[data-action="retry"]');
        if (target && gate && gate.contains(target) && status === 'error') {
            event.preventDefault();
            recheck(true);
        }
    });
    window.addEventListener('pageshow', function (event) {
        if (event.persisted) {
            window.location.reload();
        }
    });
    try {
        channel = new BroadcastChannel('hachitech-antidetect');
        channel.onmessage = function (event) {
            if (event.data && event.data.type === 'block') {
                if (config.page === 'gate') {
                    window.location.reload();
                } else {
                    navigateToGate(false);
                }
            }
        };
    } catch (error) {
        // The server remains authoritative when cross-tab messaging is unavailable.
    }

    window.HideGuardAccess = {
        getState: function () {
            return {status: status, expiresAt: expiresAt};
        },
        whenReady: function () {
            if (status === 'allowed' && expiresAt > Date.now()) {
                return Promise.resolve();
            }
            if (status !== 'pending') {
                return Promise.reject(new Error('HideGuard access is ' + status + '.'));
            }
            return new Promise(function (resolve, reject) {
                waiters.push({resolve: resolve, reject: reject});
            });
        }
    };
    transition(config.initialState || 'pending');
    if (pageProtected && !(config.page === 'gate' && config.initialState === 'error')) {
        recheck();
    }
    return window.HideGuardAccess;
}
