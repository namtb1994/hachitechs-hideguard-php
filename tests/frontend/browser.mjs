import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const runtimeSource = readFileSync(new URL('../../browser/dist/runtime.amd.js', import.meta.url), 'utf8');

export function browser({preflight = {status: 'verification_required'}, report, points = ['all_pages'],
  page = 'gate', pageProtected = true, fail = false, initialState = 'pending', responseCode = 200,
  bodyAlreadyInert = false, enabled = true, adapterSource, endpointUrl, gateUrl, deniedUrl, failUrl,
  verificationId, failResult = {status: 'verification_failed'}} = {}) {
  const listeners = new Map(), elements = new Map(), scripts = [], requests = [], timers = [], redirects = [];
  const mutations = [], heading = {}, message = {};
  function element(id) {
    const attributes = new Map();
    return {id, children: [], hidden: false,
      setAttribute: (name, value) => attributes.set(name, value),
      getAttribute: name => attributes.get(name), hasAttribute: name => attributes.has(name),
      removeAttribute: name => attributes.delete(name),
      contains(target) { return this === target || this.children.some(child => child.contains(target)); }};
  }
  const retry = element('retry');
  retry.closest = selector => selector === '[data-action="retry"]' ? retry : null;
  const gate = element('hachitech-ab-gate'), content = element('page-content'), preserved = element('already-inert');
  gate.children.push(retry);
  gate.querySelector = selector => selector === 'h2' ? heading : message;
  gate.setAttribute('data-state', initialState);
  preserved.setAttribute('inert', '');
  const children = [content, preserved];
  if (pageProtected || page === 'gate') { children.unshift(gate); elements.set(gate.id, gate); }
  let locked = false, reloads = 0, initialize, runtime, accessDependencies, lockDependencies;
  const document = {
    getElementById: id => elements.get(id),
    createElement: tag => tag === 'script' ? {dataset: {}} : gate,
    body: element('page-body'),
    head: {appendChild: script => { scripts.push(script); elements.set(script.id, script); }},
    documentElement: {classList: {toggle: (name, enabled) => { locked = enabled; }}},
    addEventListener: (name, callback) => {
      const key = 'document:' + name;
      listeners.set(key, [...(listeners.get(key) || []), callback]);
    }
  };
  document.body.children = children;
  document.body.appendChild = element => {
    children.push(element); elements.set(element.id, element); mutations.forEach(callback => callback());
  };
  if (bodyAlreadyInert || pageProtected || page === 'gate') {
    document.body.setAttribute('inert', '');
    if (!bodyAlreadyInert) { document.body.setAttribute('data-hachitech-ab-inert', ''); }
  }
  const bodyLockedBeforeInit = document.body.hasAttribute('inert');
  const window = {
    addEventListener: (name, callback) => listeners.set(name, callback),
    dispatchEvent() {},
    location: {href: 'https://store.test/antidetectbrowser/gate/index',
      reload: () => { reloads++; }, replace: url => redirects.push(url)},
    fetch: async (url, options) => {
      const body = Object.fromEntries(new URLSearchParams(options.body));
      requests.push({url, body, credentials: options.credentials});
      const result = url === '/access' ? (typeof preflight === 'function' ? await preflight(body) : preflight)
        : url === failUrl ? (typeof failResult === 'function' ? await failResult(body) : failResult) : await report(body);
      const code = typeof responseCode === 'function' ? responseCode(result) : responseCode;
      return {ok: !fail && code < 400, status: code, json: async () => result};
    }
  };
  const context = vm.createContext({
    window, document, URL, URLSearchParams, AbortController, Promise, Date,
    MutationObserver: class { constructor(callback) { mutations.push(callback); } observe() {} },
    CustomEvent: class { constructor(type, options) { this.type = type; this.detail = options.detail; } },
    setTimeout: (callback, ms) => { timers.push({callback, ms, active: true}); return timers.length; },
    clearTimeout: id => { if (timers[id - 1]) timers[id - 1].active = false; },
    define: (dependencies, factory) => {
      if (dependencies.length === 0) {
        lockDependencies = dependencies;
        runtime = factory();
      } else {
        accessDependencies = dependencies;
        initialize = factory({mage: {cookies: {get: () => 'form-key'}}}, {}, value => value, runtime);
      }
    }
  });
  vm.runInContext(runtimeSource, context);
  if (adapterSource) {
    vm.runInContext(adapterSource, context);
  } else {
    initialize = config => runtime.initialize(config);
  }
  initialize({enabled, points, page, pageProtected, initialState, endpointUrl, gateUrl, deniedUrl, failUrl, verificationId, publicKey: 'public-sdk-key',
    accessUrl: '/access', verdictUrl: '/verdict', returnUrl: '/protected-page'});
  const lockedBeforeInit = locked;
  return {window, listeners, requests, scripts, gate, retry, heading, message, timers, redirects, document, content, preserved,
    lockedBeforeInit, bodyLockedBeforeInit, accessDependencies, lockDependencies,
    interaction: (type, target = content) => {
      let prevented = false, stopped = false;
      const event = {target, preventDefault() { prevented = true; }, stopImmediatePropagation() { stopped = true; }};
      for (const listener of listeners.get('document:' + type) || []) {
        listener(event);
        if (stopped) break;
      }
      return {prevented, stopped};
    },
    get locked() { return locked; }, get reloads() { return reloads; },
    verdict: (verdict, visitorId = 'visitor-a') => listeners.get('fpc:verdict')({detail: {verdict, visitorId}})};
}

