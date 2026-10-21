/* =============================================================================
 *  PHP2Shell Extension — background service-worker tests
 * =============================================================================
 *
 *  ⚠️  These tests load the REAL background.js into a mocked chrome.* runtime
 *  and drive it through its message API against the LOCAL php-cgi target from
 *  tests/vuln-server.js. Nothing leaves 127.0.0.1.
 *
 *  What is asserted:
 *    • the consent gate (no active probe without authorization)
 *    • the origin lock (a vector pointing elsewhere is refused)
 *    • the vector lock (no command without a confirmed vector)
 *    • the authorisation gate (no consent, no traffic)
 *    • a full SCAN -> vulnerable -> LIVE EXEC round trip
 * =============================================================================
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const { startServer, startPlainServer, findPhpCgi } = require('./vuln-server.js');

const ROOT = path.resolve(__dirname, '..');

/* ---------------------------------------------------------------------------
 * A minimal but faithful chrome.* mock
 * ------------------------------------------------------------------------- */
function makeChromeMock(domResult) {
  const listeners = { message: [], installed: [], startup: [], updated: [] };
  const local = {};
  const session = {};
  const downloads = [];

  function area(store) {
    return {
      get(keys, cb) {
        const out = {};
        const list = Array.isArray(keys) ? keys : [keys];
        list.forEach((k) => { if (k in store) out[k] = store[k]; });
        if (typeof cb === 'function') cb(out);
        return Promise.resolve(out);
      },
      set(items, cb) {
        Object.assign(store, items);
        if (typeof cb === 'function') cb();
        return Promise.resolve();
      },
      remove(keys, cb) {
        (Array.isArray(keys) ? keys : [keys]).forEach((k) => { delete store[k]; });
        if (typeof cb === 'function') cb();
        return Promise.resolve();
      },
      clear(cb) {
        Object.keys(store).forEach((k) => { delete store[k]; });
        if (typeof cb === 'function') cb();
        return Promise.resolve();
      }
    };
  }

  return {
    runtime: {
      lastError: undefined,
      id: 'php2shell-test',
      onMessage: { addListener: (fn) => listeners.message.push(fn) },
      onInstalled: { addListener: (fn) => listeners.installed.push(fn) },
      onStartup: { addListener: (fn) => listeners.startup.push(fn) },
      sendMessage: (msg, cb) => { if (cb) cb(undefined); return Promise.resolve(); }
    },
    tabs: {
      onUpdated: { addListener: (fn) => listeners.updated.push(fn) },
      sendMessage: (tabId, msg, cb) => { if (cb) cb(undefined); }
    },
    scripting: {
      executeScript(opts, cb) {
        /* First call injects content.js, second call reads the fingerprint. */
        if (opts && opts.files) {
          if (cb) cb([{ result: undefined }]);
          return;
        }
        if (cb) cb([{ result: domResult }]);
      }
    },
    storage: { local: area(local), session: area(session) },
    downloads: {
      download(opts, cb) {
        downloads.push(opts);
        if (typeof cb === 'function') cb(downloads.length);
      }
    },
    __listeners: listeners,
    __local: local,
    __downloads: downloads
  };
}

/**
 * Load background.js in the current context with a mocked chrome runtime.
 * A tiny test hook is appended *inside* the IIFE so the tests can inspect the
 * worker state (origin lock, vector lock) without changing production code.
 */
function loadBackground(chromeMock) {
  globalThis.chrome = chromeMock;

  /* background.js calls importScripts('core/engine.js') — provide it. */
  globalThis.importScripts = function (rel) {
    const abs = path.resolve(ROOT, rel);
    const engine = require(abs);
    globalThis.P2SEngine = engine;
    return engine;
  };

  const src = fs.readFileSync(path.join(ROOT, 'background.js'), 'utf8');
  const marker = '})();';
  const idx = src.lastIndexOf(marker);
  if (idx === -1) throw new Error('could not find the IIFE end in background.js');
  const patched = src.slice(0, idx) +
    '\n  globalThis.__P2S_TEST__ = { state: state, handlers: handlers, runScan: runScan, runCommand: runCommand };\n' +
    src.slice(idx);

  vm.runInThisContext(patched, { filename: 'background.js' });
  return globalThis.__P2S_TEST__;
}

/** Send a message through the captured onMessage listener. */
function send(type, payload) {
  const listener = globalThis.chrome.__listeners.message[0];
  assert.ok(listener, 'background.js did not register an onMessage listener');
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('message timeout: ' + type)), 40000);
    listener({ type, payload }, { id: 'test' }, (res) => {
      clearTimeout(timer);
      resolve(res);
    });
  });
}

/* ---------------------------------------------------------------------------
 * Tests
 * ------------------------------------------------------------------------- */

test('background: refuses to run a command before a successful scan', async () => {
  const mock = makeChromeMock(null);
  loadBackground(mock);

  const state = await send('P2S_GET_STATE');
  assert.strictEqual(state.ok, true);
  assert.strictEqual(state.state.authorized, false);
  assert.ok(state.engineVersion, 'engine version must be reported');

  const exec = await send('P2S_EXEC', { command: 'id' });
  assert.strictEqual(exec.ok, false);
  assert.match(exec.error, /No confirmed vulnerability vector/);
});

test('background: without consent the scan stays passive', async (t) => {
  const srv = await startPlainServer();
  t.after(() => srv.close());

  const mock = makeChromeMock(null);
  loadBackground(mock);

  const res = await send('P2S_SCAN', { tabId: 1, url: srv.origin + '/', authorized: false });
  assert.strictEqual(res.ok, true);
  assert.strictEqual(res.report.verdict, 'secure');
  assert.strictEqual(res.report.vector, null);
  assert.ok(res.report.steps.includes('active:skipped(no-consent)'),
    'the scan must record that active probing was skipped: ' + res.report.steps.join(','));

  const exec = await send('P2S_EXEC', { command: 'id' });
  assert.strictEqual(exec.ok, false, 'no vector, no command');
});

test('background: full round trip against the vulnerable php-cgi target', async (t) => {
  if (!findPhpCgi()) {
    t.skip('php-cgi binary not available');
    return;
  }

  const srv = await startServer({ mode: 'windows' });
  t.after(() => srv.close());

  const mock = makeChromeMock({ findings: [], title: 'demo' });
  loadBackground(mock);

  /* --- consent -------------------------------------------------------- */
  const auth = await send('P2S_SET_AUTH', { authorized: true });
  assert.strictEqual(auth.authorized, true);

  /* --- scan ----------------------------------------------------------- */
  const scan = await send('P2S_SCAN', {
    tabId: 1,
    url: srv.origin + '/index.php',
    authorized: true,
    deep: true
  });
  assert.strictEqual(scan.ok, true, scan.error || '');
  assert.strictEqual(scan.report.verdict, 'vulnerable',
    'expected a confirmed RCE, got: ' + scan.report.verdict +
    ' steps=' + scan.report.steps.join(','));
  assert.ok(scan.report.vector, 'a vector must be recorded');
  assert.ok(scan.report.evidence.some((e) => e.type === 'active'));

  /* --- the command really runs on the target --------------------------- */
  const live = await send('P2S_EXEC', { command: 'echo P2S_BG_CANARY_778899' });
  assert.strictEqual(live.ok, true, live.error || '');
  assert.strictEqual(live.simulated, undefined, 'there is no simulation mode any more');
  assert.ok(live.output.includes('P2S_BG_CANARY_778899'),
    'live output must contain the canary, got: ' + JSON.stringify(live.output).slice(0, 400));

  /* --- destructive commands are flagged -------------------------------- */
  const risk = await send('P2S_CHECK_CMD', { command: 'rm -rf /var/www' });
  assert.strictEqual(risk.risk.dangerous, true);
  assert.ok(risk.risk.reasons.length > 0);

  /* --- audit log ------------------------------------------------------- */
  const log = await send('P2S_LOG');
  assert.strictEqual(log.ok, true);
  assert.ok(log.entries.length > 0, 'the audit log must not be empty');
  assert.ok(log.entries.some((e) => /Command: /.test(e.message)),
    'commands must be logged');
});

test('background: the origin lock refuses a vector pointing somewhere else', async (t) => {
  if (!findPhpCgi()) {
    t.skip('php-cgi binary not available');
    return;
  }

  const srv = await startServer({ mode: 'windows' });
  t.after(() => srv.close());

  const mock = makeChromeMock(null);
  const hooks = loadBackground(mock);

  await send('P2S_SET_AUTH', { authorized: true });
  const scan = await send('P2S_SCAN', {
    tabId: 1, url: srv.origin + '/index.php', authorized: true, deep: true
  });
  assert.strictEqual(scan.report.verdict, 'vulnerable');

  /* Tamper with the locked vector — the worker must refuse to follow it. */
  hooks.state.report.vector.script = 'http://198.51.100.7/evil.php';
  const exec = await send('P2S_EXEC', { command: 'id' });
  assert.strictEqual(exec.ok, false);
  assert.match(exec.error, /escaped the locked origin/);
});

test('background: navigating away releases the target lock', async (t) => {
  if (!findPhpCgi()) {
    t.skip('php-cgi binary not available');
    return;
  }

  const srv = await startServer({ mode: 'windows' });
  t.after(() => srv.close());

  const mock = makeChromeMock(null);
  loadBackground(mock);

  await send('P2S_SET_AUTH', { authorized: true });
  await send('P2S_SCAN', { tabId: 1, url: srv.origin + '/index.php', authorized: true });

  /* The user navigates to another origin — the lock must be dropped. */
  const onUpdated = mock.__listeners.updated[0];
  onUpdated(1, { url: 'http://example.org/elsewhere' });

  const state = await send('P2S_GET_STATE');
  assert.strictEqual(state.state.report, null, 'the report must be dropped');
  assert.strictEqual(state.state.status, 'idle');

  const exec = await send('P2S_EXEC', { command: 'id' });
  assert.strictEqual(exec.ok, false);
});

test('background: finds a shell linked from the page (DOM-discovered target)', async (t) => {
  if (!findPhpCgi()) {
    t.skip('php-cgi binary not available');
    return;
  }

  const srv = await startServer({ mode: 'unix' });
  t.after(() => srv.close());

  /* The content script reports a link to a web-shell filename. */
  const dom = {
    findings: [{
      type: 'dom',
      severity: 'critical',
      title: 'Links to well-known web-shell filenames',
      links: ['/shell.php']
    }]
  };

  const mock = makeChromeMock(dom);
  loadBackground(mock);

  await send('P2S_SET_AUTH', { authorized: true });
  const scan = await send('P2S_SCAN', {
    tabId: 1, url: srv.origin + '/index.php', authorized: true, deep: true
  });

  assert.strictEqual(scan.ok, true, scan.error || '');
  assert.strictEqual(scan.report.verdict, 'vulnerable',
    'the planted shell behind the linked URL must be found');
  assert.strictEqual(scan.report.strategy, 'existing-shell');
  assert.strictEqual(scan.report.vector.param, 'cmd');
  assert.ok(scan.report.vector.script.endsWith('/shell.php'),
    'the vector must point at the linked shell: ' + scan.report.vector.script);

  /* And it must be usable for a live command. */
  const live = await send('P2S_EXEC', { command: 'echo P2S_SHELL_CANARY_13579' });
  assert.strictEqual(live.ok, true, live.error || '');
  assert.ok(live.output.includes('P2S_SHELL_CANARY_13579'),
    'live output must contain the canary: ' + JSON.stringify(live.output).slice(0, 300));
});

test('background: "download all" lists the directory and queues same-origin downloads', async (t) => {
  if (!findPhpCgi()) {
    t.skip('php-cgi binary not available');
    return;
  }

  const srv = await startServer({ mode: 'windows' });
  t.after(() => srv.close());

  const mock = makeChromeMock({ findings: [], title: 'demo' });
  loadBackground(mock);

  /* --- gates ------------------------------------------------------------ */
  await send('P2S_SCAN', {
    tabId: 1, url: srv.origin + '/index.php', authorized: true, deep: true
  });

  /* Without the consent box nothing is queued. */
  await send('P2S_SET_AUTH', { authorized: false });
  const noConsent = await send('P2S_SAVE_ALL', {});
  assert.strictEqual(noConsent.ok, false, 'without consent nothing may be downloaded');
  assert.match(noConsent.error, /Authorization required/);
  assert.strictEqual(mock.__downloads.length, 0, 'nothing may be queued without consent');

  await send('P2S_SET_AUTH', { authorized: true });


  /* --- the real thing --------------------------------------------------- */
  const res = await send('P2S_SAVE_ALL', {});
  assert.strictEqual(res.ok, true, res.error || '');
  assert.ok(res.listed > 0, 'the listing must contain entries');
  assert.ok(res.files.length > 0, 'at least one file must be planned');
  assert.ok(res.started > 0, 'downloads must have been queued');

  const origin = srv.origin;
  res.files.forEach((f) => {
    assert.ok(f.url.startsWith(origin + '/'),
      'every download URL must stay on the locked origin: ' + f.url);
    assert.ok(!f.filename.includes('..'), 'no traversal in the local filename');
    assert.ok(f.filename.startsWith('p2s-'), 'files land in a dedicated folder: ' + f.filename);
  });

  assert.strictEqual(mock.__downloads.length, res.files.length,
    'one download per planned file');
  mock.__downloads.forEach((d) => {
    assert.ok(d.url.startsWith(origin + '/'), 'off-origin download: ' + d.url);
    assert.strictEqual(d.conflictAction, 'uniquify');
  });
});

test('background: markup output is filtered, source code is kept verbatim', async (t) => {
  if (!findPhpCgi()) {
    t.skip('php-cgi binary not available');
    return;
  }

  const srv = await startServer({ mode: 'windows' });
  t.after(() => srv.close());

  const mock = makeChromeMock({ findings: [], title: 'demo' });
  loadBackground(mock);

  await send('P2S_SET_AUTH', { authorized: true });
  await send('P2S_SCAN', {
    tabId: 1, url: srv.origin + '/index.php', authorized: true, deep: true
  });

  /* --- markup ----------------------------------------------------------- */
  const html = await send('P2S_EXEC', {
    command: "printf '%s' '<html><body><h1>Hi &amp; bye</h1><p>one</p></body></html>'"
  });
  assert.strictEqual(html.ok, true, html.error || '');
  assert.strictEqual(html.kind, 'html', 'the worker must classify the output');
  assert.ok(!html.output.includes('<h1>'), 'the tags must be gone: ' + html.output);
  assert.ok(html.output.includes('Hi & bye'), 'the entities must be decoded: ' + html.output);
  assert.ok(html.raw.includes('<h1>'), 'the raw bytes must still be there');
  assert.ok(html.bytes > html.output.length, 'the raw size is reported');

  /* --- source code ------------------------------------------------------ */
  const code = await send('P2S_EXEC', {
    command: "printf '%s' '<?php echo 1; ?>'"
  });
  assert.strictEqual(code.ok, true, code.error || '');
  assert.strictEqual(code.kind, 'code', 'source code must not be rewritten');
  assert.ok(code.output.includes('<?php echo 1; ?>'), code.output);
});

test('background: "download all" refuses without a confirmed vector', async () => {
  const mock = makeChromeMock(null);
  loadBackground(mock);

  await send('P2S_SET_AUTH', { authorized: true });

  const res = await send('P2S_SAVE_ALL', {});
  assert.strictEqual(res.ok, false);
  assert.match(res.error, /No confirmed vulnerability vector/);
  assert.strictEqual(mock.__downloads.length, 0);
});
