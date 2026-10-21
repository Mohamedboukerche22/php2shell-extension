/* =============================================================================
 *  PHP2Shell Extension — popup controller
 * =============================================================================
 *
 *  ⚠️  AUTHORIZED USE ONLY
 *  -----------------------------------------------------------------------------
 *  The popup is a thin UI layer. All network activity and all policy decisions
 *  (origin lock, vector lock, consent lock) live in background.js — this file
 *  cannot make the extension talk to a host the operator did not scan.
 *
 *  The console talks to the target for real: every command runs through the
 *  confirmed vector. The authorisation box is the only switch
 *  explicitly (and requires the authorization checkbox) before a single byte
 *  is sent to the target.
 * =============================================================================
 */

/* global chrome */

(function () {
  'use strict';

  /* ---------------------------------------------------------------------------
   * DOM handles
   * ------------------------------------------------------------------------ */

  var $ = function (id) { return document.getElementById(id); };

  var el = {
    version: $('version'),
    urlBox: $('url-box'),
    targetUrl: $('target-url'),
    targetHost: $('target-host'),
    targetPath: $('target-path'),
    targetTitle: $('target-title'),

    statusPill: $('status-pill'),
    statusText: $('status-text'),
    severityWrap: $('severity-wrap'),
    severityValue: $('severity-value'),
    progress: $('progress'),
    statusDetail: $('status-detail'),
    scanBtn: $('scan-btn'),
    deepToggle: $('deep-toggle'),
    consent: $('consent'),

    evidenceCard: $('evidence-card'),
    evidenceList: $('evidence-list'),
    evidenceCount: $('evidence-count'),

    consoleCard: $('console-card'),
    consoleHint: $('console-hint'),
    terminal: $('terminal'),
    cmdForm: $('cmd-form'),
    cmdInput: $('cmd-input'),
    runBtn: $('run-btn'),
    dangerBar: $('danger-bar'),
    dangerText: $('danger-text'),
    dangerRun: $('danger-run'),
    dangerCancel: $('danger-cancel'),
    filterHtml: $('filter-html'),

    saveAll: $('save-all'),
    saveRecursive: $('save-recursive'),
    saveDir: $('save-dir'),
    saveNote: $('save-note'),

    logList: $('log-list'),
    clearLog: $('clear-log'),
    footState: $('foot-state')
  };

  /* ---------------------------------------------------------------------------
   * Local UI state
   * ------------------------------------------------------------------------ */

  var ui = {
    tab: null,
    report: null,
    authorized: false,
    status: 'idle',
    busy: false,
    pendingCommand: null
  };

  /* ---------------------------------------------------------------------------
   * Helpers
   * ------------------------------------------------------------------------ */

  function send(message) {
    return new Promise(function (resolve) {
      try {
        chrome.runtime.sendMessage(message, function (response) {
          void chrome.runtime.lastError;
          resolve(response || { ok: false, error: 'no response from background' });
        });
      } catch (e) {
        resolve({ ok: false, error: String((e && e.message) || e) });
      }
    });
  }

  function pad(n) { return (n < 10 ? '0' : '') + n; }

  function timestamp() {
    var d = new Date();
    return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
  }

  function logTimestamp(ts) {
    var d = new Date(ts || Date.now());
    return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
  }

  function humanBytes(n) {
    n = Number(n) || 0;
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' kB';
    return (n / (1024 * 1024)).toFixed(1) + ' MB';
  }

  function truncate(s, n) {
    s = String(s == null ? '' : s);
    return s.length <= n ? s : s.slice(0, n - 1) + '…';
  }

  /* ---------------------------------------------------------------------------
   * Terminal
   * ------------------------------------------------------------------------ */

  function term(text, cls) {
    var line = document.createElement('div');
    line.className = 't-line' + (cls ? ' ' + cls : '');
    /* textContent — never innerHTML: command output is untrusted. */
    line.textContent = text;
    el.terminal.appendChild(line);
    el.terminal.scrollTop = el.terminal.scrollHeight;
    return line;
  }

  function termBanner(text, cls) {
    var line = document.createElement('div');
    line.className = 't-line ' + (cls || 't-sys');
    line.textContent = '─'.repeat(4) + ' ' + text + ' ' + '─'.repeat(Math.max(0, 36 - text.length));
    el.terminal.appendChild(line);
    el.terminal.scrollTop = el.terminal.scrollHeight;
  }

  /* ---------------------------------------------------------------------------
   * Rendering
   * ------------------------------------------------------------------------ */

  var STATUS_TEXT = {
    idle: 'Idle',
    scanning: 'Scanning…',
    vulnerable: 'Vulnerable — PHP2Shell Detected',
    suspicious: 'Indicators Found',
    secure: 'Secure',
    error: 'Error'
  };

  function setStatus(status, detail, severity) {
    ui.status = status;
    el.statusPill.className = 'status-pill ' + status;
    el.statusText.textContent = STATUS_TEXT[status] || status;
    el.statusDetail.textContent = detail || el.statusDetail.textContent;
    el.footState.textContent = status;

    if (severity) {
      el.severityWrap.hidden = false;
      el.severityValue.textContent = severity;
    } else {
      el.severityWrap.hidden = true;
    }
  }

  function renderEvidence(report) {
    var list = (report && report.evidence) || [];
    el.evidenceList.innerHTML = '';
    el.evidenceCount.textContent = String(list.length);

    if (!list.length) {
      el.evidenceCard.hidden = true;
      return;
    }

    list.forEach(function (ev) {
      var li = document.createElement('li');
      li.className = 'sev-' + (ev.severity || 'info');

      var sev = document.createElement('span');
      sev.className = 'ev-sev';
      sev.textContent = ev.severity || 'info';

      var body = document.createElement('div');

      var title = document.createElement('div');
      title.className = 'ev-title';
      title.textContent = ev.title || ev.type || 'finding';

      var detail = document.createElement('div');
      detail.className = 'ev-detail';
      detail.textContent = ev.detail || '';

      body.appendChild(title);
      if (ev.detail) body.appendChild(detail);

      if (ev.sample) {
        var sample = document.createElement('div');
        sample.className = 'ev-sample';
        sample.textContent = ev.sample;
        body.appendChild(sample);
      } else if (ev.value) {
        var value = document.createElement('div');
        value.className = 'ev-sample';
        value.textContent = ev.value;
        body.appendChild(value);
      }

      li.appendChild(sev);
      li.appendChild(body);
      el.evidenceList.appendChild(li);
    });

    el.evidenceCard.hidden = false;
  }

  function renderConsole(report) {
    var unlocked = ui.status === 'vulnerable' && report && report.vector;
    var locked = !unlocked || !ui.authorized;
    el.consoleCard.hidden = false;
    el.cmdInput.disabled = locked || ui.busy;
    el.runBtn.disabled = locked || ui.busy;
    refreshSaveControls();

    if (unlocked) {
      var v = report.vector;
      termBanner('VECTOR ' + (v.id || v.name), 't-cmd');
      term('strategy : ' + (report.strategy || 'unknown'), 't-meta');
      term('script   : ' + v.script, 't-meta');
      if (v.query) term('query    : ' + v.query, 't-meta');
      if (v.phpVersion) term('php      : ' + v.phpVersion + ' (' + (v.sapi || '?') + ')', 't-meta');
      term('target   : ' + report.target.origin, 't-meta');
      term('traffic  : real requests to the target', 't-warn');
      term('type a command and press Enter →', 't-sys');
    } else if (!ui.authorized) {
      term('console locked — tick the authorisation box to run commands.', 't-warn');
    } else {
      term('console locked — no confirmed vector yet.', 't-warn');
    }
    updateHint();
  }

  function updateHint() {
    el.consoleHint.innerHTML = '';
    el.consoleHint.appendChild(document.createTextNode('Every command runs on '));
    var b = document.createElement('b');
    b.textContent = ui.report && ui.report.target ? ui.report.target.origin : 'the target';
    el.consoleHint.appendChild(b);
    el.consoleHint.appendChild(document.createTextNode(' through the confirmed vector. Keep it inside your scope.'));
  }

  /* ---------------------------------------------------------------------------
   * "Download all files"
   * ------------------------------------------------------------------------ */

  /**
   * The download button follows the same rules as the console: a confirmed
   * vector and the authorisation box. Anything less and the button
   * stays greyed out with the reason spelled out underneath it.
   */
  function refreshSaveControls() {
    if (!el.saveAll) return;

    var unlocked = ui.status === 'vulnerable' && ui.report && ui.report.vector;
    var can = !!unlocked && ui.authorized && !ui.busy;

    el.saveAll.disabled = !can;
    el.saveRecursive.disabled = !can;
    el.saveDir.disabled = !can;

    var note = '';
    if (!unlocked) note = 'needs a confirmed vulnerability vector — run a scan first.';
    else if (!ui.authorized) note = 'tick the authorisation box to enable downloading.';
    else note = 'lists the directory through the confirmed vector and saves every file it finds.';

    if (el.saveNote.textContent !== note) el.saveNote.textContent = note;
    el.saveNote.classList.toggle('warn', !can);
    el.saveNote.classList.toggle('ok', can);
  }

  function startSaveAll() {
    if (el.saveAll.disabled || ui.busy) return;

    ui.busy = true;
    refreshSaveControls();
    el.saveAll.textContent = '… working';
    term('listing the directory and queueing downloads…', 't-sys');

    send({
      type: 'P2S_SAVE_ALL',
      payload: {
        dir: el.saveDir.value,
        recursive: el.saveRecursive.checked
      }
    }).then(function (res) {
      ui.busy = false;
      el.saveAll.textContent = '⬇ Download all files';
      refreshSaveControls();

      if (!res || !res.ok) {
        var msg = (res && res.error) || 'download failed';
        term('! ' + msg, 't-err');
        el.saveNote.textContent = msg;
        el.saveNote.classList.add('warn');
        el.saveNote.classList.remove('ok');
        return;
      }

      term('listed ' + res.listed + ' entr' + (res.listed === 1 ? 'y' : 'ies') +
           ' → queued ' + res.started + ' download(s)', 't-ok');

      (res.files || []).slice(0, 40).forEach(function (f) {
        term('  ↓ ' + f.path + '  (' + f.size + ' bytes)', 't-out');
      });
      if ((res.files || []).length > 40) {
        term('  … ' + (res.files.length - 40) + ' more', 't-meta');
      }
      if ((res.skipped || []).length) {
        term('skipped ' + res.skipped.length + ': ' +
             res.skipped.slice(0, 8).map(function (s) { return s.name + ' (' + s.reason + ')'; }).join(', '),
             't-meta');
      }
      if (res.docroot) term('document root: ' + res.docroot, 't-meta');
      if (res.cwd) term('working dir  : ' + res.cwd, 't-meta');

      el.saveNote.textContent = res.started + ' file(s) queued into ' + res.rootName + '/';
      el.saveNote.classList.add('ok');
      el.saveNote.classList.remove('warn');
    }).catch(function (err) {
      ui.busy = false;
      el.saveAll.textContent = '⬇ Download all files';
      refreshSaveControls();
      term('! ' + String((err && err.message) || err), 't-err');
    });
  }

  /* ---------------------------------------------------------------------------
   * Target / tab
   * ------------------------------------------------------------------------ */

  function loadActiveTab() {
    return new Promise(function (resolve) {
      chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        void chrome.runtime.lastError;
        resolve((tabs && tabs[0]) || null);
      });
    });
  }

  function renderTarget(tab) {
    ui.tab = tab;
    if (!tab || !tab.url) {
      el.targetUrl.textContent = 'no scannable page (browser internal page?)';
      el.targetHost.textContent = '—';
      el.targetPath.textContent = '—';
      el.targetTitle.textContent = '—';
      el.scanBtn.disabled = true;
      return;
    }
    el.targetUrl.textContent = tab.url;
    el.urlBox.title = tab.url;

    var host = '—', path = '—';
    try {
      var u = new URL(tab.url);
      host = u.host;
      path = u.pathname + (u.search || '');
    } catch (e) { /* ignore */ }
    el.targetHost.textContent = host;
    el.targetPath.textContent = truncate(path, 34);
    el.targetTitle.textContent = truncate(tab.title || 'untitled', 26);
    el.scanBtn.disabled = false;
  }

  /* ---------------------------------------------------------------------------
   * Scan
   * ------------------------------------------------------------------------ */

  function startScan() {
    if (!ui.tab || !ui.tab.url || ui.busy) return;

    ui.busy = true;
    el.scanBtn.disabled = true;
    el.progress.hidden = false;
    setStatus('scanning', 'Analysing URL, page source and response headers…');
    el.consoleCard.hidden = true;
    el.evidenceCard.hidden = true;

    send({
      type: 'P2S_SCAN',
      payload: {
        tabId: ui.tab.id,
        url: ui.tab.url,
        deep: el.deepToggle.checked,
        authorized: el.consent.checked
      }
    }).then(function (res) {
      ui.busy = false;
      el.progress.hidden = true;
      el.scanBtn.disabled = false;

      if (!res || !res.ok || !res.report) {
        setStatus('error', (res && res.error) || 'Scan failed.');
        return;
      }

      ui.report = res.report;
      renderEvidence(ui.report);

      if (ui.report.verdict === 'vulnerable') {
        setStatus('vulnerable',
          'Arbitrary PHP execution confirmed — ' +
          (ui.report.vector.name || ui.report.vector.id) +
          '. The console below can now run verification commands.',
          ui.report.severity);
        renderConsole(ui.report);
      } else if (ui.report.verdict === 'suspicious') {
        setStatus('suspicious',
          'Indicators were found but execution was not confirmed. Tick the authorization box and re-scan for an active probe.',
          ui.report.severity);
        renderConsole(ui.report);
      } else {
        setStatus('secure',
          'No PHP2Shell indicators found on this target. Nothing was exploited.',
          ui.report.severity);
        el.consoleCard.hidden = true;
      }
    }).catch(function (err) {
      ui.busy = false;
      el.progress.hidden = true;
      el.scanBtn.disabled = false;
      setStatus('error', String((err && err.message) || err));
    });
  }

  /* ---------------------------------------------------------------------------
   * Console
   * ------------------------------------------------------------------------ */

  function runCommand(command) {
    var cmd = String(command || '').trim();
    if (!cmd) return;

    term('[' + timestamp() + '] $ ' + cmd, 't-cmd');

    send({ type: 'P2S_CHECK_CMD', payload: { command: cmd } }).then(function (check) {
      var risk = (check && check.risk) || { dangerous: false, reasons: [] };
      if (risk.dangerous) {
        ui.pendingCommand = cmd;
        el.dangerText.textContent = '⚠ Destructive command (' + risk.reasons.join(', ') + ').';
        el.dangerBar.hidden = false;
        return;
      }
      dispatchCommand(cmd);
    });
  }

  function dispatchCommand(cmd) {
    ui.busy = true;
    el.cmdInput.disabled = true;
    el.runBtn.disabled = true;

    send({ type: 'P2S_EXEC', payload: { command: cmd } }).then(function (res) {
      ui.busy = false;
      el.cmdInput.disabled = false;
      el.runBtn.disabled = false;
      el.cmdInput.focus();

      if (!res || !res.ok) {
        term('[' + timestamp() + '] ! ' + ((res && res.error) || 'command failed'), 't-err');
        return;
      }

      /* The worker returns the readable text plus the untouched bytes. */
      var filtered = res.output == null ? '' : String(res.output);
      var raw = res.raw == null ? filtered : String(res.raw);
      var out = el.filterHtml.checked ? filtered : raw;

      if (out.length) {
        out.split(/\r?\n/).forEach(function (line) {
          term(line, 't-out');
        });
      } else {
        term('(no output)', 't-meta');
      }

      /* Tell the operator when something was rewritten. */
      if (res.kind === 'html' && el.filterHtml.checked && filtered.length < raw.length) {
        term('[HTML stripped: ' + humanBytes(raw.length) + ' \u2192 ' + humanBytes(filtered.length) +
             ' — untick "strip HTML" to see the markup]', 't-meta');
      } else if (res.kind === 'html' && !el.filterHtml.checked) {
        term('[markup shown raw: ' + humanBytes(raw.length) + ']', 't-meta');
      }

      if (res.status && res.status !== 200) {
        term('HTTP ' + res.status, 't-warn');
      }
    }).catch(function (err) {
      ui.busy = false;
      el.cmdInput.disabled = false;
      el.runBtn.disabled = false;
      term('[' + timestamp() + '] ! ' + String((err && err.message) || err), 't-err');
    });
  }

  /* ---------------------------------------------------------------------------
   * Audit log
   * ------------------------------------------------------------------------ */

  function refreshLog() {
    send({ type: 'P2S_LOG' }).then(function (res) {
      var entries = (res && res.entries) || [];
      el.logList.innerHTML = '';
      if (!entries.length) {
        var li = document.createElement('li');
        li.className = 'log-empty';
        li.textContent = 'no activity yet';
        el.logList.appendChild(li);
        return;
      }
      entries.slice(0, 60).forEach(function (entry) {
        var li = document.createElement('li');
        li.className = 'lvl-' + (entry.level || 'info');

        var time = document.createElement('span');
        time.className = 'log-time';
        time.textContent = logTimestamp(entry.ts);

        var msg = document.createElement('span');
        msg.className = 'log-msg';
        msg.textContent = entry.message + (entry.detail ? ' — ' + entry.detail : '');

        li.appendChild(time);
        li.appendChild(msg);
        el.logList.appendChild(li);
      });
    });
  }

  /* ---------------------------------------------------------------------------
   * Wiring
   * ------------------------------------------------------------------------ */

  function wire() {
    el.scanBtn.addEventListener('click', startScan);

    el.consent.addEventListener('change', function () {
      ui.authorized = el.consent.checked;
      send({ type: 'P2S_SET_AUTH', payload: { authorized: ui.authorized } });
      refreshSaveControls();
      /* The console unlocks / locks with the consent box — but a hidden
       * console (secure target) must stay hidden. */
      if (ui.report && !el.consoleCard.hidden) renderConsole(ui.report);
      if (ui.authorized) {
        term('[' + timestamp() + '] authorization granted — active probes enabled', 't-warn');
      } else {
        term('[' + timestamp() + '] authorization revoked', 't-sys');
      }
    });

    el.deepToggle.addEventListener('change', function () {
      term('[' + timestamp() + '] deep scan ' + (el.deepToggle.checked ? 'enabled' : 'disabled'), 't-sys');
    });

    el.filterHtml.addEventListener('change', function () {
      term('[' + timestamp() + '] HTML filter ' + (el.filterHtml.checked ? 'enabled' : 'disabled'), 't-sys');
    });

    el.cmdForm.addEventListener('submit', function (ev) {
      ev.preventDefault();
      var cmd = el.cmdInput.value;
      el.cmdInput.value = '';
      runCommand(cmd);
    });

    el.saveAll.addEventListener('click', startSaveAll);
    el.saveDir.addEventListener('keydown', function (ev) {
      if (ev.key === 'Enter') { ev.preventDefault(); startSaveAll(); }
    });

    el.dangerCancel.addEventListener('click', function () {
      ui.pendingCommand = null;
      el.dangerBar.hidden = true;
    });

    el.dangerRun.addEventListener('click', function () {
      var cmd = ui.pendingCommand;
      ui.pendingCommand = null;
      el.dangerBar.hidden = true;
      if (cmd) dispatchCommand(cmd);
    });

    Array.prototype.forEach.call(document.querySelectorAll('.qchip'), function (chip) {
      chip.addEventListener('click', function () {
        if (!ui.authorized) {
          term('[' + timestamp() + '] ! tick the authorisation box first', 't-err');
          return;
        }
        var cmd = chip.getAttribute('data-cmd');
        el.cmdInput.value = cmd;
        runCommand(cmd);
      });
    });

    el.clearLog.addEventListener('click', function () {
      send({ type: 'P2S_CLEAR_LOG' }).then(refreshLog);
    });

    el.cmdInput.addEventListener('keydown', function (ev) {
      if (ev.key === 'l' && (ev.ctrlKey || ev.metaKey)) {
        ev.preventDefault();
        el.terminal.innerHTML = '';
      }
    });
  }

  /* ---------------------------------------------------------------------------
   * Boot
   * ------------------------------------------------------------------------ */

  function boot() {
    wire();
    loadActiveTab().then(function (tab) {
      renderTarget(tab);
      return send({ type: 'P2S_GET_STATE' });
    }).then(function (res) {
      if (res && res.state) {
        var st = res.state;
        ui.authorized = !!st.authorized;
        el.consent.checked = ui.authorized;
        if (res.engineVersion) el.version.textContent = 'v' + res.engineVersion;

        /* Restore the previous report only if it belongs to the current tab. */
        var sameTarget = false;
        try {
          sameTarget = st.target && ui.tab && new URL(st.target.url).origin === new URL(ui.tab.url).origin;
        } catch (e) { sameTarget = false; }

        if (sameTarget && st.report) {
          ui.report = st.report;
          renderEvidence(ui.report);
          if (st.report.verdict === 'vulnerable') {
            setStatus('vulnerable', 'Restored session — arbitrary PHP execution confirmed.', st.report.severity);
            renderConsole(ui.report);
          } else if (st.report.verdict === 'suspicious') {
            setStatus('suspicious', 'Restored session — indicators found, execution not confirmed.', st.report.severity);
            renderConsole(ui.report);
          } else {
            setStatus('secure', 'Restored session — no indicators found.', st.report.severity);
          }
        } else if (st.status === 'scanning') {
          setStatus('scanning', 'A scan was interrupted. Press Scan Website again.');
        }
      }
      refreshSaveControls();
      refreshLog();
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
