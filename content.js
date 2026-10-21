/* =============================================================================
 *  PHP2Shell Extension — content script (DOM / response fingerprinting)
 * =============================================================================
 *
 *  ⚠️  AUTHORIZED USE ONLY. This file only READS the page. It never modifies
 *  the DOM, never submits forms, and never exfiltrates anything. It is
 *  injected on demand (chrome.scripting.executeScript) when the user clicks
 *  "Scan Website" on a target they are authorized to test.
 *
 *  It collects static indicators of PHP code execution / web shells:
 *    • leaked PHP source markers  (<?php, <?=)
 *    • PHP error banners          (Parse error, Fatal error, Stack trace…)
 *    • shell-capable PHP calls    (shell_exec, system, passthru, popen, assert…)
 *    • superglobal usage          ($_GET / $_POST / $_REQUEST / $_SERVER)
 *    • well-known shell artefacts  (c99.php, r57.php, B374K, WSO, FilesMan…)
 *    • hidden iframes pointing at PHP endpoints
 *    • forms exposing a command channel (input name=cmd|exec|shell…)
 *    • obfuscation markers        (eval(atob(...)), long base64 blobs)
 *
 *  The result is published on the isolated-world global `__P2S_SCAN__` and the
 *  reusable collector is exposed as `__P2S_SCAN_FN__` so the background page
 *  can call it through a second executeScript() call (works in both Chrome and
 *  Firefox, unlike relying on the completion value of a file injection).
 * =============================================================================
 */

(function () {
  'use strict';

  if (typeof document === 'undefined') return;
  if (document.contentType && document.contentType !== 'text/html' &&
      document.contentType !== 'application/xhtml+xml') return;

  /* ---------------------------------------------------------------------------
   * Signature tables
   * ------------------------------------------------------------------------ */

  /* PHP error output that should never be visible in a production response. */
  var PHP_ERROR_SIGS = [
    { re: /PHP (Parse error|Fatal error|Warning|Notice|Deprecated)\b/gi, title: 'PHP error output exposed', severity: 'medium', detail: 'The response contains a raw PHP error banner. This indicates the page is executed by PHP and that error reporting is not suppressed.' },
    { re: /\bUncaught\s+(Error|Exception|PDOException|TypeError)\b/gi, title: 'Uncaught PHP exception leaked', severity: 'medium', detail: 'An uncaught exception (often with file paths and source context) is present in the response.' },
    { re: /\bStack trace:\s*#0\b/gi, title: 'PHP stack trace leaked', severity: 'high', detail: 'A PHP stack trace is exposed, which usually reveals absolute server paths and internal call structure.' },
    { re: /\bCall to undefined (function|method)\s+/gi, title: 'PHP fatal error banner', severity: 'medium', detail: 'The page threw a PHP fatal error.' },
    { re: /\bPHP (CGI|FastCGI)\b/gi, title: 'php-cgi / FastCGI reference', severity: 'medium', detail: 'The response mentions a php-cgi/FastCGI SAPI, which is the precondition for argument-injection exploits.' },
    { re: /\bDOCUMENT_ROOT\b|\/var\/www\/|\/home\/[a-z0-9_-]+\/public_html/gi, title: 'Absolute server path disclosure', severity: 'medium', detail: 'The response contains server filesystem paths, useful for locating writable session/temp directories.' }
  ];

  /* PHP functions that indicate the page itself can run OS commands. */
  var PHP_EXEC_SIGS = [
    { re: /\bshell_exec\s*\(/gi, title: 'shell_exec() in page source', severity: 'high' },
    { re: /\bpassthru\s*\(/gi, title: 'passthru() in page source', severity: 'high' },
    { re: /\bproc_open\s*\(/gi, title: 'proc_open() in page source', severity: 'high' },
    { re: /\bpopen\s*\(/gi, title: 'popen() in page source', severity: 'high' },
    { re: /\bsystem\s*\(\s*\$_(GET|POST|REQUEST)/gi, title: 'system($_REQUEST) in page source', severity: 'critical' },
    { re: /\bshell_exec\s*\(\s*\$_(GET|POST|REQUEST)/gi, title: 'shell_exec($_REQUEST) in page source', severity: 'critical' },
    { re: /\bpassthru\s*\(\s*\$_(GET|POST|REQUEST)/gi, title: 'passthru($_REQUEST) in page source', severity: 'critical' },
    { re: /\bassert\s*\(\s*\$_(GET|POST|REQUEST)/gi, title: 'assert($_REQUEST) in page source', severity: 'critical' },
    { re: /\beval\s*\(\s*\$_(GET|POST|REQUEST)/gi, title: 'eval($_REQUEST) in page source', severity: 'critical' },
    { re: /\bcreate_function\s*\(\s*['"]\s*(eval|assert)/gi, title: 'create_function() abuse', severity: 'high' },
    { re: /\bphpinfo\s*\(/gi, title: 'phpinfo() in page source', severity: 'low' },
    { re: /\bassert\s*\(\s*base64_decode/gi, title: 'assert(base64_decode()) chain', severity: 'critical' },
    { re: /\bpreg_replace\s*\(\s*['"][^'"]*\/e['"]\s*,/gi, title: 'preg_replace /e modifier', severity: 'critical' }
  ];

  /* Superglobals: weak on their own, strong in combination with exec calls. */
  var PHP_GLOBAL_SIGS = [
    { re: /\$_(GET|POST|REQUEST|COOKIE)\b/g, title: 'PHP superglobal usage', severity: 'low' },
    { re: /\$_SERVER\s*\[\s*['"](DOCUMENT_ROOT|PATH_TRANSLATED|SCRIPT_FILENAME)/gi, title: 'Server path disclosure via $_SERVER', severity: 'medium' },
    { re: /\bphp:\/\/(input|filter|stdin|temp)/gi, title: 'php:// stream wrapper referenced', severity: 'medium' },
    { re: /\bauto_prepend_file\b|\ballow_url_include\b/gi, title: 'PHP ini injection switches referenced', severity: 'high' }
  ];

  /* Known web-shell artefacts. */
  var SHELL_ARTIFACT_SIGS = [
    { re: /\bc99\b/i, title: 'c99 shell marker', severity: 'critical' },
    { re: /\br57\b/i, title: 'r57 shell marker', severity: 'critical' },
    { re: /\bb374k\b/i, title: 'B374K shell marker', severity: 'critical' },
    { re: /\bwso\b/i, title: 'WSO shell marker', severity: 'critical' },
    { re: /\balfa\b/i, title: 'Alfa shell marker', severity: 'critical' },
    { re: /\bFilesMan\b/i, title: 'FilesMan backdoor panel', severity: 'critical' },
    { re: /\bbackdoor\b/i, title: '"backdoor" identifier', severity: 'medium' },
    { re: /\bWebShell\b|\bwebshell\b/i, title: 'webshell identifier', severity: 'medium' },
    { re: /\bFiles\s*Manager\b/i, title: 'remote file manager identifier', severity: 'medium' },
    { re: /\bUploading\s+file|\bFile\s+uploaded\b/i, title: 'Shell-like upload banner', severity: 'medium' },
    { re: /\bcmd\.php|\bshell\.php|\bc0den\.php/i, title: 'web-shell filename reference', severity: 'high' }
  ];

  /* Obfuscation markers. */
  var OBFUSCATION_SIGS = [
    { re: /\beval\s*\(\s*(atob|base64_decode)/gi, title: 'eval(atob(...)) obfuscation', severity: 'high' },
    { re: /\beval\s*\(\s*unescape\s*\(/gi, title: 'eval(unescape(...)) obfuscation', severity: 'high' },
    { re: /\bString\.fromCharCode\s*\(\s*(72\s*,\s*101\s*,\s*108)/gi, title: 'String.fromCharCode("Hel") decoding', severity: 'high' },
    { re: /\batob\s*\(\s*['"][A-Za-z0-9+/=]{60,}['"]\s*\)/gi, title: 'Large base64 blob decoded at runtime', severity: 'medium' },
    { re: /\b(document\.write|innerHTML)\s*=.*(atob|unescape)/gi, title: 'DOM write of decoded payload', severity: 'medium' }
  ];

  var ALL_SIGS = []
    .concat(PHP_ERROR_SIGS)
    .concat(PHP_EXEC_SIGS)
    .concat(PHP_GLOBAL_SIGS)
    .concat(SHELL_ARTIFACT_SIGS)
    .concat(OBFUSCATION_SIGS);

  /* ---------------------------------------------------------------------------
   * Collector
   * ------------------------------------------------------------------------ */

  function escapeRegExp(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

  function snippet(text, index, len) {
    var start = Math.max(0, index - 40);
    var end = Math.min(text.length, index + (len || 80));
    var s = text.slice(start, end).replace(/\s+/g, ' ');
    if (start > 0) s = '…' + s;
    if (end < text.length) s = s + '…';
    return s;
  }

  function collect() {
    var findings = [];
    var raw = '';
    try {
      raw = document.documentElement ? document.documentElement.outerHTML : '';
    } catch (e) { raw = ''; }

    /* 1. Raw HTML source signatures. */
    ALL_SIGS.forEach(function (sig) {
      var re = new RegExp(sig.re.source, sig.re.flags);
      var m;
      var hits = 0;
      var first = null;
      while ((m = re.exec(raw)) !== null && hits < 50) {
        if (first === null) first = m;
        hits++;
        if (m.index === re.lastIndex) re.lastIndex++;
      }
      if (hits > 0) {
        findings.push({
          type: 'dom',
          severity: sig.severity,
          title: sig.title,
          detail: sig.detail || ('Matched ' + hits + ' time(s) in the page source.'),
          count: hits,
          sample: first ? snippet(raw, first.index, 100) : ''
        });
      }
    });

    /* 2. Leaked PHP source. */
    var phpOpen = raw.match(/<\?php|\<\?=/g);
    if (phpOpen) {
      findings.push({
        type: 'dom',
        severity: 'critical',
        title: 'Raw PHP source leaked in response',
        detail: 'The response contains literal "<?php" / "<?=" markers, which normally means the server did not execute the PHP but sent its source to the client.',
        count: phpOpen.length,
        sample: snippet(raw, raw.indexOf(phpOpen[0]), 100)
      });
    }

    /* 3. Hidden iframes pointing at PHP endpoints. */
    var hiddenFrames = [];
    var frames = document.querySelectorAll('iframe, frame');
    for (var i = 0; i < frames.length; i++) {
      var f = frames[i];
      var src = f.getAttribute('src') || '';
      var w = f.clientWidth || 0, h = f.clientHeight || 0;
      var style = window.getComputedStyle ? window.getComputedStyle(f) : null;
      var hidden = (w <= 2 && h <= 2) ||
        (style && (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0'));
      if (!src) continue;
      if (!/\.php|\/cgi|\.asp|\.jsp/i.test(src)) continue;
      if (hidden) hiddenFrames.push(src);
    }
    if (hiddenFrames.length) {
      findings.push({
        type: 'dom',
        severity: 'high',
        title: 'Hidden iframe pointing at a script endpoint',
        detail: 'Zero-sized or hidden iframes are a classic technique for chaining an uploaded web shell into a legitimate page.',
        count: hiddenFrames.length,
        sample: hiddenFrames.slice(0, 5).join(', ')
      });
    }

    /* 4. Forms exposing a command channel. */
    var cmdForm = null;
    var forms = document.querySelectorAll('form');
    for (var j = 0; j < forms.length; j++) {
      var inputs = forms[j].querySelectorAll('input[name], textarea[name], select[name]');
      for (var k = 0; k < inputs.length; k++) {
        var nm = (inputs[k].getAttribute('name') || '').toLowerCase();
        if (/^(cmd|exec|command|shell|c|sh|do|run|eval|q)$/.test(nm)) {
          cmdForm = {
            action: forms[j].getAttribute('action') || location.pathname,
            method: (forms[j].getAttribute('method') || 'get').toUpperCase(),
            field: nm
          };
          break;
        }
      }
      if (cmdForm) break;
    }
    if (cmdForm) {
      findings.push({
        type: 'dom',
        severity: 'high',
        title: 'Form with a command-like field',
        detail: 'A form submits to "' + cmdForm.action + '" using a "' + cmdForm.field + '" parameter — a classic shell-panel signature.',
        count: 1,
        sample: cmdForm.method + ' ' + cmdForm.action + ' [' + cmdForm.field + ']'
      });
    }

    /* 5. Links to well-known shell filenames. */
    var shellLinks = [];
    var links = document.querySelectorAll('a[href]');
    for (var m2 = 0; m2 < links.length && shellLinks.length < 10; m2++) {
      var href = links[m2].getAttribute('href') || '';
      if (/\/(c99|r57|b374k|alfa|c0den|wso|shell|cmd|webshell|backdoor)\.php/i.test(href)) {
        shellLinks.push(href);
      }
    }
    if (shellLinks.length) {
      findings.push({
        type: 'dom',
        severity: 'critical',
        title: 'Links to well-known web-shell filenames',
        detail: 'The page links to files whose names match published web shells.',
        count: shellLinks.length,
        sample: shellLinks.join(', '),
        /* The background worker uses these as extra probe targets for
         * strategy A (a pre-existing command channel). */
        links: shellLinks.slice(0, 5)
      });
    }

    /* 6. The URL itself is a .php endpoint (weak but relevant). */
    if (/\.php(\?|$)/i.test(location.pathname + location.search)) {
      findings.push({
        type: 'dom',
        severity: 'low',
        title: 'Target is a PHP endpoint',
        detail: 'The requested resource is a .php script — the entry point required for php-cgi argument injection.',
        count: 1,
        sample: location.pathname + location.search
      });
    }

    /* 7. Page title / generator metadata. */
    var gen = document.querySelector('meta[name="generator"]');
    if (gen && /php/i.test(gen.getAttribute('content') || '')) {
      findings.push({
        type: 'dom',
        severity: 'low',
        title: 'Generator meta advertises PHP',
        detail: 'Meta generator: ' + gen.getAttribute('content'),
        count: 1,
        sample: gen.getAttribute('content')
      });
    }

    /* 8. Long base64 blobs (weak). */
    var b64 = raw.match(/['"][A-Za-z0-9+/]{300,}={0,2}['"]/g);
    if (b64 && b64.length) {
      findings.push({
        type: 'dom',
        severity: 'low',
        title: 'Large encoded blob in page source',
        detail: 'Long base64-like literals may be obfuscated payloads.',
        count: b64.length,
        sample: b64[0].slice(0, 80) + '…'
      });
    }

    return {
      url: location.href,
      title: document.title || '',
      findings: findings,
      scannedAt: Date.now(),
      byteLength: raw.length
    };
  }

  /* Publish for the background page. */
  try {
    globalThis.__P2S_SCAN_FN__ = collect;
    globalThis.__P2S_SCAN__ = collect();
  } catch (e) {
    globalThis.__P2S_SCAN__ = { url: location.href, findings: [], error: String(e && e.message || e) };
  }
})();
