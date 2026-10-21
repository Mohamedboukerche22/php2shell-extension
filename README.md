# PHP2Shell Extension

> **Status: beta.** The code is public, the tests run, and the tool works — but it is young and
> it wants eyes on it. See [ROADMAP.md](ROADMAP.md) for what is missing and
> [CONTRIBUTING.md](CONTRIBUTING.md) for how to help.

A Chrome / Firefox **Manifest V3** extension that audits the page you are looking at for
**PHP code-execution conditions** — `php-cgi` argument injection (the CVE-2024-4577 family) and
planted web shells — and gives you a guarded mini-console to verify a finding.

The console talks to the target **for real**: every command you run is executed on the host
through the vector the scan confirmed. There is no simulation mode and no dry-run — the safety
lives in the locks described below, not in a fake environment.

---

## ⚠️ Authorized use only

**This extension actively sends PHP code to the target and can execute operating-system commands on
the host.** Use it **only** on systems you own, or that you have explicit written permission to
test (authorized pentest, scoped bug bounty, CTF/lab, self-hosted lab).

Using it against third-party systems without authorization is illegal in most jurisdictions
(CFAA, Computer Misuse Act, equivalents) and can end your career.

The extension is deliberately built so that it **cannot** hurt you by accident:

| Guard | What it does |
|---|---|
| **Consent lock** | Active probes (which execute PHP on the target) are refused until you tick *"I am authorized to test this system"*. The tick is remembered for the session; the console input stays disabled until it is granted. |
| **Origin lock** | The scanned origin is pinned at scan time. Every subsequent request goes to that origin — there is no message that can redirect the worker elsewhere. The *download all* button re-checks the origin for **every single file** it queues. |
| **Vector lock** | Commands only run through a vector that a *successful probe* proved on that exact origin. The popup can only send a command string — it can never choose the URL. |
| **Second confirmation** | Destructive commands (`rm -rf`, `mkfs`, `dd of=/dev/…`, `chmod 777`, reverse shells, …) need an explicit *"Run anyway"*. |
| **Target release** | Navigating the tab to another origin drops the report and the vector, so the console goes dead instead of pointing at a new host. |
| **Download guard** | *Download all files* needs a confirmed vector **and** the authorisation box. Files outside the document root are skipped, never fetched; only `http:`/`https:` URLs on the locked origin are queued. |
| **No telemetry** | Nothing is sent to any third party. The only traffic is to the host you scanned. The audit log stays in `chrome.storage.local`. |

**Permissions:** `activeTab`, `scripting`, `storage`, `downloads` and the host permissions
`http://*/*` / `https://*/*`. `downloads` is only used by the *download all files* button; there is
no other use of the file system.

---

## What it detects

### Strategy A — a pre-existing command channel
Sends a harmless `echo <marker>` through the usual shell parameter names (`cmd`, `c`, `exec`,
`command`, `shell`, `system`, `do`, `run`, `eval`, `q`, …) and looks for the marker to come back
verbatim. A hit means the server already executes what you send it — the classic "PHP2Shell"
situation, and it works on any platform.

### Strategy B — `php-cgi` argument injection (CVE-2024-4577 family)
Posts a benign PHP payload with the query string carrying `-d` switches, so the CGI binary is
handed extra options:

```
-d allow_url_include=1 -d auto_prepend_file=php://input
```

`auto_prepend_file=php://input` makes `php-cgi` include the **raw request body** as PHP source
before the real script runs — i.e. arbitrary PHP execution. The probe body is a one-liner that
prints a random marker; it is only reported as a finding when the marker comes back.

Four variants are tried, including the Windows soft-hyphen flavour (`%ADd` instead of `-d`), which
is the actual CVE-2024-4577 bypass — see the technical notes below.

### Passive fingerprinting
Server/PHP header evidence, PHP error banners in the body, command-like query parameters, known
web-shell filenames (`c99.php`, `r57.php`, `b374k.php`, `wso.php`, …), and a read-only DOM
fingerprint (forms, upload fields, obfuscated `<script>` blocks).

The verdict is one of: `secure` → `suspicious` → `vulnerable` (only ever set by a *confirmed*
execution).

---

## Install

### Chrome / Chromium / Edge / Brave (Chrome 121+)

1. Open `chrome://extensions`.
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select this folder (`php2shell/`).
4. Pin the extension (puzzle-piece icon → *PHP2Shell*).

### Firefox (Firefox 121+)

1. Open `about:debugging#/runtime/this-firefox`.
2. Click **Load Temporary Add-on…**
3. Select `manifest.json` in this folder.

   The add-on is removed when Firefox closes — use `web-ext run` for a persistent dev install:

   ```bash
   npx web-ext run --source-dir . --target firefox-desktop
   ```

> Both browsers are supported from a single `manifest.json`: Chrome uses
> `background.service_worker`, Firefox uses `background.scripts` — the manifest declares **both**
> keys (the documented cross-browser pattern; each engine ignores the one it does not use).
> `background.js` is a *classic* script (not an ES module) so that `importScripts()` works in the
> Chrome service worker **and** in the Firefox event page.

---

## Use

1. Open the target page.
2. Click the extension icon.
3. Read the **CURRENT TAB** box to confirm the URL.
4. Tick **"I am authorized to test this system"** (required for anything active).
5. Press **⟳ Scan Website** (enable **Deep** for more parameters/vectors).
6. Read the verdict and the **Evidence** list.
7. If the verdict is `vulnerable`, the **Mini-Console** unlocks:
   * the console is **live** — every command is executed on the target through the confirmed vector;
   * quick chips: `whoami`, `id`, `uname -a`, `pwd`, `ls -la`, `cat /etc/passwd`, `php -v`;
   * **strip HTML** (on by default) rewrites markup output into readable text — see below.
8. **⬇ Download all files** — mirror the directory the target exposes (see below).
9. The **Audit log** records every scan, command and download (local only).

### Console output filtering

A command such as `cat index.php`, `curl http://target/` or `head -c 2000 page.html` returns
markup, not text — dumping 80 kB of HTML into the terminal is noise. The worker therefore
**classifies** every response and the popup renders it accordingly:

| Kind | Detection | What you see |
|---|---|---|
| `code` | starts with `<?php` / `<?xml`, or looks like JSON | the source **verbatim** — code is never rewritten |
| `html` | contains tags *and* a document marker (`<!doctype`, `<html`, `<body`, `<div`, `<table`, …) or a high tag density | tags removed, `<script>`/`<style>`/`<head>`/comments dropped, entities decoded, block elements turned into line breaks |
| `text` | anything else | unchanged |
| `empty` | no output at all | `(no output)` |

The popup shows the rewrite explicitly:

```
[HTML stripped: 18.4 kB → 1.2 kB — untick "strip HTML" to see the markup]
```

Untick **strip HTML** in the console header to see the untouched bytes instead. The raw output is
always kept by the worker, so nothing is ever lost — only the *display* is filtered.

### Downloading everything the target exposes

With a confirmed vector and the authorisation box ticked, the **⬇ Download all files** button:

1. runs `ls -la` (or `ls -laR` with *recursive*) through the confirmed vector,
   together with `DOCUMENT_ROOT` / `SCRIPT_NAME` / `PWD` so the listing can be
   mapped back onto URLs;
2. parses the listing into regular files (directories and symlinks are skipped);
3. maps every file onto a **same-origin** URL — the origin lock is re-asserted
   for every single file, anything off-origin is dropped;
4. hands them to the browser's download manager, into a folder named
   `p2s-<host>-<timestamp>/`.

Only `http:`/`https:` URLs on the scanned origin are ever queued, and the
button stays greyed out (with the reason written underneath it) until both
gates are satisfied. Files outside the document root are reported as
skipped rather than fetched. Every finished download is written to the audit log.

---

## 🛠 Help make it better

This is the part that matters to me right now: the extension works, but I am one developer and
the attack surface of "everything about `php-cgi`" is large. **Programmers who know
Apache/`mod_cgi`, PHP internals or browser extensions are exactly who I need.**

Where you would be most useful:

| Area | Why it needs you | Size |
|---|---|---|
| **More `php-cgi` variants** | I cover four injection shapes; there are more (`-C`, `extension_dir`, `PHP_VALUE`/FastCGI, `SCRIPT_FILENAME` injection). | small |
| **Firefox parity** | One manifest, two runtimes. The Firefox path is the less travelled one. | small |
| **A real browser test** | The service-worker tests use a mocked `chrome.*`; nobody has yet loaded the extension in a browser automatically. | medium |
| **Output-filter edge cases** | Binary files, UTF-16, JSON pretty-printing, `ls` output with exotic filenames/locales. | small |
| **"Why not vulnerable?"** | Right now the evidence shows *what* was tried, not *why* it did not work. | medium |
| **The download-all flow** | Rate limiting, failed-download reporting, bundling into one archive. | medium |

The full list, with the details of each item, is in **[ROADMAP.md](ROADMAP.md)**.

**How to contribute:** [CONTRIBUTING.md](CONTRIBUTING.md) — dev setup, the design rule that keeps
the engine pure, and the four ground rules (no scope widening, no telemetry, evidence or it is
not a finding).

```bash
git clone https://github.com/Mohamedboukerche22/php2shell-extension.git
cd php2shell-extension
npm test
```

Issues and PRs: <https://github.com/Mohamedboukerche22/php2shell-extension/issues>

---

## Technical notes — what CVE-2024-4577 actually needs

These statements were verified empirically against real `php-cgi` builds (8.3.7 unpatched and
8.3.16 patched) and against the Apache source, and are reproduced by the test-suite.

**1. How the query string becomes `argv`.**
Apache's `modules/generators/mod_cgi.c` (`default_build_command()`) only forwards the query
string as CGI arguments when it contains **no literal `=`**:

```c
if (r->args && r->args[0] && !ap_strchr_c(r->args, '=')) { args = r->args; }
...
w = ap_getword_nulls(p, &args, '+');   /* split on '+'  */
ap_unescape_url(w);                     /* %3d -> '='    */
(*argv)[idx++] = ap_escape_shell_cmd(p, w);
```

That is why every payload in this extension encodes the `=` as **`%3d`** and separates the words
with **`+`**. A query string containing a literal `=` is ignored by Apache entirely.

**2. `php-cgi` blocks the classic `-d` vector on Linux/Unix.**
Since the CVE-2012-1823 fix, `php-cgi` refuses to parse its own arguments when the decoded
`QUERY_STRING` starts with `-`:

```c
if ((query_string = getenv("QUERY_STRING")) != NULL && strchr(query_string, '=') == NULL) {
    php_url_decode(...);
    if (*p == '-') { skip_getopt = 1; }   /* the -d switches are ignored */
}
```

Because Apache passes the *same* string as both `QUERY_STRING` and `argv`, the guard triggers and
the injection is a no-op. **Verified:** against the local Apache+`php-cgi` 8.3.7 emulation in "unix"
mode the extension reports *not vulnerable* — no false positive.

**3. The real CVE-2024-4577 is a Windows-only bypass.**
On Windows the command line is UTF-16 and the Win32 "Best-Fit" mapping converts the soft hyphen
`U+00AD` (`0xAD`) into a real `-` (`0x2D`) for code pages 932/936/950 — while `QUERY_STRING` still
contains `0xAD`. The guard in (2) sees `0xAD` (not `-`) and does *not* trigger, but `php_getopt()`
sees `-` and parses the option. Apache also escapes a literal `-` (`ap_escape_shell_cmd`), so only
the soft hyphen survives.

Hence the `%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3Dphp://input` variant.

**4. Argument order matters.**
`php_getopt()` stops at the first non-option argument. A CGI wrapper that passes `-f script`
*before* the injected switches makes the injection a no-op. The extension therefore relies on
Apache/`mod_cgi` semantics (the script comes from `SCRIPT_FILENAME`), which is what real
deployments do.

**5. What the post-fix versions actually change.**
PHP 8.3.8 / 8.2.20 (and the 8.1/8.0 back-ports) changed `sapi/cgi/cgi_main.c` to:

```c
 if ((query_string = getenv("QUERY_STRING")) != NULL && strchr(query_string, '=') == NULL) {
+#ifdef PHP_WIN32
+    skip_getopt = cgi || fastcgi;      /* Windows: never parse argv in CGI mode */
+#else
     /* ... unchanged: only skip when the decoded query string starts with '-' */
+#endif
 }
```

The fix is behind **`#ifdef PHP_WIN32`** — i.e. CVE-2024-4577 is structurally a
Windows-only issue. On Linux the classic `-d` vector has been blocked since 2012 and the `%AD`
vector never worked there. *Verified:* the same request against a patched `php-cgi` 8.3.16
executes nothing, and the extension reports *not vulnerable*.

**6. A broken `argv` ↔ `QUERY_STRING` binding re-opens it on every platform.**
The upstream advisory says it outright:

> *"if the binding between argv and QUERY_STRING is broken, the vulnerability of PHP-CGI Argument
> Injection would reappear"*

Apache sets `QUERY_STRING` to the *same* string it passes as `argv`, so the guard in (2) and the
"no literal `=`" condition of (1) cancel each other out. Break that binding — a reverse proxy
that rewrites the variable, a CGI wrapper, a `SetEnv` directive, a FastCGI bridge — and the
guard sees a value containing `=` and stays quiet, while Apache has already handed the query
string to `php-cgi` as arguments.

**Verified locally:** with `QUERY_STRING` replaced by a value containing `=`, the plain
`-d allow_url_include=1 -d auto_prepend_file=php://input` payload executes on **both** php-cgi
8.3.7 *and* the patched 8.3.16 — the patch does not cover this case. This is a *deployment*
mistake, not a CVE, and it is why the extension also ships the classic `-d` vector.

---

## Project layout

```
php2shell/
├── manifest.json          MV3 manifest (Chrome + Firefox dual background keys)
├── background.js          service worker / event page: all policy + all network I/O
├── core/
│   └── engine.js          pure UMD engine — no chrome.* APIs, runs in Node too
├── content.js             read-only DOM fingerprint (injected via chrome.scripting)
├── popup.html/.css/.js    dark UI: status, evidence, mini-console, audit log
├── icons/                 generated PNGs (16/32/48/128)
├── tools/make_icons.py    icon generator (Pillow)
├── CONTRIBUTING.md        how to help, dev setup, ground rules
├── ROADMAP.md             what is not finished yet — pick something
├── ANNOUNCEMENT.md        the X thread / Reddit post
├── LICENSE                MIT
└── tests/
    ├── engine.test.js     34 unit + integration tests
    ├── background.test.js 9 service-worker tests (mocked chrome.* API)
    └── vuln-server.js     local Apache+php-cgi emulator used by the tests
```

**Design rule:** `core/engine.js` contains **no** browser API calls and **no** side effects — all
network access goes through an injectable `fetchImpl`. That is what makes the exact code path
that runs in the browser testable under Node.

---

## Architecture

```
popup.js ──(chrome.runtime.sendMessage)──▶ background.js ──▶ core/engine.js ──▶ fetch()
   │                                             │                 │
   │ chrome.downloads.download()                │ policy:         │ pure functions:
   ▼                                             │ consent,        │ probes, payloads,
download manager                                 │ origin lock,    │ parsing, filtering
                                                 │ vector lock,    │
                                                 │ risk check      │
                                                 ▼
                                          audit log (storage.local)
```

* **`core/engine.js`** — pure functions only: URL analysis, probe payloads, command execution,
  `ls` parsing, download planning, output classification. No `chrome.*`, no timers, no state.
* **`background.js`** — the only place that performs network I/O and the only place that holds
  policy. It re-asserts the origin lock immediately before every request and before every queued
  download.
* **`popup.js`** — presentation and intent. It never chooses a URL, it only asks the worker to
  run something inside the locked scope.
* **`content.js`** — read-only DOM fingerprint, injected on demand with `chrome.scripting`.

### Message API (popup → worker)

| Message | Payload | Answer |
|---|---|---|
| `P2S_GET_STATE` | – | current target, report, vector, authorisation |
| `P2S_SCAN` | `{ tabId, url, authorized, deep }` | full report: verdict, evidence, vector |
| `P2S_SET_AUTH` | `{ authorized }` | new authorisation state |
| `P2S_CHECK_CMD` | `{ command }` | risk assessment (`dangerous`, reasons) |
| `P2S_EXEC` | `{ command }` | `{ ok, output, raw, kind, bytes, status, risk }` |
| `P2S_SAVE_ALL` | `{ dir?, recursive? }` | `{ listed, files[], skipped[], started }` |
| `P2S_LOG` / `P2S_CLEAR_LOG` | – | audit entries / clears them |
| `P2S_RESET` | – | drops the target lock and the report |

`P2S_EXEC` returns **both** representations of the output: `output` (filtered, readable) and
`raw` (untouched bytes). The popup picks one according to the *strip HTML* checkbox.

---

## Tests

```bash
npm test                     # everything (43 tests)
npm run test:engine          # engine unit + integration
npm run test:background      # service-worker behaviour with a mocked chrome.* runtime
```

The integration tests need a real `php-cgi` binary. Point `PHP_CGI` at one, or drop it at
`/tmp/downloads/php-8.3.7/sapi/cgi/php-cgi`:

```bash
PHP_CGI=/path/to/php-cgi npm test
```

### Local vulnerable target

```bash
npm run target            # Windows-flavour emulation (the CVE-2024-4577 condition) on :8080
npm run target:unix       # Apache-on-Linux emulation (php-cgi blocks the -d vector)
```

It exposes `/index.php`, `/info.php` and `/shell.php` (a planted `?cmd=` shell) and emulates
`mod_cgi`'s argument construction — including the Windows `0xAD → 0x2D` best-fit conversion.

---

## Limitations

* Detection is **behavioural**: it confirms execution by getting a marker back. A target that
  filters the probe, or a hardened `php-cgi` that silently drops the options, will be reported as
  `secure`/`suspicious` — that is a false negative, not a clean bill of health. Cross-check with
  the passive evidence.
* The classic `-d` vector does not work against Apache + `php-cgi` on Linux/Unix (see note 2).
  The Windows `%AD` variant is the one that reproduces CVE-2024-4577. It *does* work when the
  `argv` ↔ `QUERY_STRING` binding is broken (note 6) — on every PHP version.
* Only `http://` and `https://` origins can be scanned.
* The extension is a **verification aid**, not a scanner: it does not crawl, fuzz, or brute-force.
* *Download all files* mirrors what the web server can serve over HTTP. Files that are not
  reachable by URL (outside the document root, blocked by the server) are listed as skipped.

---

## License

MIT. Use it responsibly.
