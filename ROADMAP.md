# Roadmap — beta

This is the honest list of what is **not** finished yet, and where a contributor can take over.
Every item is small enough to be a first PR.

---

## 🟢 Ready to pick up (good first issues)

### 1. More `php-cgi` injection variants
**Files:** `core/engine.js` → `probeInjection()`
The probe currently tries four shapes (`-d` Unix, `-d` percent-encoded, `%ADd` Windows, `%ADd`
percent-encoded). Known variants that are **not** covered yet:

* `-d` with `+` vs `%20` vs literal spaces in the query string.
* `-C` / `-d extension_dir` combinations.
* The `auto_prepend_file` variant using `data://` or `php://filter`.
* The `PHP_VALUE`/`PHP_ADMIN_VALUE` FastCGI paths (different mechanism, same family).
* The `SCRIPT_FILENAME` / `DOCUMENT_ROOT` injection with a path to a writable file.

*What a good PR looks like:* a new variant constant, a unit test in `tests/engine.test.js`
asserting the exact query string it produces, and a note in the README technical section.

### 2. Firefox parity pass
**Files:** `manifest.json`, `background.js`
`background.js` is loaded as a *classic* script in both browsers (Chrome service worker +
Firefox event page). The Firefox path is the less travelled one:

* `chrome.downloads` behaviour differences (Firefox wants a `filename` with a relative path —
  already handled, but untested on a real Firefox).
* `chrome.scripting.executeScript` in an event page vs a service worker.
* `browser_specific_settings` / gecko id / `strict_min_version` handling.

*What a good PR looks like:* a note in the PR description of what you tested and on which
Firefox version, plus a fix for whatever broke.

### 3. A real end-to-end browser test
**Files:** `tests/`
The service-worker tests use a `makeChromeMock()` harness. There is no test that actually loads
the extension in a browser. Candidates:

* Playwright with a persistent context + `--load-extension` for Chromium.
* `web-ext run` + `web-ext lint` in CI.
* A tiny harness that drives `popup.html` in a headless browser and asserts the terminal
  renders the filtered output.

### 4. Output filter improvements
**Files:** `core/engine.js` → `stripHtml()`, `formatCommandOutput()`
The filter handles HTML, XML, JSON and plain text. It does **not** yet:

* Detect and pretty-print JSON (currently JSON is treated as "code" and shown raw).
* Strip `<svg>` / `<math>` payloads, which can carry huge payloads in attributes.
* Handle BOM / UTF-16 output (a `cat` of a UTF-16 file currently shows garbage).
* Detect binary output (a `cat` of a PDF) and refuse to dump it into the terminal.

### 5. `ls` parser hardening
**Files:** `core/engine.js` → `parseLsLine()`, `parseLsOutput()`
The parser handles the classic `ls -la` line format. It breaks on:

* Filenames containing spaces, quotes or newlines (GNU `ls` escapes them — does the parser
  un-escape them correctly?).
* `ls` output with a different `LANG`/`LC_ALL` (date format, "total N" line).
* Symlink chains and broken symlinks (`ls -la` shows `-> target`).
* `--time-style=long-iso` style output.

### 6. The "download all" flow, hardened
**Files:** `core/engine.js` → `buildDownloadPlan()`, `background.js` → `saveAllFiles()`
* Resume/partial-download handling, and a report of which downloads failed.
* Detect files that are listed but not reachable over HTTP (404) and mark them as such instead
  of silently failing in the download manager.
* Support a `--tar` style bundle: fetch every file and pack them into one archive locally.
* Rate limiting — a directory with 5 000 files currently queues 5 000 downloads at once.

---

## 🟡 Bigger, high-value work

### 7. A vector for `SCRIPT_FILENAME`/`DOCUMENT_ROOT` injection
Beyond the query-string vectors: some deployments let you control the *script path*, which is a
different code path in `php-cgi` and a different detection surface.

### 8. Detection for non-Apache stacks
`php-fpm` behind nginx, IIS + PHP (the actual CVE-2024-4577 platform), and containerised
`php:apache`. The current probe is Apache-shaped.

### 9. A "why not vulnerable" explanation
When the verdict is `secure`, the extension should say *what it tried and why it did not work* —
which variant, which guard (the `=` rule, the `-` guard, the Windows-only `#ifdef`). Right now
the evidence list shows what was tried but not the reasoning.

### 10. Structured export
Let the report be exported as SARIF / Markdown / JSON so it can be dropped into a scanner report
or a bug-bounty submission.

---

## 🔴 Known gaps (reported, not yet scheduled)

* The DOM fingerprint is shallow — it does not try to deobfuscate JS. A page that builds its
  form URLs at runtime hides its shell from the passive scan.
* No rate limiting between probes. A deep scan fires a lot of requests; some WAFs will notice.
* The audit log lives in `chrome.storage.local` and is never exported.
* Firefox: the popup uses `chrome.*` (not `browser.*`) — it works through the alias, but the
  code would be cleaner with a compatibility shim.

---

## Want to take something?

Open an issue titled **"Taking: &lt;item number&gt; — &lt;what you plan to do&gt;"**, or just send a
PR. If you pick something from the 🟢 list, small and imperfect beats perfect and unmerged.
