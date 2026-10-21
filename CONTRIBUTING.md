# Contributing to PHP2Shell Extension

**This project is in beta. It is looking for programmers who want to make it better — not
drive-by star-clicks.** If you can read PHP, Apache/mod_cgi internals or browser-extension code,
there is a real task waiting for you in [ROADMAP.md](ROADMAP.md).

---

## What this project is

A Manifest V3 browser extension (Chrome / Firefox) that audits the page you are looking at for
**PHP code-execution conditions**:

* **Strategy A** — a pre-existing command channel (`?cmd=`, `?exec=`, `?shell=` …). Works on any
  platform, any stack.
* **Strategy B** — `php-cgi` argument injection (the CVE-2024-4577 family), including the
  Windows soft-hyphen (`%ADd`) bypass and the classic `-d` variant for deployments with a broken
  `argv` ↔ `QUERY_STRING` binding.

When a vector is *confirmed* (a random marker comes back), the extension unlocks a guarded
mini-console, filters the output and can mirror the exposed directory into the browser's download
manager.

Everything is verified behaviourally: **no finding without a marker coming back.** That is why
there are so few false positives, and it is also the hardest part to maintain.

---

## Ground rules (please read)

1. **Authorized use only.** The extension sends PHP to the target. Every change must preserve the
   lock model: consent → confirmed vector → pinned origin. If your patch makes it possible to run
   a command against a host that was not scanned and confirmed, it will be rejected.
2. **No new telemetry, ever.** No analytics, no crash reporting, no remote config, no calls to
   third-party services. The only traffic is to the host the operator scanned.
3. **No silent scope widening.** New probing techniques must be opt-in (deep scan, or a new
   toggle) and must be documented in the guard table of the README.
4. **A finding needs evidence.** A detector that cannot produce a marker back is a heuristic, not
   a finding — heuristics belong in the *passive evidence* section, with the severity they deserve.

---

## Dev setup

```bash
git clone https://github.com/Mohamedboukerche22/php2shell-exention.git
cd php2shell-exention
npm test                       # 43 tests, no php-cgi needed for the unit part
```

### Running the integration tests

The integration tests spawn a real `php-cgi`. Point `PHP_CGI` at any build:

```bash
PHP_CGI=/path/to/php-cgi npm test
```

If no binary is found the integration tests skip themselves (they print `skip`), so a green run
does not mean the network paths were exercised — check the output.

### Running the local target

```bash
npm run target        # emulates the Windows CVE-2024-4577 condition on :8080
npm run target:unix   # emulates Apache-on-Linux (php-cgi blocks the classic -d vector)
```

The emulator reproduces Apache's `mod_cgi` argument construction — including the
`0xAD → 0x2D` Windows best-fit conversion — so you can develop against a realistic target
without Docker.

### Loading the extension

* **Chrome / Chromium / Edge:** `chrome://extensions` → *Developer mode* → *Load unpacked* → pick
  the repo root.
* **Firefox 121+:** `about:debugging#/runtime/this-firefox` → *Load Temporary Add-on…* → pick
  `manifest.json`.

---

## Where the code lives

```
core/engine.js    pure functions, no chrome.* API, no side effects — runs in Node too
background.js     the ONLY place with network I/O and the ONLY place with policy
popup.*           presentation and intent; it can never choose a URL
content.js        read-only DOM fingerprint
tests/            engine unit tests + service-worker tests with a mocked chrome.* runtime
```

**The design rule:** `core/engine.js` must stay pure. All network access goes through an
injectable `fetchImpl` — that is what makes the exact code path that runs in the browser testable
under Node. Please do not "just add a `fetch()`" inside the engine.

If you touch the engine, add the test to `tests/engine.test.js`; if you touch the worker, add it
to `tests/background.test.js` (it has a `makeChromeMock()` harness — use it instead of hitting
the network from a test).

---

## Style

* Plain ES5-ish JavaScript (no build step, no bundler, no transpiler — the extension has to run
  from a folder on disk). `const`/`let`/arrow functions are fine; template literals are fine.
* Two-space indentation, semicolons, single quotes for strings.
* Comments explain **why**, not **what**.
* Public functions get a JSDoc block; keep the description honest.

---

## Pull requests

* One topic per PR. Smaller is better.
* Run `npm test` before you push.
* Describe what you changed, how you tested it, and what you *didn't* test.
* If you touch the detection logic, include the raw HTTP exchange (query string + response
  snippet) in the PR description — it makes review much faster.
* Security-sensitive changes (anything that changes what leaves the browser) get discussed in an
  issue first.

---

## Security policy

Do **not** open a public issue for a vulnerability in this extension or in a target it can be used
against. Report it privately to the maintainer first; a fix and a credit will follow.

---

## Code of conduct

Be decent. Critique the code, not the person. Assume the other person knows more about their
part than you do. No harassment, no gatekeeping, no "you must have tried harder".

---

## License

By contributing you agree that your work is released under the [MIT license](LICENSE).
