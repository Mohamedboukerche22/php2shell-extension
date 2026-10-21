# Announcement — PHP2Shell Extension (beta)

Everything below is ready to copy-paste. The X thread is one post per bullet, each under 280
characters. The Reddit post is a single markdown body.

---

## 🚀 One-liner (for a bio, a banner, or the top of the post)

> A Manifest V3 browser extension that detects PHP code-execution (php-cgi argument injection /
> web shells) and hands you a guarded console — **beta, open source, looking for reviewers.**

---

## 🐦 X thread (post these in order)

**1/9**
> I built a browser extension that finds PHP code-execution on whatever page you're looking at — php-cgi argument injection (CVE-2024-4577 family) and planted web shells. It's open source and in beta. 🧵👇

**2/9**
> The problem: php-cgi argument injection is invisible in a normal scan. The `-d` switch is buried in the query string, so a page looks clean while the CGI binary is about to include your POST body as PHP.

**3/9**
> How it works: the extension sends a harmless `echo <random marker>` through every common shell parameter (`cmd`, `exec`, `shell`…) and every known injection shape, and only reports a finding when the marker comes back.

**4/9**
> No marker, no finding. Every verdict is behavioural, so there are no "your server looks like it might be vulnerable" verdicts. A finding means code really executed.

**5/9**
> The part I spent the most time on: getting the CGI details right. Apache only forwards a query string as argv if it has no literal `=`, and php-cgi ignores its own args when the decoded query starts with `-`. Both verified against real source + real php-cgi builds.

**6/9**
> Also shipped: CVE-2024-4577 is structurally a Windows-only bug (the upstream fix sits behind `#ifdef PHP_WIN32`). But a broken `argv` ↔ `QUERY_STRING` binding re-opens the classic `-d` vector on every platform — including fully patched PHP. I ship that vector too.

**7/9**
> When a vector is confirmed you get a guarded console (consent lock, origin lock, vector lock, second confirmation for destructive commands) and an "⬇ download all files" that mirrors the exposed directory into the browser's download manager, same-origin only.

**8/9**
> Output is filtered: HTML comes back as readable text, source code stays verbatim, and the raw bytes are always one click away.

**9/9**
> It's beta and the code is up. If you write PHP, Apache/mod_cgi, or browser extensions — I'd love a second pair of eyes. Issues, PRs and "this is wrong" all welcome: [repo link] 🐛

---

## 🟥 Reddit post

**Suggested title:**

> [Beta] I built a browser extension that detects PHP code-execution (php-cgi argument injection / web shells) — looking for reviewers

**Body:**

> **TL;DR** — I made a Manifest V3 extension (Chrome/Firefox) that audits the page you're on for
> PHP code-execution: `php-cgi` argument injection (the CVE-2024-4577 family) and planted web
> shells. It's MIT-licensed, it's beta, and I'm looking for programmers to help me make it better.
> Repo: [repo link]

> ### What it actually does
>
> 1. **Passive fingerprinting** — PHP headers, error banners, command-like query params,
>    known web-shell filenames (`c99.php`, `r57.php`, `wso.php`…), a read-only DOM fingerprint.
> 2. **Strategy A — existing command channel.** It sends `echo <random marker>` through the
>    usual suspects (`cmd`, `c`, `exec`, `command`, `shell`, `system`, `do`, `run`, `eval`, `q`…)
>    and looks for the marker to come back.
> 3. **Strategy B — `php-cgi` argument injection.** It posts a benign PHP payload with the query
>    string carrying `-d allow_url_include=1 -d auto_prepend_file=php://input`, so the CGI binary
>    includes the raw request body as PHP source. Four variants are tried, including the Windows
>    soft-hyphen (`%ADd`) flavour that *is* CVE-2024-4577.
>
> **Nothing is reported unless a marker comes back.** The verdict is `secure` / `suspicious` /
> `vulnerable`, and `vulnerable` only ever means "code actually executed on the target".

> ### The details I went deep on
>
> - Apache only forwards a query string as CGI arguments if it contains **no literal `=`** — that's
>   why every payload encodes `=` as `%3d` and separates words with `+`.
> - Since the 2012 fix, `php-cgi` ignores its own argv when the decoded `QUERY_STRING` starts
>   with `-`, which kills the classic vector on Linux.
> - The upstream fix for CVE-2024-4577 (PHP 8.3.8 / 8.2.20) is behind **`#ifdef PHP_WIN32`** —
>   so structurally, it's a Windows-only bug.
> - …but a broken `argv` ↔ `QUERY_STRING` binding (a wrapper, a `SetEnv`, a reverse proxy, a
>   FastCGI bridge) re-opens the plain `-d` vector **on every platform, on every version,
>   including fully patched PHP**. That's a deployment bug, not a CVE, and the extension ships
>   that vector as well.
>
> All of that was verified against real `php-cgi` 8.3.7 (unpatched) and 8.3.16 (patched) builds
> and against the Apache source — and it's reproduced by the test suite.

> ### If a vector is confirmed
>
> You get a **guarded mini-console**: consent lock (nothing active without the authorisation
> box), origin lock (the scanned origin is pinned; nothing can redirect the worker), vector lock
> (commands only run through the probe that actually proved execution), second confirmation for
> destructive commands, and a local-only audit log. Plus an **"⬇ download all files"** button
> that mirrors the exposed directory into the download manager — same-origin only, files outside
> the document root are skipped, never fetched.

> Output is filtered too: HTML comes back as readable text, source code stays verbatim, and the
> raw bytes are always one click away.

> ### Why I'm posting
>
> It works, but **it's beta and it needs eyes on it.** The things I'd most love help with:
>
> - **More `php-cgi` variants** — I cover four shapes; there are more (`-C`, `extension_dir`,
>   `PHP_VALUE`/FastCGI paths, `SCRIPT_FILENAME` injection).
> - **Firefox parity** — the worker runs as a classic script in both browsers; the Firefox path
>   is the less travelled one.
> - **A real browser test** — right now the service-worker tests use a mocked `chrome.*`; I'd
>   love a Playwright/`web-ext` harness that loads the extension for real.
> - **Output-filter edge cases** — binary output, UTF-16, JSON pretty-printing, `ls` parsing with
>   weird filenames/locales.
>
> The full roadmap is in the repo (`ROADMAP.md`). It's plain JavaScript, no build step, no
> bundler, MIT licensed — clone it, `npm test`, load it unpacked.

> ### ⚠️ Authorized use only
>
> This extension **executes commands on the target**. Only use it on systems you own or have
> explicit written permission to test. That's why the guard rails exist, and why I built it
> that way instead of shipping a "scan" button and calling it a day.
>
> Repo: [repo link] · Issues and PRs: [issues link] · MIT

**Suggested flair** (depending on the sub): `r/netsec` → *Tool* · `r/webdev` → *Tool* /
*Show HN* style post · `r/selfhosted` → *Resource* · `r/programming` → *Tool*.

---

## 📸 What to attach

* A short screen recording (30–45 s): open popup → tick authorisation → scan → verdict →
  run `ls -la` → filtered output → press **⬇ download all files** → the download folder appears.
* A screenshot of the evidence list and the filtered terminal.

If you post the recording, blur the target URL or use the bundled local target
(`npm run target`) — do not show a live site you do not own.

---

## 🗣️ Short talk track (if you'd rather say it than paste it)

> "I kept running into the same problem: a site looks clean in every scanner, but a php-cgi
> argument injection is invisible to a normal scan, because the whole payload hides in the query
> string. So I wrote an extension that doesn't *guess* — it sends a random marker and only calls
> it a finding when the marker comes back. Then I spent a lot of time in the Apache and PHP
> source, because the details decide everything: whether the `=` is encoded, whether the `-d`
> survives php-cgi's guard, whether the fix even applies on your platform. It's beta, it's open
> source, and I want the people who actually know mod_cgi to tell me what I got wrong."
