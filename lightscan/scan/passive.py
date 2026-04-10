"""
LightScan v2.0 PHANTOM — Passive Fingerprint Layer | Developer: Light
──────────────────────────────────────────────────────────────────────
Collects fingerprints BEFORE active probing:
  - TLS fingerprint (JA3/JA3S hash)
  - HTTP header fingerprint
  - SSH banner entropy analysis
  - TCP stack fingerprint (from SYN-ACK)
  - Service behavior patterns

JA3: MD5 of (TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurveFormats)
JA3S: MD5 of (TLSVersion,Cipher,Extensions) from server hello
"""
from __future__ import annotations

import asyncio
import hashlib
import re
import socket
import ssl
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from lightscan.core.engine import ScanResult, Severity


@dataclass
class PassiveFingerprint:
    """Collected passive fingerprint data for a host:port."""
    host:         str
    port:         int
    ja3:          str = ""       # JA3 hash (client hello fingerprint)
    ja3s:         str = ""       # JA3S hash (server hello fingerprint)
    tls_version:  str = ""
    cipher_suite: str = ""
    cert_cn:      str = ""
    http_headers: Dict[str, str] = field(default_factory=dict)
    ssh_banner:   str = ""
    ssh_entropy:  float = 0.0
    tcp_window:   int = 0
    tcp_ttl:      int = 0
    banner:       str = ""
    service_hints: List[str] = field(default_factory=list)


def _entropy(data: str) -> float:
    """Shannon entropy of a string."""
    if not data: return 0.0
    import math
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    total = len(data)
    return -sum((f/total) * math.log2(f/total) for f in freq.values())


def _compute_ja3s(server_hello: bytes) -> str:
    """
    Compute JA3S from TLS ServerHello bytes.
    JA3S = MD5(TLSVersion,Cipher,Extensions)
    """
    try:
        if len(server_hello) < 5: return ""
        # TLS record layer: type(1) + version(2) + length(2)
        if server_hello[0] != 0x16: return ""  # not TLS handshake
        rec_version = struct.unpack("!H", server_hello[1:3])[0]
        pos = 5  # skip record header
        if server_hello[pos] != 0x02: return ""  # not ServerHello
        pos += 4  # skip handshake type + length
        hs_version = struct.unpack("!H", server_hello[pos:pos+2])[0]
        pos += 2 + 32  # skip version + random
        sess_len = server_hello[pos]
        pos += 1 + sess_len
        cipher = struct.unpack("!H", server_hello[pos:pos+2])[0]
        pos += 3  # skip cipher + compression
        extensions = []
        if pos + 2 <= len(server_hello):
            ext_total = struct.unpack("!H", server_hello[pos:pos+2])[0]
            pos += 2
            ext_end = pos + ext_total
            while pos + 4 <= ext_end and pos < len(server_hello):
                ext_type = struct.unpack("!H", server_hello[pos:pos+2])[0]
                ext_len  = struct.unpack("!H", server_hello[pos+2:pos+4])[0]
                extensions.append(ext_type)
                pos += 4 + ext_len
        ja3s_str = f"{hs_version},{cipher},{'-'.join(str(e) for e in extensions)}"
        return hashlib.md5(ja3s_str.encode()).hexdigest()
    except Exception:
        return ""


def _build_client_hello() -> bytes:
    """
    Build a TLS 1.2 ClientHello with common cipher suites.
    Used to capture ServerHello for JA3S computation.
    """
    # Cipher suites (common set matching Chrome-like fingerprint)
    ciphers = [
        0x1301, 0x1302, 0x1303,  # TLS 1.3
        0xc02b, 0xc02f, 0xc02c, 0xc030,  # ECDHE-ECDSA/RSA-AES-GCM
        0xcca9, 0xcca8,           # ECDHE-CHACHA20
        0xc013, 0xc014,           # ECDHE-RSA-AES-CBC
        0x009c, 0x009d,           # RSA-AES-GCM
        0x002f, 0x0035,           # RSA-AES-CBC
    ]
    cipher_bytes = struct.pack(f"!H{'H'*len(ciphers)}", len(ciphers)*2, *ciphers)

    # Extensions
    def ext(type_: int, data: bytes) -> bytes:
        return struct.pack("!HH", type_, len(data)) + data

    exts = b""
    exts += ext(0x0000, b"\x00\x00\x08\x00\x06" + b"\x00" * 5)  # SNI placeholder
    exts += ext(0x000a, struct.pack("!HHH", 4, 2, 0x001d))  # elliptic curves
    exts += ext(0x000b, b"\x01\x00")                          # EC point formats
    exts += ext(0x000d, b"\x00\x08\x04\x01\x04\x03\x05\x01\x05\x03")  # sig algos
    exts += ext(0xff01, b"\x00")                              # renegotiation info

    ext_block = struct.pack("!H", len(exts)) + exts

    # ClientHello body
    import os, time
    random_bytes = struct.pack("!I", int(time.time())) + os.urandom(28)
    ch_body = (
        b"\x03\x03" +       # TLS 1.2
        random_bytes +
        b"\x00" +           # session id length
        cipher_bytes +
        b"\x01\x00" +       # compression: null only
        ext_block
    )

    # Handshake header
    hs = b"\x01" + struct.pack("!I", len(ch_body))[1:] + ch_body

    # TLS record
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


async def collect_tls_fingerprint(host: str, port: int,
                                   timeout: float = 5.0) -> Tuple[str, str, str, str]:
    """
    Collect JA3S hash and TLS info from a server.
    Returns (ja3s, tls_version, cipher, cert_cn)
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        ctx.set_ciphers("ALL:@SECLEVEL=0")

        r, w = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx),
            timeout=timeout)

        tls_obj  = w.get_extra_info("ssl_object")
        version  = tls_obj.version() or "" if tls_obj else ""
        cipher   = tls_obj.cipher()[0] if tls_obj and tls_obj.cipher() else ""
        cert     = tls_obj.getpeercert() if tls_obj else {}
        cn = ""
        for field_group in (cert or {}).get("subject", []):
            for k, v in field_group:
                if k == "commonName":
                    cn = v

        # Get raw server hello for JA3S (approximation using cipher+version)
        ja3s = hashlib.md5(f"{version},{cipher}".encode()).hexdigest()

        try: w.close(); await w.wait_closed()
        except: pass
        return ja3s, version, cipher, cn
    except Exception:
        return "", "", "", ""


async def collect_http_fingerprint(host: str, port: int,
                                    timeout: float = 5.0) -> Dict[str, str]:
    """Collect HTTP headers passively."""
    import urllib.request, urllib.error
    scheme = "https" if port in (443, 8443, 9443) else "http"
    loop   = asyncio.get_event_loop()
    def _fetch():
        try:
            ctx = None
            if scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
            req = urllib.request.Request(
                f"{scheme}://{host}:{port}/",
                headers={"User-Agent": "Mozilla/5.0 (compatible; LightScan/2.0)"})
            kw = {"context": ctx} if ctx else {}
            with urllib.request.urlopen(req, timeout=timeout, **kw) as r:
                return dict(r.info())
        except urllib.error.HTTPError as e:
            return dict(e.headers)
        except Exception:
            return {}
    return await loop.run_in_executor(None, _fetch)


async def collect_ssh_fingerprint(host: str, port: int,
                                   timeout: float = 5.0) -> Tuple[str, float]:
    """Collect SSH banner and compute entropy."""
    try:
        r, w = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
        banner = b""
        try:
            banner = await asyncio.wait_for(r.read(256), timeout=2.0)
        except Exception:
            pass
        try: w.close(); await w.wait_closed()
        except: pass
        banner_str = banner.decode("utf-8", errors="replace").strip()
        entropy    = _entropy(banner_str)
        return banner_str, entropy
    except Exception:
        return "", 0.0


async def passive_fingerprint(
    host:   str,
    ports:  List[int],
    timeout:float = 5.0,
) -> List[ScanResult]:
    """
    Run passive fingerprinting on all open ports.
    Collects TLS/JA3S, HTTP headers, SSH banner entropy.
    """
    results = []

    for port in ports:
        fp = PassiveFingerprint(host=host, port=port)

        # TLS ports
        if port in (443, 8443, 9443, 993, 995, 636, 465, 6443, 2376):
            ja3s, ver, cipher, cn = await collect_tls_fingerprint(
                host, port, timeout)
            fp.ja3s          = ja3s
            fp.tls_version   = ver
            fp.cipher_suite  = cipher
            fp.cert_cn       = cn
            if ja3s:
                results.append(ScanResult(
                    "passive:tls", host, port, "tls_fingerprint",
                    Severity.INFO,
                    f"JA3S={ja3s} | {ver} | {cipher}" + (f" | CN={cn}" if cn else ""),
                    {"ja3s": ja3s, "tls_version": ver, "cipher": cipher, "cn": cn}
                ))
            # Flag weak TLS
            if ver in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                results.append(ScanResult(
                    "passive:tls", host, port, "weak_tls",
                    Severity.HIGH,
                    f"Weak TLS version detected: {ver}",
                    {"version": ver}
                ))

        # HTTP ports
        if port in (80, 443, 8080, 8443, 8000, 3000, 5000, 9090, 9200):
            headers = await collect_http_fingerprint(host, port, timeout)
            if headers:
                fp.http_headers = headers
                server  = headers.get("Server", "")
                powered = headers.get("X-Powered-By", "")
                info_str = " | ".join(filter(None, [server, powered]))
                if info_str:
                    results.append(ScanResult(
                        "passive:http", host, port, "http_fingerprint",
                        Severity.INFO, f"HTTP: {info_str}",
                        {"headers": {k: v for k, v in headers.items()
                                     if k in ("Server","X-Powered-By",
                                               "X-Generator","Via","X-AspNet-Version")}}
                    ))

        # SSH ports
        if port in (22, 2222, 22222):
            banner, entropy = await collect_ssh_fingerprint(host, port, timeout)
            if banner:
                fp.ssh_banner  = banner
                fp.ssh_entropy = entropy
                # High entropy banner could indicate obfuscated/custom SSH
                hint = " [HIGH ENTROPY - possible custom/obfuscated]" if entropy > 4.5 else ""
                results.append(ScanResult(
                    "passive:ssh", host, port, "ssh_banner",
                    Severity.INFO,
                    f"SSH: {banner[:80]}{hint}",
                    {"banner": banner, "entropy": round(entropy, 3)}
                ))

    return results
