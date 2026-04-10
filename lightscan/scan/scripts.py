"""
LightScan v2.0 PHANTOM — Script Engine (NSE-style) | Developer: Light
───────────────────────────────────────────────────────────────────────
Equivalent to: nmap --script <name>

Scripts live in lightscan/scripts/<category>/<name>.py
Each script is a Python module with:
  - SCRIPT_NAME   : str
  - SCRIPT_PORTS  : List[int]  (empty = any port)
  - SCRIPT_TAGS   : List[str]
  - async def run(host, port, timeout) -> List[ScanResult]

Built-in scripts:
  http/http_headers       — grab + analyse HTTP headers
  http/http_methods       — test allowed HTTP methods
  http/http_title         — extract page title
  http/http_auth          — detect auth type (Basic, Digest, NTLM)
  smb/smb_os_discovery    — SMB OS/hostname enumeration
  smb/smb_security_mode   — SMB signing, auth level
  tls/tls_versions        — enumerate TLS/SSL versions
  tls/tls_ciphers         — list accepted cipher suites
  tls/tls_cert_info       — certificate details + expiry
  dns/dns_zone_transfer   — AXFR zone transfer attempt
  dns/dns_recursion       — test for open DNS recursion
  ssh/ssh_algorithms      — list supported SSH algorithms
  ssh/ssh_hostkey         — extract SSH host key fingerprint
"""
from __future__ import annotations

import asyncio
import importlib
import importlib.util
import os
import re
import ssl
import socket
import struct
import sys
from pathlib import Path
from typing import Dict, List, Optional

from lightscan.core.engine import ScanResult, Severity


# ── Script registry ───────────────────────────────────────────────────────────

class ScriptRegistry:
    """Discovers and loads scripts from the scripts directory."""

    def __init__(self, script_dirs: Optional[List[str]] = None):
        self._scripts: Dict[str, object] = {}
        pkg_scripts  = Path(__file__).parent.parent / "scripts"
        home_scripts = Path.home() / ".lightscan" / "scripts"
        # Always scan both pkg and home dirs
        default_dirs = [str(pkg_scripts), str(home_scripts)]
        dirs = script_dirs or default_dirs
        for d in dirs:
            self._load_dir(Path(d))

    def _load_dir(self, path: Path):
        if not path.exists(): return
        for f in path.rglob("*.py"):
            if f.name.startswith("_"): continue
            try:
                spec   = importlib.util.spec_from_file_location(f.stem, f)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                name = getattr(module, "SCRIPT_NAME", f.stem)
                self._scripts[name] = module
            except Exception as e:
                print(f"\033[38;5;240m[!] Script load failed {f.name}: {e}\033[0m")

    def get(self, name: str):
        return self._scripts.get(name)

    def filter(self, tags: Optional[List[str]] = None,
               ports: Optional[List[int]] = None,
               names: Optional[List[str]] = None) -> List:
        out = list(self._scripts.values())
        if names:
            out = [s for s in out if getattr(s, "SCRIPT_NAME", "") in names]
        if tags:
            out = [s for s in out if
                   any(t in getattr(s, "SCRIPT_TAGS", []) for t in tags)]
        if ports:
            out = [s for s in out if
                   not getattr(s, "SCRIPT_PORTS", []) or
                   any(p in getattr(s, "SCRIPT_PORTS", []) for p in ports)]
        return out

    def for_port(self, port: int) -> List:
        return [s for s in self._scripts.values()
                if not getattr(s, "SCRIPT_PORTS", []) or
                port in getattr(s, "SCRIPT_PORTS", [])]

    def list_all(self) -> List[Dict]:
        result = []
        for name, mod in self._scripts.items():
            result.append({
                "name":  name,
                "tags":  getattr(mod, "SCRIPT_TAGS", []),
                "ports": getattr(mod, "SCRIPT_PORTS", []),
                "desc":  (mod.__doc__ or "").strip().split("\n")[0][:60],
            })
        return sorted(result, key=lambda x: x["name"])

    def __len__(self): return len(self._scripts)


async def run_script(script, host: str, port: int,
                     timeout: float = 8.0) -> List[ScanResult]:
    """Run a single script against a host:port."""
    try:
        fn = getattr(script, "run", None)
        if not fn: return []
        result = await fn(host, port, timeout)
        if isinstance(result, list): return result
        if isinstance(result, ScanResult): return [result]
        return []
    except Exception as e:
        return []


async def run_scripts(
    host:       str,
    open_ports: List[int],
    script_dirs: Optional[List[str]] = None,
    names:      Optional[List[str]]  = None,
    tags:       Optional[List[str]]  = None,
    timeout:    float = 8.0,
    concurrency:int   = 16,
    verbose:    bool  = False,
) -> List[ScanResult]:
    """Run all matching scripts against all open ports."""
    registry = ScriptRegistry(script_dirs)
    results  = []
    sem      = asyncio.Semaphore(concurrency)
    tasks    = []

    for port in open_ports:
        scripts = registry.filter(tags=tags, ports=[port], names=names)
        for script in scripts:
            sname = getattr(script, "SCRIPT_NAME", "unknown")
            async def _run(s=script, p=port, sn=sname):
                async with sem:
                    if verbose:
                        print(f"\033[38;5;240m  [script] {sn} → {host}:{p}\033[0m")
                    r = await run_script(s, host, p, timeout)
                    results.extend(r)
                    for res in r:
                        print(f"  \033[38;5;196m[{res.severity.value}]\033[0m "
                              f"script:{sn} @ {host}:{p} — {res.detail[:80]}")
            tasks.append(_run())

    if tasks:
        await asyncio.gather(*tasks)
    return results


# ══════════════════════════════════════════════════════════════════════════════
# Built-in scripts — written inline, saved to scripts/ on first run
# ══════════════════════════════════════════════════════════════════════════════

BUILTIN_SCRIPTS = {}

# ── http_headers ──────────────────────────────────────────────────────────────
BUILTIN_SCRIPTS["http_headers"] = '''"""Grab and analyse HTTP response headers."""
import asyncio, ssl, urllib.request, urllib.error
SCRIPT_NAME  = "http_headers"
SCRIPT_PORTS = [80, 443, 8080, 8443, 8000, 3000]
SCRIPT_TAGS  = ["http", "safe", "discovery"]

from lightscan.core.engine import ScanResult, Severity

SECURITY_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy",
    "X-Frame-Options", "X-Content-Type-Options",
    "Referrer-Policy", "Permissions-Policy",
]

async def run(host, port, timeout=8.0):
    scheme = "https" if port in (443, 8443) else "http"
    url    = f"{scheme}://{host}:{port}/"
    loop   = asyncio.get_event_loop()
    def _fetch():
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={"User-Agent": "LightScan/2.0"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx if scheme=="https" else None) as r:
                return dict(r.info()), r.status
        except urllib.error.HTTPError as e:
            return dict(e.headers), e.code
        except Exception:
            return {}, 0
    headers, status = await loop.run_in_executor(None, _fetch)
    if not headers: return []
    results = []
    # Security header analysis
    missing = [h for h in SECURITY_HEADERS if h not in headers]
    if missing:
        results.append(ScanResult("script:http_headers", host, port, "missing_headers",
            Severity.MEDIUM,
            f"Missing security headers: {', '.join(missing[:3])}",
            {"missing": missing, "present": {k:v for k,v in headers.items() if k in SECURITY_HEADERS}}))
    # Server header disclosure
    server = headers.get("Server", "")
    if server:
        results.append(ScanResult("script:http_headers", host, port, "server_header",
            Severity.LOW, f"Server: {server}", {"server": server}))
    # Interesting headers
    for hdr in ["X-Powered-By", "X-AspNet-Version", "X-Generator"]:
        if hdr in headers:
            results.append(ScanResult("script:http_headers", host, port, "info_disclosure",
                Severity.LOW, f"{hdr}: {headers[hdr]}", {"header": hdr, "value": headers[hdr]}))
    return results
'''

# ── http_methods ──────────────────────────────────────────────────────────────
BUILTIN_SCRIPTS["http_methods"] = '''"""Test which HTTP methods are allowed on the server."""
import asyncio, ssl
SCRIPT_NAME  = "http_methods"
SCRIPT_PORTS = [80, 443, 8080, 8443]
SCRIPT_TAGS  = ["http", "safe", "discovery"]
from lightscan.core.engine import ScanResult, Severity

DANGEROUS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}

async def run(host, port, timeout=8.0):
    scheme = "https" if port in (443, 8443) else "http"
    loop   = asyncio.get_event_loop()
    allowed = []
    def _try(method):
        import urllib.request, urllib.error
        try:
            ctx = None
            if scheme == "https":
                import ssl; ctx = ssl.create_default_context()
                ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(f"{scheme}://{host}:{port}/",
                method=method, headers={"User-Agent": "LightScan/2.0"})
            with urllib.request.urlopen(req, timeout=3.0, **({"context":ctx} if ctx else {})) as r:
                return method, r.status
        except urllib.error.HTTPError as e:
            if e.code not in (405, 501): return method, e.code
        except Exception:
            pass
        return None
    results_raw = await asyncio.gather(*[
        loop.run_in_executor(None, _try, m)
        for m in ["GET","POST","PUT","DELETE","OPTIONS","TRACE","PATCH","HEAD"]
    ])
    allowed = [r[0] for r in results_raw if r]
    if not allowed: return []
    dangerous = [m for m in allowed if m in DANGEROUS]
    sev = Severity.HIGH if dangerous else Severity.INFO
    return [ScanResult("script:http_methods", host, port, "methods",
        sev, f"Allowed: {', '.join(allowed)}" + (f" | DANGEROUS: {', '.join(dangerous)}" if dangerous else ""),
        {"allowed": allowed, "dangerous": dangerous})]
'''

# ── tls_cert_info ─────────────────────────────────────────────────────────────
BUILTIN_SCRIPTS["tls_cert_info"] = '''"""Extract TLS certificate info and check expiry."""
import asyncio, ssl, socket
from datetime import datetime
SCRIPT_NAME  = "tls_cert_info"
SCRIPT_PORTS = [443, 8443, 993, 995, 636, 465, 587, 6443]
SCRIPT_TAGS  = ["tls", "ssl", "safe", "discovery"]
from lightscan.core.engine import ScanResult, Severity

async def run(host, port, timeout=8.0):
    loop = asyncio.get_event_loop()
    def _get_cert():
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert    = ssock.getpeercert()
                    version = ssock.version()
                    cipher  = ssock.cipher()
                    return cert, version, cipher
        except Exception:
            return None, None, None
    cert, version, cipher = await loop.run_in_executor(None, _get_cert)
    if not cert: return []
    results = []
    # Expiry check
    exp_str = cert.get("notAfter","")
    if exp_str:
        try:
            exp = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (exp - datetime.utcnow()).days
            sev = Severity.CRITICAL if days_left < 7 else Severity.HIGH if days_left < 30 else Severity.INFO
            results.append(ScanResult("script:tls_cert_info", host, port, "cert_expiry",
                sev, f"TLS cert expires in {days_left} days ({exp_str})",
                {"days_left": days_left, "expiry": exp_str, "version": version}))
        except Exception: pass
    # Weak TLS version
    if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
        results.append(ScanResult("script:tls_cert_info", host, port, "weak_tls",
            Severity.HIGH, f"Weak TLS version: {version}",
            {"version": version}))
    # Subject info
    subject = {}
    for field in cert.get("subject", []):
        for k, v in field: subject[k] = v
    cn = subject.get("commonName", "")
    if cn:
        results.append(ScanResult("script:tls_cert_info", host, port, "tls_cert",
            Severity.INFO, f"CN={cn} | {version} | {cipher[0] if cipher else ''}",
            {"cn": cn, "subject": subject, "version": version,
             "cipher": cipher[0] if cipher else ""}))
    return results
'''

# ── ssh_algorithms ────────────────────────────────────────────────────────────
BUILTIN_SCRIPTS["ssh_algorithms"] = '''"""Extract SSH supported algorithms and flag weak ones."""
import asyncio, socket
SCRIPT_NAME  = "ssh_algorithms"
SCRIPT_PORTS = [22, 2222]
SCRIPT_TAGS  = ["ssh", "safe", "discovery"]
from lightscan.core.engine import ScanResult, Severity

WEAK_ALGOS = ["arcfour","blowfish","cast128","3des","des","md5","sha1","diffie-hellman-group1","diffie-hellman-group-exchange-sha1"]

async def run(host, port, timeout=8.0):
    loop = asyncio.get_event_loop()
    def _get_kex():
        import struct, socket
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.settimeout(timeout)
            # Read banner
            banner = s.recv(256).decode("utf-8","replace").strip()
            # Send our banner
            s.send(b"SSH-2.0-LightScan_2.0_scanner\\r\\n")
            # Read KEX_INIT packet
            raw = b""
            while len(raw) < 4:
                raw += s.recv(4 - len(raw))
            pkt_len = struct.unpack("!I", raw[:4])[0]
            payload = b""
            while len(payload) < pkt_len:
                payload += s.recv(pkt_len - len(payload))
            s.close()
            # Parse KEX_INIT (skip padding and message type)
            pad_len = payload[0]
            msg = payload[1:]
            if msg[0] != 20: return banner, {}  # not KEXINIT
            # Skip cookie (16 bytes) + message type
            pos = 17
            lists = {}
            names = ["kex_algos","server_host_key_algos","enc_c2s","enc_s2c",
                     "mac_c2s","mac_s2c","comp_c2s","comp_s2c"]
            for name in names:
                if pos + 4 > len(msg): break
                slen = struct.unpack("!I", msg[pos:pos+4])[0]
                pos += 4
                if pos + slen > len(msg): break
                algos = msg[pos:pos+slen].decode("utf-8","replace").split(",")
                lists[name] = algos
                pos += slen
            return banner, lists
        except Exception:
            return "", {}
    banner, algos = await loop.run_in_executor(None, _get_kex)
    if not algos: return []
    results = []
    all_algos = []
    for v in algos.values(): all_algos.extend(v)
    weak = [a for a in all_algos if any(w in a.lower() for w in WEAK_ALGOS)]
    if weak:
        results.append(ScanResult("script:ssh_algorithms", host, port, "weak_algos",
            Severity.MEDIUM, f"Weak SSH algorithms: {', '.join(set(weak[:5]))}",
            {"weak": list(set(weak)), "all": algos}))
    results.append(ScanResult("script:ssh_algorithms", host, port, "ssh_kex",
        Severity.INFO,
        f"KEX: {', '.join(algos.get('kex_algos',['?'])[:3])}",
        {"algorithms": algos, "banner": banner}))
    return results
'''

# ── smb_os_discovery ──────────────────────────────────────────────────────────
BUILTIN_SCRIPTS["smb_os_discovery"] = '''"""Enumerate OS and hostname via SMB negotiate."""
import asyncio, struct, socket
SCRIPT_NAME  = "smb_os_discovery"
SCRIPT_PORTS = [445, 139]
SCRIPT_TAGS  = ["smb", "safe", "discovery"]
from lightscan.core.engine import ScanResult, Severity

SMB_NEG = bytes([
    0x00,0x00,0x00,0x54,0xff,0x53,0x4d,0x42,0x72,0x00,0x00,0x00,0x00,0x18,
    0x53,0xc8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xfe,
    0x00,0x00,0x00,0x00,0x00,0x31,0x00,0x02,0x4c,0x41,0x4e,0x4d,0x41,0x4e,
    0x31,0x2e,0x30,0x00,0x02,0x4c,0x4d,0x31,0x2e,0x32,0x58,0x30,0x30,0x32,
    0x00,0x02,0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00,
])

async def run(host, port, timeout=8.0):
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        w.write(SMB_NEG); await w.drain()
        resp = await asyncio.wait_for(r.read(1024), timeout=timeout)
        w.close()
        if len(resp) < 36: return []
        # Parse SMB response for OS string
        if resp[4:8] != b"\\xff\\x53\\x4d\\x42": return []
        os_info = resp[73:].decode("utf-16-le", errors="replace").rstrip("\\x00")
        parts = [p.strip() for p in os_info.split("\\x00") if p.strip()]
        os_str = " | ".join(parts[:3]) if parts else "Unknown"
        return [ScanResult("script:smb_os_discovery", host, port, "smb_os",
            Severity.INFO, f"SMB OS: {os_str}",
            {"os": os_str, "raw_parts": parts})]
    except Exception:
        return []
'''

# ── dns_recursion ──────────────────────────────────────────────────────────────
BUILTIN_SCRIPTS["dns_recursion"] = '''"""Test if DNS server allows open recursion."""
import asyncio, struct, socket, time
SCRIPT_NAME  = "dns_recursion"
SCRIPT_PORTS = [53]
SCRIPT_TAGS  = ["dns", "safe", "discovery"]
from lightscan.core.engine import ScanResult, Severity

def _build_dns_query(name):
    txid = int(time.time()) & 0xFFFF
    hdr  = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qname = b""
    for part in name.split("."):
        enc = part.encode()
        qname += struct.pack("B", len(enc)) + enc
    return hdr + qname + b"\\x00" + struct.pack("!HH", 1, 1)

async def run(host, port, timeout=8.0):
    loop = asyncio.get_event_loop()
    def _test():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            # Query an external domain — if it resolves, recursion is open
            q = _build_dns_query("scanme.nmap.org")
            s.sendto(q, (host, port))
            resp, _ = s.recvfrom(512)
            s.close()
            ancount = struct.unpack("!H", resp[6:8])[0]
            return ancount > 0
        except Exception:
            return False
    is_open = await loop.run_in_executor(None, _test)
    if is_open:
        return [ScanResult("script:dns_recursion", host, port, "open_recursion",
            Severity.MEDIUM, "DNS server allows open recursion (can be abused for DRDoS)",
            {"recursive": True})]
    return [ScanResult("script:dns_recursion", host, port, "recursion_disabled",
        Severity.INFO, "DNS recursion disabled", {"recursive": False})]
'''


def install_builtin_scripts(script_dir: Optional[str] = None) -> str:
    """Write built-in scripts to disk so ScriptRegistry can load them."""
    if script_dir:
        base = Path(script_dir)
    else:
        # Try package dir first, fall back to ~/.lightscan/scripts
        pkg_scripts = Path(__file__).parent.parent / "scripts"
        try:
            pkg_scripts.mkdir(parents=True, exist_ok=True)
            base = pkg_scripts
        except PermissionError:
            base = Path.home() / ".lightscan" / "scripts"

    categories = {
        "http":  ["http_headers", "http_methods"],
        "tls":   ["tls_cert_info"],
        "ssh":   ["ssh_algorithms"],
        "smb":   ["smb_os_discovery"],
        "dns":   ["dns_recursion"],
    }

    for cat, names in categories.items():
        cat_dir = base / cat
        cat_dir.mkdir(parents=True, exist_ok=True)
        (cat_dir / "__init__.py").touch()
        for name in names:
            script_path = cat_dir / f"{name}.py"
            if not script_path.exists() and name in BUILTIN_SCRIPTS:
                script_path.write_text(BUILTIN_SCRIPTS[name])

    return str(base)
