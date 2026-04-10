"""
LightScan v2.0 PHANTOM — IPv6 Scanner | Developer: Light
─────────────────────────────────────────────────────────────────────
Full IPv6 support:
  - Dual-stack target resolution (A + AAAA)
  - IPv6 TCP connect scan (no root needed)
  - IPv6 raw SYN scan (root, uses rawscan.py)
  - ICMPv6 neighbour discovery
  - Link-local and global scope handling
  - IPv6 address expansion/compression
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import struct
import sys
from typing import Dict, List, Optional, Tuple

from lightscan.core.engine import ScanResult, Severity
from lightscan.scan.portscan import SERVICE_MAP, CRIT_PORTS, HIGH_PORTS, PROBES


# ── IPv6 address utilities ────────────────────────────────────────────────────

def expand_ipv6(addr: str) -> str:
    """Expand a compressed IPv6 address to full form."""
    try:
        return str(ipaddress.IPv6Address(addr).exploded)
    except ValueError:
        return addr


def is_ipv6(addr: str) -> bool:
    try:
        ipaddress.IPv6Address(addr)
        return True
    except ValueError:
        return ":" in addr


def resolve_dual_stack(hostname: str) -> Dict[str, List[str]]:
    """
    Resolve a hostname to both IPv4 and IPv6 addresses.
    Returns {"ipv4": [...], "ipv6": [...]}
    """
    result: Dict[str, List[str]] = {"ipv4": [], "ipv6": []}
    try:
        infos = socket.getaddrinfo(hostname, None)
        for info in infos:
            af, _, _, _, addr = info
            if af == socket.AF_INET:
                ip = addr[0]
                if ip not in result["ipv4"]:
                    result["ipv4"].append(ip)
            elif af == socket.AF_INET6:
                ip = addr[0].split("%")[0]  # strip interface scope
                if ip not in result["ipv6"]:
                    result["ipv6"].append(ip)
    except Exception:
        pass
    return result


def ipv6_range(network: str) -> List[str]:
    """
    Generate IPs from an IPv6 CIDR range.
    Caps at 1024 hosts to avoid scanning /64 etc.
    """
    try:
        net = ipaddress.IPv6Network(network, strict=False)
        hosts = list(net.hosts())
        if len(hosts) > 1024:
            hosts = hosts[:1024]
        return [str(h) for h in hosts]
    except ValueError:
        return []


# ── IPv6 TCP connect scanner ──────────────────────────────────────────────────

async def tcp6_scan(host: str, port: int, timeout: float = 2.0,
                    grab_banner: bool = True) -> Optional[ScanResult]:
    """IPv6 TCP connect scan — no root required."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port,
                                    family=socket.AF_INET6),
            timeout=timeout)
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None

    banner = ""
    service = SERVICE_MAP.get(port, f"port/{port}")

    if grab_banner:
        try:
            probe = PROBES.get(port)
            if probe:
                writer.write(probe)
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=1.5)
            else:
                data = await asyncio.wait_for(reader.read(512), timeout=1.0)
            banner = data.decode("utf-8", errors="replace").strip()[:200]
        except Exception:
            pass

    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass

    if service.startswith("port/") and banner:
        bl = banner.lower()
        if "ssh"   in bl: service = "SSH"
        elif "ftp"  in bl: service = "FTP"
        elif "smtp" in bl: service = "SMTP"
        elif "http" in bl: service = "HTTP"

    sev = (Severity.CRITICAL if port in CRIT_PORTS
           else Severity.HIGH if port in HIGH_PORTS
           else Severity.INFO)
    detail = f"{service} [IPv6]" + (f" | {banner[:80]}" if banner else "")
    return ScanResult(
        "portscan-ipv6", host, port, "open", sev, detail,
        {"service": service, "banner": banner, "protocol": "IPv6"}
    )


async def scan_ipv6(
    host:        str,
    ports:       List[int],
    timeout:     float = 2.0,
    concurrency: int   = 256,
    grab_banner: bool  = True,
    verbose:     bool  = False,
) -> List[ScanResult]:
    """
    Full async IPv6 port scanner.
    Uses TCP connect (no root) or raw SYN (root).
    """
    # Resolve to IPv6
    if not is_ipv6(host):
        resolved = resolve_dual_stack(host)
        if not resolved["ipv6"]:
            print(f"\033[38;5;240m[!] No IPv6 address found for {host}\033[0m")
            return []
        ipv6_addr = resolved["ipv6"][0]
        print(f"\033[38;5;196m[IPv6]\033[0m {host} → {ipv6_addr}")
    else:
        ipv6_addr = host

    if os.geteuid() == 0:
        # Use raw SYN scanner for speed
        try:
            from lightscan.scan.rawscan import async_raw_scan
            return await async_raw_scan(
                ipv6_addr, ports, timing=4,
                grab_banner=grab_banner, verbose=verbose, ipv6=True)
        except Exception as e:
            if verbose:
                print(f"\033[38;5;240m[!] Raw IPv6 scan failed ({e}), "
                      f"falling back to connect scan\033[0m")

    # TCP connect fallback
    sem = asyncio.Semaphore(concurrency)
    results = []
    done = 0
    total = len(ports)

    print(f"\033[38;5;196m[IPv6]\033[0m {ipv6_addr} | {total} ports | connect scan")

    async def _one(port):
        nonlocal done
        async with sem:
            r = await tcp6_scan(ipv6_addr, port, timeout, grab_banner)
            done += 1
            if not verbose:
                pct = done / total * 100
                sys.stdout.write(
                    f"\r\033[38;5;196m[IPv6]\033[0m "
                    f"{done}/{total} ({pct:.1f}%)  "
                    f"open=\033[38;5;196m{len(results)}\033[0m"
                )
                sys.stdout.flush()
            if r:
                results.append(r)

    await asyncio.gather(*[_one(p) for p in ports])
    print(f"\n\033[38;5;240m[+] IPv6 scan done: {len(results)} open\033[0m")
    return results


# ── Dual-stack scanner ────────────────────────────────────────────────────────

async def dual_stack_scan(
    host:        str,
    ports:       List[int],
    timeout:     float = 2.0,
    concurrency: int   = 256,
    grab_banner: bool  = True,
    verbose:     bool  = False,
    prefer_ipv6: bool  = False,
) -> List[ScanResult]:
    """
    Scan both IPv4 and IPv6 addresses for a hostname.
    Returns combined results tagged by protocol.
    """
    resolved = resolve_dual_stack(host)
    results  = []

    v4_addrs = resolved["ipv4"]
    v6_addrs = resolved["ipv6"]

    if not v4_addrs and not v6_addrs:
        print(f"\033[38;5;196m[!]\033[0m Could not resolve {host}")
        return []

    scan_order = []
    if prefer_ipv6:
        scan_order = [(a, True) for a in v6_addrs] + [(a, False) for a in v4_addrs]
    else:
        scan_order = [(a, False) for a in v4_addrs] + [(a, True) for a in v6_addrs]

    for addr, is_v6 in scan_order:
        print(f"\033[38;5;196m[DUAL]\033[0m Scanning {'IPv6' if is_v6 else 'IPv4'}: {addr}")
        if is_v6:
            r = await scan_ipv6(addr, ports, timeout, concurrency, grab_banner, verbose)
        else:
            from lightscan.scan.rawscan import async_raw_scan
            from lightscan.scan.portscan import tcp_scan
            sem = asyncio.Semaphore(concurrency)
            async def _v4(p):
                async with sem:
                    return await tcp_scan(addr, p, timeout, grab_banner)
            raw = await asyncio.gather(*[_v4(p) for p in ports])
            r = [x for x in raw if x]
        results.extend(r)

    return results


# ── ICMPv6 ping sweep ─────────────────────────────────────────────────────────

async def icmpv6_ping(host: str, timeout: float = 2.0) -> bool:
    """
    Send ICMPv6 echo request. Returns True if host responds.
    Requires root for raw socket.
    """
    if os.geteuid() != 0:
        # Fallback: try TCP connect to common ports
        for port in [80, 443, 22]:
            try:
                _, w = await asyncio.wait_for(
                    asyncio.open_connection(host, port,
                                            family=socket.AF_INET6),
                    timeout=1.0)
                w.close()
                return True
            except Exception:
                continue
        return False

    def _ping():
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW,
                                  socket.getprotobyname("ipv6-icmp"))
            sock.settimeout(timeout)

            # ICMPv6 Echo Request: type=128, code=0
            ident = os.getpid() & 0xFFFF
            seq   = 1
            data  = b"LightScanPHANTOM"
            hdr   = struct.pack("!BBHHH", 128, 0, 0, ident, seq)
            # Checksum
            raw   = hdr + data
            csum  = 0
            for i in range(0, len(raw), 2):
                if i + 1 < len(raw):
                    csum += (raw[i] << 8) + raw[i+1]
                else:
                    csum += raw[i] << 8
            csum  = (csum >> 16) + (csum & 0xFFFF)
            csum += csum >> 16
            csum  = ~csum & 0xFFFF
            hdr   = struct.pack("!BBHHH", 128, 0, csum, ident, seq)

            sock.sendto(hdr + data, (host, 0, 0, 0))

            while True:
                try:
                    resp, _ = sock.recvfrom(1024)
                    if len(resp) >= 8 and resp[0] == 129:  # Echo Reply
                        return True
                except socket.timeout:
                    return False
        except Exception:
            return False
        finally:
            try: sock.close()
            except: pass

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _ping)


async def ipv6_host_discovery(
    network: str,
    timeout: float = 1.0,
    max_hosts: int = 256,
) -> List[str]:
    """
    Discover live IPv6 hosts in a subnet via ICMPv6 ping sweep.
    """
    hosts = ipv6_range(network)[:max_hosts]
    if not hosts:
        return []

    print(f"\033[38;5;196m[IPv6-DISC]\033[0m Pinging {len(hosts)} hosts in {network}")
    live = []
    sem  = asyncio.Semaphore(50)

    async def _check(h):
        async with sem:
            if await icmpv6_ping(h, timeout):
                live.append(h)

    await asyncio.gather(*[_check(h) for h in hosts])
    print(f"\033[38;5;240m[+] Found {len(live)} live IPv6 hosts\033[0m")
    return live
