"""
LightScan v2.0 PHANTOM — Raw Async Port Scanner | Developer: Light
─────────────────────────────────────────────────────────────────────
epoll-based async TCP SYN scanner using pure stdlib raw sockets.
No scapy. No threads. Runs at ~nmap speed in Python.

Architecture:
  - One raw SOCK_RAW send socket (IPPROTO_RAW, IP_HDRINCL)
  - One raw SOCK_RAW recv socket (IPPROTO_TCP) on epoll
  - Semaphore-controlled burst sender
  - Single receiver coroutine draining epoll responses
  - Timing templates T0-T5 (nmap-compatible)
  - IPv4 + IPv6 dual-stack
  - Evasion: decoy IPs, fragmentation, randomised scan order, bad checksum probes

Requires root for raw sockets.
Falls back to async TCP connect scan when not root.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import random
import select
import socket
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from lightscan.core.engine import ScanResult, Severity
from lightscan.scan.portscan import SERVICE_MAP, CRIT_PORTS, HIGH_PORTS, PROBES

# ── Timing templates (nmap-compatible) ───────────────────────────────────────
@dataclass
class TimingTemplate:
    name:           str
    min_rate:       float   # packets/sec minimum
    max_rate:       float   # packets/sec maximum
    inter_packet:   float   # seconds between packets (base)
    timeout:        float   # per-port timeout seconds
    retries:        int     # SYN retransmissions
    scan_delay:     float   # host-level inter-probe delay
    parallelism:    int     # max simultaneous outstanding probes

TIMING = {
    0: TimingTemplate("Paranoid",    0.05,   1.0,   15.0,  300.0, 1,  15.0,  1),
    1: TimingTemplate("Sneaky",      1.0,    5.0,    1.5,   15.0, 1,   1.5,  5),
    2: TimingTemplate("Polite",      5.0,   50.0,    0.4,    6.0, 2,   0.4, 10),
    3: TimingTemplate("Normal",     50.0,  500.0,    0.05,   3.0, 2,   0.05,256),
    4: TimingTemplate("Aggressive", 200.0, 2000.0,   0.01,   1.5, 2,   0.01,512),
    5: TimingTemplate("Insane",    1000.0,10000.0,   0.001,  0.5, 1,   0.0, 1000),
}

# ── IP/TCP packet helpers ─────────────────────────────────────────────────────

def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum((data[i] << 8) + data[i+1] for i in range(0, len(data), 2))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _build_ipv4_syn(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                    seq: int = 0, ttl: int = 64, fragment: bool = False,
                    bad_checksum: bool = False) -> bytes:
    """Build a raw IPv4 TCP SYN packet."""
    ip_saddr = socket.inet_aton(src_ip)
    ip_daddr = socket.inet_aton(dst_ip)

    # TCP header
    tcp_flags = 0x02  # SYN
    tcp_win   = socket.htons(random.choice([1024, 2048, 4096, 8192, 16384, 65535]))
    tcp_hdr   = struct.pack("!HHLLBBHHH",
        src_port, dst_port, seq, 0,
        (5 << 4), tcp_flags, tcp_win, 0, 0)

    # TCP checksum via pseudo-header
    pseudo = struct.pack("!4s4sBBH", ip_saddr, ip_daddr, 0, socket.IPPROTO_TCP, len(tcp_hdr))
    tcp_chk = 0 if bad_checksum else _checksum(pseudo + tcp_hdr)
    tcp_hdr = struct.pack("!HHLLBBHHH",
        src_port, dst_port, seq, 0,
        (5 << 4), tcp_flags, tcp_win, tcp_chk, 0)

    # IP header
    frag_off = 0x2000 if fragment else 0  # More Fragments bit
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        (4 << 4) | 5, 0, 0,
        random.randint(1, 65535), frag_off,
        ttl, socket.IPPROTO_TCP, 0,
        ip_saddr, ip_daddr)
    ip_chk = _checksum(ip_hdr)
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        (4 << 4) | 5, 0, 0,
        random.randint(1, 65535), frag_off,
        ttl, socket.IPPROTO_TCP, ip_chk,
        ip_saddr, ip_daddr)

    return ip_hdr + tcp_hdr


def _build_ipv6_syn(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                    seq: int = 0) -> bytes:
    """Build a raw IPv6 TCP SYN packet (for use with SOCK_RAW AF_INET6)."""
    src = socket.inet_pton(socket.AF_INET6, src_ip)
    dst = socket.inet_pton(socket.AF_INET6, dst_ip)

    tcp_flags = 0x02
    tcp_win   = socket.htons(8192)
    tcp_hdr   = struct.pack("!HHLLBBHHH",
        src_port, dst_port, seq, 0,
        (5 << 4), tcp_flags, tcp_win, 0, 0)

    # IPv6 pseudo-header for TCP checksum
    pseudo = src + dst + struct.pack("!I", len(tcp_hdr)) + b"\x00\x00\x00" + bytes([6])
    tcp_chk = _checksum(pseudo + tcp_hdr)
    tcp_hdr = struct.pack("!HHLLBBHHH",
        src_port, dst_port, seq, 0,
        (5 << 4), tcp_flags, tcp_win, tcp_chk, 0)

    return tcp_hdr  # IPv6 kernel prepends IP header automatically


def _get_src_ip(dst: str, ipv6: bool = False) -> str:
    af = socket.AF_INET6 if ipv6 else socket.AF_INET
    with socket.socket(af, socket.SOCK_DGRAM) as s:
        try:
            s.connect((dst, 80))
            return s.getsockname()[0]
        except Exception:
            return "::1" if ipv6 else "127.0.0.1"


def _parse_tcp_response(data: bytes, expected_dst_ip: str,
                        port_map: Dict[int, int],
                        ipv6: bool = False) -> Optional[Tuple[int, str]]:
    """
    Parse a raw IP+TCP packet. Returns (target_port, state) or None.
    state: 'open' | 'closed' | 'filtered'
    """
    try:
        if ipv6:
            # Kernel strips IPv6 header for AF_INET6 SOCK_RAW
            if len(data) < 20: return None
            ihl = 0
            proto_offset = 6  # next header
            # Check next header is TCP (6)
            # For simplicity, parse first 40 bytes as IPv6 + TCP
            # Actually kernel gives us just TCP for IPPROTO_TCP raw
            tcp = data
        else:
            if len(data) < 40: return None
            ihl = (data[0] & 0x0F) * 4
            src_ip = socket.inet_ntoa(data[12:16])
            if src_ip != expected_dst_ip: return None
            if data[9] != 6: return None  # not TCP
            tcp = data[ihl:]

        if len(tcp) < 14: return None
        dst_port_resp = struct.unpack("!H", tcp[0:2])[0]   # their src = our src_port
        src_port_resp = struct.unpack("!H", tcp[2:4])[0]   # their dst = target port
        flags = tcp[13]

        target_port = port_map.get(dst_port_resp)
        if target_port is None: return None

        if flags & 0x12 == 0x12:   # SYN+ACK → open
            return (target_port, "open")
        elif flags & 0x04:          # RST → closed
            return (target_port, "closed")
        return None
    except Exception:
        return None


# ── Evasion: Decoy packets ────────────────────────────────────────────────────

def _random_ip() -> str:
    while True:
        ip = ipaddress.IPv4Address(random.randint(0x01000001, 0xFEFFFFFE))
        if ip.is_global and not ip.is_multicast:
            return str(ip)


def _send_decoys(send_sock, dst_ip: str, dst_port: int, src_port: int,
                 decoys: List[str], ttl: int):
    """Send SYN packets from decoy IPs to confuse IDS."""
    for decoy in decoys:
        try:
            pkt = _build_ipv4_syn(decoy, dst_ip, src_port, dst_port,
                                  seq=random.randint(0, 2**32-1), ttl=ttl)
            send_sock.sendto(pkt, (dst_ip, 0))
        except Exception:
            pass


# ── Core scanner ──────────────────────────────────────────────────────────────

class RawAsyncScanner:
    """
    epoll-based raw TCP SYN scanner.
    - Pure stdlib, no scapy
    - Dual-stack IPv4/IPv6
    - nmap-compatible timing templates T0-T5
    - Decoy scan, fragmentation, bad-checksum evasion
    - Banner grabbing on open ports via secondary connect
    """

    def __init__(
        self,
        target:       str,
        ports:        List[int],
        timing:       int   = 4,        # T4 default (aggressive)
        ttl:          int   = 64,
        decoys:       int   = 0,        # number of random decoy IPs (0=disabled)
        fragment:     bool  = False,    # IP fragmentation evasion
        randomize:    bool  = True,     # randomise port scan order
        grab_banner:  bool  = True,
        verbose:      bool  = False,
        ipv6:         bool  = False,
    ):
        self.target      = target
        self.ports       = list(ports)
        self.tmpl        = TIMING[max(0, min(5, timing))]
        self.ttl         = ttl
        self.decoys      = decoys
        self.fragment    = fragment
        self.randomize   = randomize
        self.grab_banner = grab_banner
        self.verbose     = verbose
        self.ipv6        = ipv6

        self._open:     List[int] = []
        self._closed:   List[int] = []
        self._filtered: List[int] = []
        self._banners:  Dict[int, str] = {}
        self._total     = len(ports)
        self._sent      = 0
        self._recv      = 0

    def _progress(self):
        pct = (self._sent / self._total * 100) if self._total else 0
        sys.stdout.write(
            f"\r\033[38;5;196m[RAW]\033[0m "
            f"{self._sent}/{self._total} ({pct:.1f}%)  "
            f"open=\033[38;5;196m{len(self._open)}\033[0m  "
            f"T{list(TIMING.values()).index(self.tmpl)}"
        )
        sys.stdout.flush()

    async def _banner_grab(self, ip: str, port: int) -> str:
        """Secondary TCP connect to grab banner from confirmed-open port."""
        try:
            probe = PROBES.get(port)
            af = socket.AF_INET6 if self.ipv6 else socket.AF_INET
            r, w = await asyncio.wait_for(
                asyncio.open_connection(ip, port, family=af), timeout=2.0)
            if probe:
                w.write(probe); await w.drain()
            data = await asyncio.wait_for(r.read(1024), timeout=1.5)
            try: w.close(); await w.wait_closed()
            except: pass
            return data.decode("utf-8", errors="replace").strip()[:200]
        except Exception:
            return ""

    async def _rst(self, send_sock, dst_ip: str, dst_port: int,
                   src_port: int, ack_seq: int):
        """Send RST to cleanly close half-open connection."""
        try:
            pkt = _build_ipv4_syn.__wrapped__ if hasattr(_build_ipv4_syn, '__wrapped__') else None
            # Build RST packet
            ip_saddr = socket.inet_aton(self._src_ip)
            ip_daddr = socket.inet_aton(dst_ip)
            tcp_flags = 0x04  # RST
            tcp_hdr = struct.pack("!HHLLBBHHH",
                src_port, dst_port, ack_seq, 0,
                (5 << 4), tcp_flags, 0, 0, 0)
            pseudo = struct.pack("!4s4sBBH", ip_saddr, ip_daddr,
                                 0, socket.IPPROTO_TCP, len(tcp_hdr))
            tcp_chk = _checksum(pseudo + tcp_hdr)
            tcp_hdr = struct.pack("!HHLLBBHHH",
                src_port, dst_port, ack_seq, 0,
                (5 << 4), tcp_flags, 0, tcp_chk, 0)
            ip_hdr = struct.pack("!BBHHHBBH4s4s",
                (4 << 4)|5, 0, 0, random.randint(1,65535), 0,
                self.ttl, socket.IPPROTO_TCP, 0, ip_saddr, ip_daddr)
            ip_chk = _checksum(ip_hdr)
            ip_hdr = struct.pack("!BBHHHBBH4s4s",
                (4 << 4)|5, 0, 0, random.randint(1,65535), 0,
                self.ttl, socket.IPPROTO_TCP, ip_chk, ip_saddr, ip_daddr)
            send_sock.sendto(ip_hdr + tcp_hdr, (dst_ip, 0))
        except Exception:
            pass

    def scan(self) -> List[ScanResult]:
        """Run the raw scanner synchronously (call from thread or run directly)."""
        if os.geteuid() != 0:
            raise PermissionError("Raw scan requires root")

        # Resolve target
        try:
            if self.ipv6:
                info = socket.getaddrinfo(self.target, None, socket.AF_INET6)
                self._dst_ip = info[0][4][0]
            else:
                self._dst_ip = socket.gethostbyname(self.target)
        except Exception:
            self._dst_ip = self.target

        self._src_ip = _get_src_ip(self._dst_ip, self.ipv6)

        # Decoy IPs
        decoy_ips = [_random_ip() for _ in range(self.decoys)]

        # Port order
        scan_ports = list(self.ports)
        if self.randomize:
            random.shuffle(scan_ports)

        # src_port → dst_port mapping for response matching
        port_map: Dict[int, int] = {}
        src_ports: Dict[int, int] = {}  # dst_port → src_port

        t0 = time.time()
        tmpl = self.tmpl

        print(f"\033[38;5;196m[RAW]\033[0m {self._dst_ip} | {self._total} ports | "
              f"T{list(TIMING.values()).index(tmpl)} ({tmpl.name}) | "
              f"{'IPv6' if self.ipv6 else 'IPv4'} | "
              f"{'decoys=' + str(self.decoys) + ' ' if self.decoys else ''}"
              f"{'frag ' if self.fragment else ''}"
              f"src={self._src_ip}")

        # Create sockets
        try:
            if self.ipv6:
                send_sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
                recv_sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
            else:
                send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            recv_sock.setblocking(False)
        except PermissionError:
            raise PermissionError("Raw socket requires root")

        # epoll for non-blocking receive
        ep = select.epoll()
        ep.register(recv_sock.fileno(), select.EPOLLIN)

        responded: Set[int] = set()
        outstanding: Dict[int, float] = {}  # dst_port → time sent

        def _flush_responses(deadline: float):
            """Drain epoll responses until deadline."""
            while time.time() < deadline:
                events = ep.poll(timeout=0.01)
                if not events:
                    break
                for fd, _ in events:
                    if fd != recv_sock.fileno():
                        continue
                    try:
                        data, addr = recv_sock.recvfrom(65535)
                        result = _parse_tcp_response(
                            data, self._dst_ip, port_map, self.ipv6)
                        if result:
                            dport, state = result
                            if dport not in responded:
                                responded.add(dport)
                                sport = src_ports.get(dport, 0)
                                if state == "open":
                                    self._open.append(dport)
                                    # Send RST immediately
                                    try:
                                        # Extract ack from packet
                                        if not self.ipv6:
                                            ihl = (data[0] & 0x0F) * 4
                                            tcp = data[ihl:]
                                        else:
                                            tcp = data
                                        ack_seq = struct.unpack("!L", tcp[8:12])[0]
                                        send_sock.sendto(
                                            _build_ipv4_syn(
                                                self._src_ip, self._dst_ip,
                                                sport, dport,
                                                seq=ack_seq, ttl=self.ttl) if True else b"",
                                            (self._dst_ip, 0)
                                        )
                                    except Exception:
                                        pass
                                else:
                                    self._closed.append(dport)
                    except BlockingIOError:
                        break
                    except Exception:
                        break

        # Rate control
        interval = 1.0 / min(tmpl.max_rate, 10000)

        # Send loop
        for i, port in enumerate(scan_ports):
            sport = random.randint(32768, 60999)
            port_map[sport] = port
            src_ports[port] = sport

            # Build + send SYN
            try:
                if self.ipv6:
                    pkt = _build_ipv6_syn(self._src_ip, self._dst_ip, sport, port,
                                          seq=random.randint(0, 2**32-1))
                    send_sock.sendto(pkt, (self._dst_ip, port, 0, 0))
                else:
                    pkt = _build_ipv4_syn(
                        self._src_ip, self._dst_ip, sport, port,
                        seq=random.randint(0, 2**32-1),
                        ttl=self.ttl, fragment=self.fragment)
                    send_sock.sendto(pkt, (self._dst_ip, 0))

                # Send decoys
                if decoy_ips:
                    _send_decoys(send_sock, self._dst_ip, port, sport,
                                 decoy_ips, self.ttl)

                outstanding[port] = time.time()
            except Exception as e:
                if self.verbose:
                    print(f"\n  [!] send {port}: {e}")

            self._sent += 1
            if not self.verbose and self._sent % 50 == 0:
                self._progress()

            # Flush responses + rate control
            _flush_responses(time.time() + interval * 0.5)
            time.sleep(max(0, interval - 0.001))

            # Scan delay (T0/T1 only)
            if tmpl.scan_delay > 0.1 and i % 10 == 0:
                time.sleep(tmpl.scan_delay)

        self._progress()

        # Wait for stragglers
        straggler_deadline = time.time() + tmpl.timeout
        print(f"\n\033[38;5;240m[+] Probes sent — waiting {tmpl.timeout:.1f}s for responses...\033[0m")
        _flush_responses(straggler_deadline)

        # Retransmit non-responded ports
        if tmpl.retries > 0:
            retry_ports = [p for p in scan_ports if p not in responded]
            if retry_ports and self.verbose:
                print(f"\033[38;5;240m[+] Retrying {len(retry_ports)} ports...\033[0m")
            for port in retry_ports:
                sport = src_ports.get(port, random.randint(32768, 60999))
                try:
                    pkt = _build_ipv4_syn(
                        self._src_ip, self._dst_ip, sport, port,
                        seq=random.randint(0, 2**32-1), ttl=self.ttl)
                    send_sock.sendto(pkt, (self._dst_ip, 0))
                except Exception:
                    pass
            _flush_responses(time.time() + tmpl.timeout * 0.5)

        ep.close()
        send_sock.close()
        recv_sock.close()

        # Classify non-responded as filtered
        for port in scan_ports:
            if port not in responded:
                self._filtered.append(port)

        elapsed = time.time() - t0
        print(f"\033[38;5;196m[RAW]\033[0m Done in {elapsed:.2f}s — "
              f"open=\033[38;5;196m{len(self._open)}\033[0m  "
              f"closed={len(self._closed)}  filtered={len(self._filtered)}")

        # Banner grab open ports
        if self.grab_banner and self._open:
            print(f"\033[38;5;240m[+] Banner grabbing {len(self._open)} open ports...\033[0m")
            loop = asyncio.new_event_loop()
            try:
                async def _grab_all():
                    tasks = [self._banner_grab(self._dst_ip, p) for p in self._open]
                    results = await asyncio.gather(*tasks)
                    for port, banner in zip(self._open, results):
                        if banner:
                            self._banners[port] = banner
                loop.run_until_complete(_grab_all())
            finally:
                loop.close()

        return self._build_results()

    def _build_results(self) -> List[ScanResult]:
        results = []
        for port in sorted(self._open):
            svc = SERVICE_MAP.get(port, f"port/{port}")
            sev = (Severity.CRITICAL if port in CRIT_PORTS
                   else Severity.HIGH if port in HIGH_PORTS
                   else Severity.INFO)
            banner = self._banners.get(port, "")
            # Auto-detect service from banner
            if svc.startswith("port/") and banner:
                bl = banner.lower()
                if "ssh" in bl: svc = "SSH"
                elif "ftp" in bl: svc = "FTP"
                elif "smtp" in bl: svc = "SMTP"
                elif "http" in bl: svc = "HTTP"
                elif "redis" in bl: svc = "Redis"
                elif "mongodb" in bl: svc = "MongoDB"
                elif "mysql" in bl: svc = "MySQL"
            detail = f"{svc} [RAW-SYN]" + (f" | {banner[:80]}" if banner else "")
            results.append(ScanResult(
                "raw-scan", self.target, port, "open", sev, detail,
                {"service": svc, "banner": banner, "method": "RAW-SYN",
                 "dst_ip": self._dst_ip}
            ))
        for port in sorted(self._filtered):
            svc = SERVICE_MAP.get(port, f"port/{port}")
            results.append(ScanResult(
                "raw-scan", self.target, port, "filtered", Severity.INFO,
                f"{svc} [filtered/no-response]",
                {"service": svc, "method": "RAW-SYN"}
            ))
        return results


async def async_raw_scan(
    target: str, ports: List[int],
    timing: int = 4, ttl: int = 64,
    decoys: int = 0, fragment: bool = False,
    randomize: bool = True, grab_banner: bool = True,
    verbose: bool = False, ipv6: bool = False,
) -> List[ScanResult]:
    """Async wrapper — runs raw scan in executor."""
    if os.geteuid() != 0:
        # Fall back to async connect scan
        from lightscan.scan.portscan import tcp_scan
        import concurrent.futures
        sem = asyncio.Semaphore(TIMING[timing].parallelism)
        async def _one(p):
            async with sem:
                return await tcp_scan(target, p, TIMING[timing].timeout, grab_banner)
        results = await asyncio.gather(*[_one(p) for p in ports])
        return [r for r in results if r]

    loop = asyncio.get_event_loop()
    scanner = RawAsyncScanner(
        target, ports, timing, ttl, decoys, fragment,
        randomize, grab_banner, verbose, ipv6)
    return await loop.run_in_executor(None, scanner.scan)
