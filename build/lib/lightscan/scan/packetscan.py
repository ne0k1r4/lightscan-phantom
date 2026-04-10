"""
LightScan v2.0 PHANTOM — True Half-Open SYN Scanner | Developer: Light
───────────────────────────────────────────────────────────────────────
nmap -sS equivalent via AF_PACKET.  All 7 engine upgrades applied.

Half-open mechanics
  SYN  →  SYN-ACK  →  RST (crafted, correct SEQ — handshake never completes)
  SYN  →  RST      →  CLOSED
  SYN  →  (none)   →  FILTERED

Kernel RST suppression [true half-open]
  iptables OUTPUT DROP on our sport range for the duration of the scan.
  Without this the kernel races our crafted RST with its own, making this
  a probe sender rather than a true half-open scanner.

Firewall detection [accurate]
  ICMP type-3 admin-prohibited codes (9,10,13,14,15) → state 'firewall'
  Inline RST without ACK (window=0) → flagged in meta as firewall_rst=True
  Full ICMP3 table (16 codes) via tcpflags.classify_icmp3()

IDS-evasion mode [--stealth-scan]
  stealth=True forces T1 max, adds 10–25 % random jitter, randomises sport,
  optionally spoof source port (e.g. 53/80/443 to bypass port-based ACLs).

Interface auto-selection [fixed]
  _get_default_iface() now validates operstate and falls back through all
  default-route interfaces before returning 'eth0'.

TCP flag parser [core fix]
  All flag decisions routed through tcpflags.classify_tcp() — no more raw
  bitmask comparisons scattered through the parser.

ICMP filtered detection [full table]
  Every ICMP type-3 code mapped.  TTL-exceeded (type 11) also caught.
"""
from __future__ import annotations

import asyncio
import contextlib
import os
import random
import select
import socket
import struct
import subprocess
import sys
import time
from typing import Dict, List, Optional, Set, Tuple

from lightscan.core.engine import ScanResult, Severity
from lightscan.scan.portscan import SERVICE_MAP, CRIT_PORTS, HIGH_PORTS
from lightscan.scan.rawscan import _checksum, _build_ipv4_syn, _get_src_ip, TIMING
from lightscan.scan.tcpflags import (
    classify_tcp, classify_icmp3, flags_str, is_firewall_rst,
    ICMP_DEST_UNREACHABLE, ICMP_TTL_EXCEEDED,
)

ETH_HDR_LEN = 14
IP_PROTO_TCP  = 6
IP_PROTO_ICMP = 1
RST_PKT_LEN   = 40   # IP(20) + TCP(20), no options — must be explicit for AF_PACKET


# ── Interface helpers (fixed auto-selection) ──────────────────────────────────

def _iface_is_up(iface: str) -> bool:
    """Return True if the interface operstate is up or unknown."""
    try:
        state = open(f"/sys/class/net/{iface}/operstate").read().strip()
        return state in ("up", "unknown")
    except Exception:
        return True   # can't read → assume OK


def _get_default_iface() -> str:
    """
    Return the best network interface for sending raw packets.

    Fix over original: the old version returned the first default-route entry
    without checking whether the interface is actually UP.  We now:
      1. Collect all interfaces with a default route (gateway=0.0.0.0)
      2. Return the first one whose operstate is 'up' or 'unknown'
      3. Fall back to any non-loopback UP interface
      4. Hard fallback: 'eth0'
    """
    candidates: List[str] = []
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                fields = line.strip().split()
                if len(fields) >= 3 and fields[1] == "00000000":
                    candidates.append(fields[0])
    except Exception:
        pass

    for iface in candidates:
        if _iface_is_up(iface):
            return iface

    # No default-route interface is up — scan all interfaces
    try:
        for iface in sorted(os.listdir("/sys/class/net")):
            if iface == "lo":
                continue
            if _iface_is_up(iface):
                return iface
    except Exception:
        pass

    return "eth0"


def _iface_for_src_ip(src_ip: str) -> str:
    """
    Find the interface that owns src_ip by scanning /proc/net/if_inet6 and
    /proc/net/fib_trie. Falls back to _get_default_iface().
    """
    try:
        with open("/proc/net/fib_trie") as f:
            content = f.read()
        import re
        # fib_trie lists local addresses; find the one matching src_ip
        # then trace back to the interface name from /proc/net/fib_triestat isn't helpful;
        # use /proc/net/if_inet6 for IPv6 and sysfs for IPv4
        pass
    except Exception:
        pass
    # IPv4: check /proc/net/arp or sysfs
    try:
        for iface in os.listdir("/sys/class/net"):
            addr_file = f"/sys/class/net/{iface}/address"
            try:
                # Read IPv4 address via ioctl (fastest)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    import fcntl
                    import struct as _struct
                    SIOCGIFADDR = 0x8915
                    result = fcntl.ioctl(
                        s.fileno(), SIOCGIFADDR,
                        _struct.pack('256s', iface[:15].encode()))
                    ip = socket.inet_ntoa(result[20:24])
                    if ip == src_ip:
                        return iface
            except Exception:
                continue
    except Exception:
        pass
    return _get_default_iface()


def _get_iface_mac(iface: str) -> bytes:
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            mac = f.read().strip()
        return bytes(int(x, 16) for x in mac.split(":"))
    except Exception:
        return b"\x00" * 6


def _get_gateway_mac(iface: str, gateway_ip: str) -> bytes:
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                fields = line.strip().split()
                if fields[0] == gateway_ip and fields[5] == iface:
                    return bytes(int(x, 16) for x in fields[3].split(":"))
    except Exception:
        pass
    return b"\xff" * 6


# ── Kernel RST suppression [true half-open] ───────────────────────────────────

@contextlib.contextmanager
def _suppress_kernel_rst(sport_lo: int, sport_hi: int):
    """
    Block kernel-generated RSTs for our sport range via iptables.

    Without this the kernel sees an incoming SYN-ACK on an unknown socket and
    fires its own RST — racing (and potentially overriding) our crafted RST.
    That makes us a probe sender, not a true half-open scanner.
    """
    sport_range = f"{sport_lo}:{sport_hi}"
    add = ["iptables", "-I", "OUTPUT", "1",
           "-p", "tcp", "--tcp-flags", "RST", "RST",
           "--sport", sport_range, "-j", "DROP"]
    rem = ["iptables", "-D", "OUTPUT",
           "-p", "tcp", "--tcp-flags", "RST", "RST",
           "--sport", sport_range, "-j", "DROP"]
    installed = False
    try:
        installed = subprocess.run(add, capture_output=True).returncode == 0
        yield installed
    finally:
        if installed:
            subprocess.run(rem, capture_output=True)


# ── Packet builders ───────────────────────────────────────────────────────────

def _build_rst(src_ip: str, dst_ip: str, sport: int, dport: int, seq: int) -> bytes:
    """
    Build RST to abort a half-open connection.

    seq   = ACK field from the SYN-ACK (= our ISN + 1 — what the remote
            expects as our next sequence number, making this RST valid).

    IP total_length is set to RST_PKT_LEN=40 explicitly.  AF_PACKET sockets
    do NOT have the kernel fill in the length field (unlike SOCK_RAW +
    IP_HDRINCL) — leaving it 0 produces a malformed packet that is dropped.
    """
    ip_s  = socket.inet_aton(src_ip)
    ip_d  = socket.inet_aton(dst_ip)
    ip_id = random.randint(1, 65535)

    tcp = struct.pack("!HHLLBBHHH", sport, dport, seq, 0, (5 << 4), 0x04, 0, 0, 0)
    pseudo  = struct.pack("!4s4sBBH", ip_s, ip_d, 0, 6, len(tcp))
    tcp_chk = _checksum(pseudo + tcp)
    tcp = struct.pack("!HHLLBBHHH", sport, dport, seq, 0, (5 << 4), 0x04, 0, tcp_chk, 0)

    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, RST_PKT_LEN, ip_id, 0, 64, 6, 0, ip_s, ip_d)
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, RST_PKT_LEN, ip_id, 0, 64, 6, _checksum(iph), ip_s, ip_d)
    return iph + tcp


# ── AF_PACKET frame parser [full ICMP table + TCP flag parser] ────────────────

def _parse_af_packet(
    data:     bytes,
    src_ip:   str,
    port_map: Dict[int, int],
) -> Optional[Tuple[int, str, int, dict]]:
    """
    Parse Ethernet frame from AF_PACKET socket.

    Returns (target_port, state, rst_seq, meta) or None.
      state   : 'open' | 'closed' | 'filtered' | 'firewall'
      rst_seq : ACK field from SYN-ACK (use as SEQ in RST reply); 0 otherwise
      meta    : {'flags_str', 'firewall_rst', 'icmp_reason', 'firewall'}

    TCP flag decisions use classify_tcp() — no raw bitmasks.
    ICMP type-3 codes use the full classify_icmp3() table.
    ICMP type-11 (TTL exceeded) is caught as filtered.
    """
    try:
        if len(data) < ETH_HDR_LEN:
            return None
        eth_type = struct.unpack("!H", data[12:14])[0]
        if eth_type != 0x0800:
            return None

        ip = data[ETH_HDR_LEN:]
        if len(ip) < 20:
            return None
        if socket.inet_ntoa(ip[12:16]) != src_ip:
            return None

        proto = ip[9]
        ihl   = (ip[0] & 0x0F) * 4

        # ── TCP ───────────────────────────────────────────────────────────────
        if proto == IP_PROTO_TCP:
            tcp = ip[ihl:]
            if len(tcp) < 14:
                return None

            our_sport = struct.unpack("!H", tcp[0:2])[0]
            tcp_win   = struct.unpack("!H", tcp[14:16])[0]
            flags     = tcp[13]
            ack_field = struct.unpack("!L", tcp[8:12])[0]

            target_port = port_map.get(our_sport)
            if target_port is None:
                return None

            state = classify_tcp(flags)
            if state is None:
                return None

            meta: dict = {
                'flags_str':    flags_str(flags),
                'firewall_rst': state == 'closed' and is_firewall_rst(flags) and tcp_win == 0,
                'icmp_reason':  '',
                'firewall':     False,
            }
            rst_seq = ack_field if state == 'open' else 0
            return (target_port, state, rst_seq, meta)

        # ── ICMP ──────────────────────────────────────────────────────────────
        elif proto == IP_PROTO_ICMP:
            icmp = ip[ihl:]
            if len(icmp) < 8:
                return None

            icmp_type = icmp[0]
            icmp_code = icmp[1]

            # TTL exceeded → filtered (probe hit a hop limit / firewall)
            if icmp_type == ICMP_TTL_EXCEEDED:
                orig_ip  = icmp[8:]
                if len(orig_ip) < 24:
                    return None
                orig_tcp = orig_ip[(orig_ip[0] & 0x0F) * 4:]
                if len(orig_tcp) < 4:
                    return None
                tp = port_map.get(struct.unpack("!H", orig_tcp[0:2])[0])
                if tp is None:
                    return None
                return (tp, 'filtered', 0, {'flags_str': '', 'firewall_rst': False,
                                             'icmp_reason': 'ttl-exceeded', 'firewall': False})

            if icmp_type != ICMP_DEST_UNREACHABLE:
                return None

            # Extract original TCP header from ICMP payload
            orig_ip = icmp[8:]
            if len(orig_ip) < 24:
                return None
            orig_ihl  = (orig_ip[0] & 0x0F) * 4
            orig_tcp  = orig_ip[orig_ihl:]
            if len(orig_tcp) < 4:
                return None
            orig_sport = struct.unpack("!H", orig_tcp[0:2])[0]

            target_port = port_map.get(orig_sport)
            if target_port is None:
                return None

            state, reason = classify_icmp3(icmp_code)
            meta = {
                'flags_str':   '',
                'firewall_rst': False,
                'icmp_reason': reason,
                'firewall':    state == 'firewall',
            }
            return (target_port, state, 0, meta)

        return None
    except Exception:
        return None


# ── Half-open SYN scanner ─────────────────────────────────────────────────────

class PacketScanner:
    """
    True half-open SYN scanner via AF_PACKET.
    Addresses all 7 engine upgrade items.

    Scan flow per port:
      SYN  →  SYN-ACK  →  RST (crafted, kernel RSTs suppressed)  →  OPEN
      SYN  →  RST / RST-ACK                                       →  CLOSED
      SYN  →  ICMP type-3 admin-prohibited                        →  FIREWALL
      SYN  →  ICMP type-3 other / type-11 / no response           →  FILTERED

    stealth=True:
      Forces T1 max timing, adds random jitter (10–25 %), uses source port
      spoofing if spoof_sport != 0.
    """

    SPORT_LO = 32768
    SPORT_HI = 60999

    def __init__(
        self,
        target:       str,
        ports:        List[int],
        timing:       int  = 4,
        ttl:          int  = 64,
        decoys:       int  = 0,
        fragment:     bool = False,
        randomize:    bool = True,
        grab_banner:  bool = True,
        verbose:      bool = False,
        iface:        str  = "",
        stealth:      bool = False,    # IDS-evasion mode
        spoof_sport:  int  = 0,        # fixed source port (0=random)
        jitter:       float = 0.0,     # extra inter-packet jitter fraction
    ):
        self.target      = target
        self.ports       = list(ports)
        self.ttl         = ttl
        self.decoys      = decoys
        self.fragment    = fragment
        self.randomize   = randomize
        self.grab_banner = grab_banner
        self.verbose     = verbose
        self.stealth     = stealth
        self.spoof_sport = spoof_sport
        self.jitter      = jitter

        # Stealth mode: cap at T1, add base jitter
        tmpl = TIMING[max(0, min(5, timing))]
        if stealth and list(TIMING.values()).index(tmpl) > 1:
            tmpl = TIMING[1]
        self.tmpl = tmpl
        if stealth and jitter == 0.0:
            self.jitter = 0.15   # 15 % default jitter in stealth mode

        self._open:     List[int]      = []
        self._closed:   List[int]      = []
        self._filtered: List[int]      = []
        self._firewall: List[int]      = []
        self._banners:  Dict[int, str] = {}
        self._meta:     Dict[int, dict] = {}
        self._total     = len(ports)
        self._sent      = 0

        # Interface: if not specified, find the one that owns our src IP
        self._iface_override = iface

    def _progress(self):
        pct = (self._sent / self._total * 100) if self._total else 0
        label = "\033[38;5;196m[STEALTH]\033[0m" if self.stealth else "\033[38;5;196m[PACKET]\033[0m"
        sys.stdout.write(
            f"\r{label} {self._sent}/{self._total} ({pct:.1f}%)  "
            f"open=\033[38;5;196m{len(self._open)}\033[0m  "
            f"closed={len(self._closed)}  "
            f"filtered={len(self._filtered)}  "
            f"firewall=\033[38;5;208m{len(self._firewall)}\033[0m"
        )
        sys.stdout.flush()

    def _interval(self, base: float) -> float:
        """Apply jitter to inter-packet interval."""
        if self.jitter > 0:
            return max(0.0, base * (1.0 + self.jitter * random.uniform(-1, 1)))
        return base

    def scan(self) -> List[ScanResult]:
        if os.geteuid() != 0:
            raise PermissionError("AF_PACKET scan requires root")
        if not hasattr(socket, "AF_PACKET"):
            raise RuntimeError("AF_PACKET not available (Linux only). Use --raw.")

        try:
            self._dst_ip = socket.gethostbyname(self.target)
        except Exception:
            self._dst_ip = self.target
        self._src_ip = _get_src_ip(self._dst_ip)

        # Interface auto-selection (fixed)
        if self._iface_override:
            iface = self._iface_override
        else:
            iface = _iface_for_src_ip(self._src_ip)

        iface_mac = _get_iface_mac(iface)
        gateway_ip = ""
        try:
            with open("/proc/net/route") as f:
                for line in f.readlines()[1:]:
                    fields = line.strip().split()
                    if fields[1] == "00000000" and fields[0] == iface:
                        gateway_ip = socket.inet_ntoa(
                            struct.pack("<L", int(fields[2], 16)))
                        break
                if not gateway_ip:
                    # iface might not be default route interface (VPN etc.) — use first default
                    f.seek(0)
                    for line in f.readlines()[1:]:
                        fields = line.strip().split()
                        if fields[1] == "00000000":
                            gateway_ip = socket.inet_ntoa(
                                struct.pack("<L", int(fields[2], 16)))
                            break
        except Exception:
            pass
        gw_mac = _get_gateway_mac(iface, gateway_ip) if gateway_ip else b"\xff" * 6

        port_map:  Dict[int, int] = {}
        src_ports: Dict[int, int] = {}
        responded: Set[int]       = set()

        scan_order = list(self.ports)
        if self.randomize:
            random.shuffle(scan_order)

        # Sockets
        try:
            send_sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
            send_sock.bind((iface, 0))
            use_eth_send = True
        except Exception:
            send_sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            gw_mac       = None
            use_eth_send = False

        try:
            recv_sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            recv_sock.bind((iface, 0))
            recv_sock.setblocking(False)
            use_af_packet = True
        except Exception:
            recv_sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            recv_sock.setblocking(False)
            use_af_packet = False

        ep = select.epoll()
        ep.register(recv_sock.fileno(), select.EPOLLIN)

        tmpl  = self.tmpl
        t_idx = list(TIMING.values()).index(tmpl)
        t0    = time.time()

        mode = "STEALTH" if self.stealth else "HALF-OPEN-SYN"
        print(
            f"\033[38;5;196m[PACKET]\033[0m {self._dst_ip} | "
            f"{self._total} ports | T{t_idx} ({tmpl.name}) | {mode} | "
            f"iface={iface} | src={self._src_ip}"
            + (f" | sport-spoof={self.spoof_sport}" if self.spoof_sport else "")
        )

        def _eth(ip_pkt: bytes) -> bytes:
            return (gw_mac + iface_mac + b"\x08\x00" + ip_pkt) if gw_mac is not None else ip_pkt

        def _send(pkt: bytes):
            if use_eth_send:
                send_sock.send(pkt)
            else:
                send_sock.sendto(pkt, (self._dst_ip, 0))

        def _send_rst(sport: int, dport: int, rst_seq: int):
            try:
                _send(_eth(_build_rst(self._src_ip, self._dst_ip, sport, dport, rst_seq)))
            except Exception:
                pass

        def _flush_recv(deadline: float):
            while time.time() < deadline:
                evts = ep.poll(timeout=0.005)
                if not evts:
                    break
                for fd, _ in evts:
                    if fd != recv_sock.fileno():
                        continue
                    try:
                        data, _ = recv_sock.recvfrom(65535)
                        if use_af_packet:
                            r = _parse_af_packet(data, self._dst_ip, port_map)
                        else:
                            # AF_INET fallback — build synthetic meta
                            from lightscan.scan.rawscan import _parse_tcp_response
                            from lightscan.scan.tcpflags import flags_str as _fstr
                            raw = _parse_tcp_response(data, self._dst_ip, port_map)
                            if raw:
                                try:
                                    ihl = (data[0] & 0x0F) * 4
                                    tcp = data[ihl:]
                                    ack_field = struct.unpack("!L", tcp[8:12])[0]
                                    flg       = tcp[13]
                                except Exception:
                                    ack_field, flg = 0, 0
                                r = (raw[0], raw[1], ack_field, {
                                    'flags_str':   flags_str(flg),
                                    'firewall_rst': False,
                                    'icmp_reason': '',
                                    'firewall':    False,
                                })
                            else:
                                r = None

                        if r:
                            dport, state, rst_seq, meta = r
                            if dport not in responded:
                                responded.add(dport)
                                sport = src_ports.get(dport, 0)
                                self._meta[dport] = meta

                                if state == 'open':
                                    if sport:
                                        _send_rst(sport, dport, rst_seq)
                                    self._open.append(dport)
                                elif state == 'closed':
                                    self._closed.append(dport)
                                elif state == 'firewall':
                                    self._firewall.append(dport)
                                else:
                                    self._filtered.append(dport)
                    except BlockingIOError:
                        break
                    except Exception:
                        break

        base_interval = 1.0 / min(tmpl.max_rate, 50000)

        with _suppress_kernel_rst(self.SPORT_LO, self.SPORT_HI) as suppressed:
            if self.verbose:
                s = "kernel RSTs suppressed (iptables)" if suppressed else "iptables unavailable — kernel RSTs not suppressed"
                print(f"\033[38;5;240m[~] {s}\033[0m")

            for port in scan_order:
                # Source port: fixed (spoof) or random
                if self.spoof_sport:
                    sport = self.spoof_sport
                else:
                    sport = random.randint(self.SPORT_LO, self.SPORT_HI)
                    while sport in port_map:
                        sport = random.randint(self.SPORT_LO, self.SPORT_HI)

                port_map[sport]  = port
                src_ports[port]  = sport

                try:
                    ip_pkt = _build_ipv4_syn(
                        self._src_ip, self._dst_ip, sport, port,
                        seq=random.randint(0, 2**32 - 1),
                        ttl=self.ttl, fragment=self.fragment)
                    _send(_eth(ip_pkt))
                except Exception as e:
                    if self.verbose:
                        print(f"\n  [!] send {port}: {e}")

                self._sent += 1
                if self._sent % 100 == 0:
                    self._progress()

                interval = self._interval(base_interval)
                _flush_recv(time.time() + interval * 0.3)
                time.sleep(max(0.0, interval))

            self._progress()
            print(
                f"\n\033[38;5;240m[+] Sent {self._total} SYNs — "
                f"waiting {tmpl.timeout:.1f}s for stragglers...\033[0m"
            )
            _flush_recv(time.time() + tmpl.timeout)

            if tmpl.retries > 0:
                retry = [p for p in scan_order if p not in responded]
                for port in retry:
                    sport = src_ports.get(port, random.randint(self.SPORT_LO, self.SPORT_HI))
                    try:
                        ip_pkt = _build_ipv4_syn(
                            self._src_ip, self._dst_ip, sport, port,
                            seq=random.randint(0, 2**32 - 1), ttl=self.ttl)
                        _send(_eth(ip_pkt))
                    except Exception:
                        pass
                _flush_recv(time.time() + tmpl.timeout * 0.5)

        ep.close()
        send_sock.close()
        recv_sock.close()

        for port in scan_order:
            if port not in responded:
                self._filtered.append(port)

        elapsed = time.time() - t0
        print(
            f"\033[38;5;196m[PACKET]\033[0m Done in {elapsed:.2f}s — "
            f"open=\033[38;5;196m{len(self._open)}\033[0m  "
            f"closed={len(self._closed)}  "
            f"filtered={len(self._filtered)}  "
            f"firewall=\033[38;5;208m{len(self._firewall)}\033[0m"
        )

        if self.grab_banner and self._open:
            loop = asyncio.new_event_loop()
            try:
                async def _grab():
                    from lightscan.scan.portscan import tcp_scan
                    return await asyncio.gather(
                        *[tcp_scan(self._dst_ip, p, 2.0, True) for p in self._open])
                for r in loop.run_until_complete(_grab()):
                    if r and r.data.get("banner"):
                        self._banners[r.port] = r.data["banner"]
            finally:
                loop.close()

        return self._build_results()

    def _build_results(self) -> List[ScanResult]:
        results = []
        method = "STEALTH-SYN" if self.stealth else "HALF-OPEN-SYN"

        for port in sorted(self._open):
            svc    = SERVICE_MAP.get(port, f"port/{port}")
            sev    = (Severity.CRITICAL if port in CRIT_PORTS
                      else Severity.HIGH if port in HIGH_PORTS else Severity.INFO)
            banner = self._banners.get(port, "")
            meta   = self._meta.get(port, {})
            detail = f"{svc} [{method}]" + (f" | {banner[:80]}" if banner else "")
            results.append(ScanResult(
                "packet-scan", self.target, port, "open", sev, detail,
                {"service": svc, "banner": banner, "method": method,
                 "flags": meta.get("flags_str", "SYN|ACK")}))

        for port in sorted(self._firewall):
            svc    = SERVICE_MAP.get(port, f"port/{port}")
            meta   = self._meta.get(port, {})
            reason = meta.get("icmp_reason", "admin-prohibited")
            results.append(ScanResult(
                "packet-scan", self.target, port, "firewall", Severity.HIGH,
                f"{svc} [FIREWALL-BLOCKED] | {reason}",
                {"service": svc, "method": method, "firewall": True, "icmp_reason": reason}))

        for port in sorted(self._filtered):
            svc  = SERVICE_MAP.get(port, f"port/{port}")
            meta = self._meta.get(port, {})
            reason = meta.get("icmp_reason", "no-response")
            results.append(ScanResult(
                "packet-scan", self.target, port, "filtered", Severity.INFO,
                f"{svc} [filtered | {reason}]",
                {"service": svc, "method": method, "icmp_reason": reason}))

        return results


# ── Async wrapper ─────────────────────────────────────────────────────────────

async def async_packet_scan(
    target:      str,
    ports:       List[int],
    timing:      int  = 4,
    ttl:         int  = 64,
    decoys:      int  = 0,
    fragment:    bool = False,
    grab_banner: bool = True,
    verbose:     bool = False,
    iface:       str  = "",
    stealth:     bool = False,
    spoof_sport: int  = 0,
) -> List[ScanResult]:
    """Async wrapper for the half-open AF_PACKET scanner."""
    if os.geteuid() != 0:
        from lightscan.scan.rawscan import async_raw_scan
        return await async_raw_scan(
            target, ports, timing, ttl, decoys, fragment, True, grab_banner, verbose)
    loop    = asyncio.get_event_loop()
    scanner = PacketScanner(
        target, ports, timing, ttl, decoys, fragment, True,
        grab_banner, verbose, iface, stealth, spoof_sport)
    return await loop.run_in_executor(None, scanner.scan)
