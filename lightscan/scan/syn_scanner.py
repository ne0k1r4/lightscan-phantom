"""
LightScan v2.0 PHANTOM — Raw SYN Scanner
Developer: Light

Integrates:
  - Scapy-based SYN scanner (SR1 half-open, stealthy)
  - Pure raw socket fallback (no Scapy needed, root required)
  - Async wrapper for engine compatibility
  - Proper RST teardown (no full TCP handshake = no connection logs)
  - OPEN / CLOSED / FILTERED classification

Requirements:
  pip install scapy     ← recommended
  OR run as root        ← pure raw socket fallback
"""
from __future__ import annotations
import asyncio, os, socket, struct, time, sys, threading, random
from queue import Queue, Empty
from threading import Lock, Thread
from typing import List, Optional

from lightscan.core.engine import ScanResult, Severity
from lightscan.scan.portscan import SERVICE_MAP, CRIT_PORTS, HIGH_PORTS

# ─── Scapy SYN Scanner ───────────────────────────────────────────────────────
try:
    # Suppress scapy IPv6 warning at import
    import logging; logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import IP, TCP, sr1, send, RandShort, conf
    conf.verb = 0          # no per-packet output
    SCAPY_OK = True
except (ImportError, KeyError, Exception):
    # KeyError: 'scope' can occur in sandboxed/containerised environments
    # where scapy's IPv6 route table fails to initialise — fall back gracefully
    SCAPY_OK = False

class ScapySYNScanner:
    """
    Half-open SYN scanner using Scapy.
    Sends SYN → receives SYN-ACK (open) / RST-ACK (closed) / nothing (filtered).
    Immediately sends RST after SYN-ACK → never completes handshake → no connection log.
    """
    def __init__(self, target: str, ports: List[int], timeout: float = 2.0,
                 threads: int = 100, verbose: bool = False):
        self.target   = target
        self.ports    = ports
        self.timeout  = timeout
        self.threads  = threads
        self.verbose  = verbose

        self._open:     List[int] = []
        self._filtered: List[int] = []
        self._closed:   List[int] = []
        self._lock      = Lock()
        self._total     = len(ports)
        self._done      = 0

    def _scan_port(self, port: int):
        try:
            ip  = IP(dst=self.target)
            tcp = TCP(sport=RandShort(), dport=port, flags="S", seq=random.randint(1000,9000000))
            resp = sr1(ip/tcp, timeout=self.timeout, verbose=0)

            with self._lock:
                self._done += 1
                if not self.verbose:
                    pct = (self._done / self._total * 100)
                    sys.stdout.write(
                        f"\r\033[38;5;196m[SYN]\033[0m "
                        f"{self._done}/{self._total} ({pct:.1f}%)  "
                        f"open=\033[38;5;196m{len(self._open)}\033[0m  "
                        f"filtered={len(self._filtered)}"
                    ); sys.stdout.flush()

            if resp is None:
                with self._lock: self._filtered.append(port)
                return

            if resp.haslayer(TCP):
                flags = resp.getlayer(TCP).flags
                if flags == 0x12:  # SYN-ACK → OPEN
                    with self._lock: self._open.append(port)
                    # RST to cleanly close — avoids half-open backlog on target
                    rst = IP(dst=self.target)/TCP(
                        sport=resp.getlayer(TCP).dport,
                        dport=port,
                        flags="R",
                        seq=resp.getlayer(TCP).ack
                    )
                    send(rst, verbose=0)
                elif flags & 0x04:  # RST → CLOSED
                    with self._lock: self._closed.append(port)
            elif resp.haslayer("ICMP"):
                icmp_type = resp.getlayer("ICMP").type
                if icmp_type == 3:  # Destination unreachable → FILTERED
                    with self._lock: self._filtered.append(port)

        except Exception as e:
            with self._lock:
                self._done += 1
                if self.verbose: print(f"  [!] port {port}: {e}")

    def _worker(self, q: Queue):
        while True:
            try:
                port = q.get(timeout=0.5)
            except Empty:
                break
            self._scan_port(port)
            q.task_done()

    def scan(self) -> dict:
        t0 = time.time()
        print(f"\033[38;5;196m[SYN-SCAPY]\033[0m {self.target} | {self._total} ports | {self.threads} threads")

        q = Queue()
        for p in self.ports: q.put(p)

        workers = [Thread(target=self._worker, args=(q,), daemon=True) for _ in range(self.threads)]
        for w in workers: w.start()
        q.join()

        elapsed = time.time() - t0
        print(f"\n\033[38;5;240m[+] SYN scan done: {len(self._open)} open · {len(self._filtered)} filtered · {elapsed:.2f}s\033[0m")
        return {"open": sorted(self._open), "filtered": sorted(self._filtered), "closed": sorted(self._closed)}


# ─── Pure Raw Socket SYN Scanner ─────────────────────────────────────────────
# No Scapy needed — implements TCP/IP stack manually with struct
# Based on the C implementation ported to Python

def _checksum(data: bytes) -> int:
    if len(data) % 2 != 0:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i+1]
        s += w
    s = (s >> 16) + (s & 0xFFFF)
    s += (s >> 16)
    return ~s & 0xFFFF

def _build_syn_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, seq: int = 1000) -> bytes:
    # IP header (20 bytes)
    ip_ihl_ver = (4 << 4) | 5
    ip_tos     = 0
    ip_tot_len = 0          # kernel fills this
    ip_id      = random.randint(1, 65535)
    ip_frag_off= 0
    ip_ttl     = 64
    ip_proto   = socket.IPPROTO_TCP
    ip_check   = 0
    ip_saddr   = socket.inet_aton(src_ip)
    ip_daddr   = socket.inet_aton(dst_ip)
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off,
        ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr
    )

    # TCP header (20 bytes)
    tcp_src   = src_port
    tcp_dst   = dst_port
    tcp_seq   = seq
    tcp_ack   = 0
    tcp_off   = (5 << 4)   # data offset: 5 × 4 = 20 bytes
    tcp_flags = 0x02       # SYN
    tcp_win   = socket.htons(5840)
    tcp_chk   = 0
    tcp_urg   = 0
    tcp_hdr = struct.pack("!HHLLBBHHH",
        tcp_src, tcp_dst, tcp_seq, tcp_ack,
        tcp_off, tcp_flags, tcp_win, tcp_chk, tcp_urg
    )

    # Pseudo header for checksum
    pseudo = struct.pack("!4s4sBBH",
        ip_saddr, ip_daddr, 0, socket.IPPROTO_TCP, len(tcp_hdr)
    )
    tcp_chk = _checksum(pseudo + tcp_hdr)
    tcp_hdr = struct.pack("!HHLLBBHHH",
        tcp_src, tcp_dst, tcp_seq, tcp_ack,
        tcp_off, tcp_flags, tcp_win, tcp_chk, tcp_urg
    )
    return ip_hdr + tcp_hdr

class RawSocketSYNScanner:
    """
    Pure raw socket SYN scanner — no Scapy.
    Sends raw IP+TCP SYN packets, sniffs ICMP/TCP responses via recv_thread.
    Requires root. 
    """
    def __init__(self, target: str, ports: List[int], timeout: float = 2.5,
                 threads: int = 50, verbose: bool = False):
        self.target   = target
        self.ports    = ports
        self.timeout  = timeout
        self.threads  = threads
        self.verbose  = verbose

        self._open:     List[int] = []
        self._filtered: List[int] = []
        self._closed:   List[int] = []
        self._lock      = Lock()
        self._total     = len(ports)
        self._done      = 0
        self._stop_sniffer = threading.Event()
        self._src_ip    = ""
        # map src_port → dst_port (so we know which port a response belongs to)
        self._port_map: dict = {}

    def _get_source_ip(self) -> str:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            try:
                s.connect((self.target, 80))
                return s.getsockname()[0]
            except Exception:
                return "127.0.0.1"

    def _sniffer(self):
        """Raw ICMP + TCP response sniffer thread"""
        try:
            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            recv_sock.settimeout(0.5)
        except PermissionError:
            return

        try:
            while not self._stop_sniffer.is_set():
                try:
                    data, addr = recv_sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except Exception:
                    break

                if addr[0] != self.target:
                    continue
                if len(data) < 40:
                    continue

                # Parse IP header to skip it (IHL field)
                ihl = (data[0] & 0x0F) * 4
                if len(data) < ihl + 20:
                    continue

                tcp = data[ihl:]
                if len(tcp) < 14:
                    continue

                dst_port_resp = struct.unpack("!H", tcp[0:2])[0]   # src port of response = our src port
                src_port_resp = struct.unpack("!H", tcp[2:4])[0]   # dst port of response = target port
                flags         = tcp[13]

                # Match src port in response to target port via our port_map
                if dst_port_resp not in self._port_map:
                    continue
                target_port = self._port_map[dst_port_resp]

                with self._lock:
                    if flags == 0x12:    # SYN-ACK → open
                        if target_port not in self._open:
                            self._open.append(target_port)
                    elif flags & 0x04:   # RST → closed
                        if target_port not in self._closed:
                            self._closed.append(target_port)
        finally:
            recv_sock.close()

    def _worker(self, send_sock, q: Queue):
        while True:
            try:
                port = q.get(timeout=0.5)
            except Empty:
                break
            src_port = random.randint(10000, 60000)
            with self._lock:
                self._port_map[src_port] = port
            try:
                pkt = _build_syn_packet(self._src_ip, self.target, src_port, port)
                dest = (self.target, 0)
                send_sock.sendto(pkt, dest)
            except Exception as e:
                if self.verbose: print(f"  [!] send port {port}: {e}")
            with self._lock:
                self._done += 1
                if not self.verbose:
                    pct = (self._done / self._total * 100)
                    sys.stdout.write(
                        f"\r\033[38;5;196m[SYN-RAW]\033[0m "
                        f"{self._done}/{self._total} ({pct:.1f}%)  "
                        f"open=\033[38;5;196m{len(self._open)}\033[0m"
                    ); sys.stdout.flush()
            time.sleep(0.0005)   # tiny inter-packet delay
            q.task_done()

    def scan(self) -> dict:
        if os.geteuid() != 0:
            print("\033[38;5;196m[!]\033[0m Raw SYN scan requires root. Falling back to connect scan.")
            from lightscan.scan.portscan import build_scan_tasks
            import concurrent.futures
            # Run in a dedicated thread to avoid asyncio.run() nested-loop crash
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, _async_connect_scan(self.target, self.ports, self.timeout))
                results = future.result()
            open_ports = [r.port for r in results if r and r.status == "open"]
            return {"open": open_ports, "filtered": [], "closed": []}

        self._src_ip = self._get_source_ip()
        t0 = time.time()
        print(f"\033[38;5;196m[SYN-RAW]\033[0m {self.target} | {self._total} ports | src={self._src_ip}")

        try:
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except PermissionError:
            print("\033[38;5;196m[!]\033[0m Cannot create raw socket. Run as root.")
            return {"open": [], "filtered": self.ports, "closed": []}

        sniffer_t = Thread(target=self._sniffer, daemon=True)
        sniffer_t.start()

        q = Queue()
        for p in self.ports: q.put(p)

        workers = [Thread(target=self._worker, args=(send_sock, q), daemon=True) for _ in range(self.threads)]
        for w in workers: w.start()
        q.join()

        # Wait for straggler responses
        time.sleep(self.timeout + 0.5)
        self._stop_sniffer.set()
        sniffer_t.join(timeout=3.0)
        send_sock.close()

        # Anything we sent but got no response for = filtered
        responded = set(self._open + self._closed)
        for p in self.ports:
            if p not in responded and p not in self._filtered:
                self._filtered.append(p)

        elapsed = time.time() - t0
        print(f"\n\033[38;5;240m[+] Raw SYN done: {len(self._open)} open · {len(self._filtered)} filtered · {elapsed:.2f}s\033[0m")
        send_sock.close()
        return {"open": sorted(self._open), "filtered": sorted(self._filtered), "closed": sorted(self._closed)}


# ─── Async fallback (connect scan) ───────────────────────────────────────────
async def _async_connect_scan(target, ports, timeout):
    from lightscan.scan.portscan import tcp_scan
    tasks = [tcp_scan(target, p, timeout, False) for p in ports]
    return [r for r in await asyncio.gather(*tasks) if r]


# ─── Unified interface ────────────────────────────────────────────────────────
def syn_scan(target: str, ports: List[int], timeout: float = 2.0,
             threads: int = 100, verbose: bool = False, force_raw: bool = False) -> List[ScanResult]:
    """
    Smart SYN scanner:
      1. Use Scapy if available (most accurate, cross-platform)
      2. Fall back to pure raw socket (requires root, Linux)
      3. Fall back to connect scan (no root needed, full handshake)

    Returns list of ScanResult (only open ports + filtered ports with HIGH sev).
    """
    results = []

    if SCAPY_OK and not force_raw:
        scanner = ScapySYNScanner(target, ports, timeout, threads, verbose)
    else:
        scanner = RawSocketSYNScanner(target, ports, timeout, threads, verbose)

    data = scanner.scan()

    for port in data["open"]:
        svc = SERVICE_MAP.get(port, f"port/{port}")
        sev = Severity.CRITICAL if port in CRIT_PORTS else Severity.HIGH if port in HIGH_PORTS else Severity.INFO
        results.append(ScanResult("syn-scan", target, port, "open", sev,
            f"{svc} [SYN half-open]", {"service": svc, "method": "SYN"}))

    for port in data["filtered"]:
        svc = SERVICE_MAP.get(port, f"port/{port}")
        results.append(ScanResult("syn-scan", target, port, "filtered", Severity.INFO,
            f"{svc} [filtered/no-response]", {"service": svc, "method": "SYN"}))

    return results


async def async_syn_scan(target: str, ports: List[int], timeout: float = 2.0,
                         threads: int = 100, verbose: bool = False) -> List[ScanResult]:
    """Async wrapper — runs SYN scan in executor so it doesn't block event loop."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, syn_scan, target, ports, timeout, threads, verbose)
