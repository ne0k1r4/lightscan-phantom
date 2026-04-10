"""LightScan v2.0 PHANTOM — UDP Scanner | Developer: Light

Performs UDP port scanning with proper ICMP-based state classification:

  OPEN          — received a UDP response from the port
  OPEN|FILTERED — no response (UDP is connectionless; silence = maybe open)
  FILTERED      — received ICMP Type 3 Code 13 (admin prohibited)
  CLOSED        — received ICMP Type 3 Code 3 (port unreachable)

Requires root for raw ICMP sniffing (accurate closed/filtered classification).
Falls back to basic send-and-wait when run without root (open/open|filtered only).
"""
from __future__ import annotations
import asyncio
import os
import socket
import struct
import sys
import time
import threading
from queue import Queue, Empty
from threading import Lock, Thread
from typing import List, Optional

from lightscan.core.engine import ScanResult, Severity
from lightscan.scan.portscan import SERVICE_MAP, CRIT_PORTS, HIGH_PORTS

# ── Common UDP probes ─────────────────────────────────────────────────────────
UDP_PROBES: dict[int, bytes] = {
    53:   b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"  # DNS query
          b"\x07version\x04bind\x00\x00\x10\x00\x03",
    123:  b"\x1b" + b"\x00" * 47,                               # NTP client request
    161:  b"\x30\x26\x02\x01\x00\x04\x06public"                # SNMP v1 GetRequest
          b"\xa0\x19\x02\x04\x71\x68\xd4\x65\x02\x01\x00"
          b"\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06"
          b"\x01\x02\x01\x05\x00",
    137:  b"\x00\x00\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00"  # NetBIOS name query
          b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01",
    1900: b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"  # SSDP
          b"MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n",
    5353: b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"  # mDNS query
          b"\x05local\x00\x00\xff\x00\x01",
    69:   b"\x00\x01README\x00octet\x00",                        # TFTP RRQ
    500:  b"\x00" * 28 + b"\x01\x10\x02\x00" + b"\x00" * 4,    # IKE/ISAKMP
    4500: b"\x00" * 28 + b"\x01\x10\x02\x00" + b"\x00" * 4,    # IKE NAT-T
    5060: (b"OPTIONS sip:nm SIP/2.0\r\nVia: SIP/2.0/UDP nm;branch=foo\r\n"
           b"From: sip:nm@nm;tag=root\r\nTo: sip:nm2@nm2\r\n"
           b"Call-ID: 50000\r\nCSeq: 42 OPTIONS\r\n"
           b"Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n"),     # SIP OPTIONS
}
_DEFAULT_PROBE = b"\x00" * 8  # generic empty probe


# ── ICMP type/code constants ──────────────────────────────────────────────────
ICMP_DEST_UNREACH       = 3
ICMP_PORT_UNREACH       = 3   # code 3 → port closed
ICMP_ADMIN_PROHIBITED   = 13  # code 13 → filtered by firewall
ICMP_NET_UNREACH        = 0
ICMP_HOST_UNREACH       = 1
ICMP_PROTO_UNREACH      = 2


def _icmp_state(icmp_code: int) -> str:
    """Map ICMP Destination Unreachable code to port state string."""
    if icmp_code == ICMP_PORT_UNREACH:
        return "closed"
    if icmp_code in (ICMP_ADMIN_PROHIBITED, 10, 11, 12):
        return "filtered"
    return "filtered"  # any other unreachable = filtered


# ── Root-mode scanner (raw ICMP sniffer) ─────────────────────────────────────

class UDPScanner:
    """
    UDP port scanner with ICMP-based state classification.

    Port states:
      open          — UDP response received
      closed        — ICMP Type 3 Code 3 (port unreachable)
      filtered      — ICMP Type 3 Code 13 (admin prohibited) or other unreach
      open|filtered — no response within timeout (common for UDP)
    """

    def __init__(self, target: str, ports: List[int], timeout: float = 2.0,
                 threads: int = 50, verbose: bool = False, retries: int = 2):
        self.target   = target
        self.ports    = ports
        self.timeout  = timeout
        self.threads  = threads
        self.verbose  = verbose
        self.retries  = retries

        self._open:            List[int] = []
        self._closed:          List[int] = []
        self._filtered:        List[int] = []
        self._open_filtered:   List[int] = []
        self._lock             = Lock()
        self._total            = len(ports)
        self._done             = 0
        self._stop_sniffer     = threading.Event()
        # port → state from ICMP replies
        self._icmp_results: dict[int, str] = {}
        # ports we sent probes to (for open|filtered classification)
        self._sent: set[int] = set()

    def _get_target_ip(self) -> str:
        try:
            return socket.gethostbyname(self.target)
        except Exception:
            return self.target

    def _sniffer(self, target_ip: str):
        """Raw socket sniffer: captures ICMP Destination Unreachable responses."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(0.5)
        except PermissionError:
            return

        try:
            while not self._stop_sniffer.is_set():
                try:
                    data, addr = sock.recvfrom(1024)
                except socket.timeout:
                    continue
                except Exception:
                    break

                if addr[0] != target_ip:
                    continue

                # IP header length
                if len(data) < 28:
                    continue
                ihl = (data[0] & 0x0F) * 4

                # ICMP header starts after IP header
                if len(data) < ihl + 8:
                    continue
                icmp_type = data[ihl]
                icmp_code = data[ihl + 1]

                if icmp_type != ICMP_DEST_UNREACH:
                    continue

                # The original IP+UDP header is embedded after the ICMP header
                # ICMP header = 8 bytes, then original IP header, then original UDP header
                orig_ip_start = ihl + 8
                if len(data) < orig_ip_start + 28:
                    continue
                orig_ihl = (data[orig_ip_start] & 0x0F) * 4
                orig_udp_start = orig_ip_start + orig_ihl

                if len(data) < orig_udp_start + 8:
                    continue

                # Original UDP destination port (the port we were scanning)
                orig_dst_port = struct.unpack("!H", data[orig_udp_start + 2: orig_udp_start + 4])[0]

                state = _icmp_state(icmp_code)
                with self._lock:
                    if orig_dst_port not in self._icmp_results:
                        self._icmp_results[orig_dst_port] = state
        finally:
            sock.close()

    def _send_probe(self, sock: socket.socket, target_ip: str, port: int):
        """Send UDP probe to a single port."""
        probe = UDP_PROBES.get(port, _DEFAULT_PROBE)
        try:
            sock.sendto(probe, (target_ip, port))
        except Exception as e:
            if self.verbose:
                print(f"  [!] UDP send port {port}: {e}")

    def _recv_response(self, target_ip: str, port: int) -> bool:
        """Try to receive a UDP response. Returns True if any data received."""
        try:
            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            recv_sock.settimeout(self.timeout)
            recv_sock.bind(("", 0))
            recv_sock.sendto(UDP_PROBES.get(port, _DEFAULT_PROBE), (target_ip, port))
            try:
                data, _ = recv_sock.recvfrom(1024)
                return len(data) > 0
            except socket.timeout:
                return False
            finally:
                recv_sock.close()
        except Exception:
            return False

    def _worker(self, send_sock: socket.socket, target_ip: str, q: Queue):
        """Worker thread: sends UDP probes."""
        while True:
            try:
                port = q.get(timeout=0.5)
            except Empty:
                break
            with self._lock:
                self._sent.add(port)

            for _ in range(self.retries):
                self._send_probe(send_sock, target_ip, port)
                time.sleep(0.001)  # slight inter-probe gap

            with self._lock:
                self._done += 1
                if not self.verbose:
                    pct = (self._done / self._total * 100)
                    sys.stdout.write(
                        f"\r\033[38;5;196m[UDP]\033[0m "
                        f"{self._done}/{self._total} ({pct:.1f}%)  "
                        f"open=\033[38;5;196m{len(self._open)}\033[0m  "
                        f"closed={len(self._closed)}"
                    )
                    sys.stdout.flush()
            q.task_done()

    def scan(self) -> dict:
        """
        Perform UDP scan. Returns dict with keys:
          open, closed, filtered, open_filtered
        """
        root = os.geteuid() == 0
        target_ip = self._get_target_ip()
        t0 = time.time()

        print(f"\033[38;5;196m[UDP]\033[0m {target_ip} | {self._total} ports | "
              f"{'root+ICMP' if root else 'no-root/basic'} mode")

        if root:
            # Start ICMP sniffer thread
            sniffer_t = Thread(target=self._sniffer, args=(target_ip,), daemon=True)
            sniffer_t.start()

            # Create raw UDP send socket
            try:
                send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            except Exception as e:
                print(f"\033[38;5;196m[!]\033[0m UDP socket error: {e}")
                return {"open": [], "closed": [], "filtered": self.ports, "open_filtered": []}

            q = Queue()
            for p in self.ports:
                q.put(p)

            workers = [
                Thread(target=self._worker, args=(send_sock, target_ip, q), daemon=True)
                for _ in range(self.threads)
            ]
            for w in workers:
                w.start()
            q.join()
            for w in workers:
                w.join(timeout=1.0)

            # Wait for straggler ICMP responses
            time.sleep(self.timeout + 0.5)
            self._stop_sniffer.set()
            sniffer_t.join(timeout=3.0)
            send_sock.close()

            # Classify all ports
            for port in self.ports:
                if port in self._icmp_results:
                    state = self._icmp_results[port]
                    if state == "closed":
                        self._closed.append(port)
                    else:
                        self._filtered.append(port)
                else:
                    # No ICMP response and no UDP response → open|filtered
                    self._open_filtered.append(port)

        else:
            # No root — basic mode: just try to get a UDP response
            # Cannot distinguish closed from open|filtered without ICMP
            print("\033[38;5;240m[!] Not root — ICMP classification unavailable. "
                  "Showing open/open|filtered only.\033[0m")
            for i, port in enumerate(self.ports):
                got_response = self._recv_response(target_ip, port)
                if got_response:
                    self._open.append(port)
                else:
                    self._open_filtered.append(port)
                self._done += 1
                if not self.verbose:
                    pct = (self._done / self._total * 100)
                    sys.stdout.write(
                        f"\r\033[38;5;196m[UDP]\033[0m "
                        f"{self._done}/{self._total} ({pct:.1f}%)  "
                        f"open=\033[38;5;196m{len(self._open)}\033[0m"
                    )
                    sys.stdout.flush()

        elapsed = time.time() - t0
        print(f"\n\033[38;5;240m[+] UDP scan done: "
              f"{len(self._open)} open · "
              f"{len(self._open_filtered)} open|filtered · "
              f"{len(self._closed)} closed · "
              f"{len(self._filtered)} filtered · "
              f"{elapsed:.2f}s\033[0m")

        return {
            "open":          sorted(self._open),
            "closed":        sorted(self._closed),
            "filtered":      sorted(self._filtered),
            "open_filtered": sorted(self._open_filtered),
        }


# ── Result builder ────────────────────────────────────────────────────────────

def udp_scan(target: str, ports: List[int], timeout: float = 2.0,
             threads: int = 50, verbose: bool = False, retries: int = 2) -> List[ScanResult]:
    """
    Run UDP scan and return LightScan ScanResult list.

    State mapping:
      open          → status="open",          severity based on port
      open|filtered → status="open|filtered", severity INFO
      closed        → not included in results (reduces noise)
      filtered      → status="filtered",      severity INFO
    """
    scanner = UDPScanner(target, ports, timeout, threads, verbose, retries)
    data = scanner.scan()
    results: List[ScanResult] = []

    for port in data["open"]:
        svc = SERVICE_MAP.get(port, f"udp/{port}")
        sev = (Severity.CRITICAL if port in CRIT_PORTS
               else Severity.HIGH if port in HIGH_PORTS
               else Severity.INFO)
        results.append(ScanResult(
            "udp-scan", target, port, "open", sev,
            f"{svc} [UDP open — response received]",
            {"service": svc, "method": "UDP", "state": "open"}
        ))

    for port in data["open_filtered"]:
        svc = SERVICE_MAP.get(port, f"udp/{port}")
        results.append(ScanResult(
            "udp-scan", target, port, "open|filtered", Severity.INFO,
            f"{svc} [UDP open|filtered — no response, no ICMP unreachable]",
            {"service": svc, "method": "UDP", "state": "open|filtered"}
        ))

    for port in data["filtered"]:
        svc = SERVICE_MAP.get(port, f"udp/{port}")
        results.append(ScanResult(
            "udp-scan", target, port, "filtered", Severity.INFO,
            f"{svc} [UDP filtered — ICMP admin prohibited]",
            {"service": svc, "method": "UDP", "state": "filtered"}
        ))

    return results


async def async_udp_scan(target: str, ports: List[int], timeout: float = 2.0,
                         threads: int = 50, verbose: bool = False) -> List[ScanResult]:
    """Async wrapper — runs UDP scan in executor so it doesn't block the event loop."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, udp_scan, target, ports, timeout, threads, verbose)
