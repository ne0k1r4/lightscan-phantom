"""
LightScan v2.0 PHANTOM — Scapy+Raw SYN Scanner (legacy interface) | Developer: Light
─────────────────────────────────────────────────────────────────────────────────────
Upgrades applied:
  - TCP flag parser: classify_tcp() replaces raw flag comparisons
  - ICMP filtered detection: full classify_icmp3() table
  - Kernel RST suppression imported from packetscan for true half-open
  - stealth / jitter wiring from EvasionConfig
"""
from __future__ import annotations
import asyncio, os, socket, time, sys, random
from threading import Thread, Lock
from queue import Queue, Empty
from typing import List, Optional

from lightscan.core.engine import ScanResult, Severity
from lightscan.scan.portscan import SERVICE_MAP, CRIT_PORTS, HIGH_PORTS
from lightscan.scan.tcpflags import (
    classify_tcp, classify_icmp3, flags_str,
    ICMP_DEST_UNREACHABLE, ICMP_TTL_EXCEEDED,
)


class SYNScanner:
    """
    Raw SYN scanner backed by Scapy.
    Upgraded: correct flag classification + ICMP filtered/firewall detection.
    """
    def __init__(self, target: str, ports: list, timeout=2.0, threads=100,
                 verbose=False, os_fingerprint=True, jitter=0.0):
        self.target        = target
        self.ports         = ports
        self.timeout       = timeout
        self.threads       = threads
        self.verbose       = verbose
        self.os_fingerprint = os_fingerprint
        self.jitter        = jitter

        self.open_ports     = []
        self.filtered_ports = []
        self.closed_ports   = []
        self.firewall_ports = []
        self.os_results     = []
        self.lock  = Lock()
        self.total = len(ports)
        self.done  = 0
        self._q    = None

    def _scan_port(self, port: int):
        if self.jitter > 0:
            time.sleep(self.jitter * random.uniform(0.5, 1.5))
        try:
            from scapy.all import IP, TCP, sr1, send, RandShort
            ip  = IP(dst=self.target)
            tcp = TCP(sport=RandShort(), dport=port, flags="S",
                      seq=random.randint(1000, 9_000_000))
            resp = sr1(ip/tcp, timeout=self.timeout, verbose=0)

            with self.lock:
                self.done += 1
                self._progress(port)

            if resp is None:
                with self.lock:
                    self.filtered_ports.append(port)
                return

            if resp.haslayer(TCP):
                flags_int = int(resp.getlayer(TCP).flags)
                state = classify_tcp(flags_int)

                if state == 'open':
                    with self.lock:
                        self.open_ports.append(port)
                        if self.os_fingerprint:
                            try:
                                from lightscan.scan.os_detect import passive_engine
                                os_r = passive_engine().fingerprint_synack(resp, self.target, port)
                                if os_r:
                                    self.os_results.append(os_r)
                            except Exception:
                                pass
                    rst = IP(dst=self.target) / TCP(
                        sport=resp.getlayer(TCP).dport,
                        dport=port, flags="R",
                        seq=resp.getlayer(TCP).ack)
                    send(rst, verbose=0)

                elif state == 'closed':
                    with self.lock:
                        self.closed_ports.append(port)

            elif resp.haslayer("ICMP"):
                icmp_type = resp.getlayer("ICMP").type
                icmp_code = resp.getlayer("ICMP").code

                if icmp_type == ICMP_TTL_EXCEEDED:
                    with self.lock:
                        self.filtered_ports.append(port)
                elif icmp_type == ICMP_DEST_UNREACHABLE:
                    icmp_state, _reason = classify_icmp3(icmp_code)
                    with self.lock:
                        if icmp_state == 'firewall':
                            self.firewall_ports.append(port)
                        else:
                            self.filtered_ports.append(port)

        except (ImportError, ModuleNotFoundError):
            with self.lock:
                self.done += 1
                if not hasattr(self, '_scapy_missing'):
                    self._scapy_missing = True
                    print("\n\033[38;5;196m[!]\033[0m scapy not found: "
                          "sudo pip install scapy --break-system-packages")
        except Exception as e:
            with self.lock:
                self.done += 1
            if self.verbose:
                print(f"\n  [!] port {port}: {e}")

    def _progress(self, port):
        if self.verbose:
            return
        pct = self.done / self.total * 100
        sys.stdout.write(
            f"\r\033[38;5;196m[SYN]\033[0m "
            f"{self.done}/{self.total} ({pct:.1f}%)  "
            f"open=\033[38;5;196m{len(self.open_ports)}\033[0m  "
            f"filtered={len(self.filtered_ports)}  "
            f"firewall=\033[38;5;208m{len(self.firewall_ports)}\033[0m  "
            f"port={port:<6}"
        )
        sys.stdout.flush()

    def _worker(self):
        while True:
            port = self._q.get()
            if port is None:
                break
            self._scan_port(port)
            self._q.task_done()

    def scan(self) -> list:
        if os.geteuid() != 0:
            raise PermissionError("SYN scan requires root")
        try:
            self.target = socket.gethostbyname(self.target)
        except Exception:
            pass

        print(f"\033[38;5;196m[SYN]\033[0m {self.target} | "
              f"{self.total} ports | {self.threads} threads | half-open")
        t0 = time.time()
        self._q = Queue()
        for p in self.ports:
            self._q.put(p)

        threads = [Thread(target=self._worker, daemon=True) for _ in range(self.threads)]
        for t in threads:
            t.start()
        self._q.join()
        for _ in range(self.threads):
            self._q.put(None)
        for t in threads:
            t.join()

        elapsed = time.time() - t0
        print(f"\n\033[38;5;196m[SYN]\033[0m Done in {elapsed:.2f}s — "
              f"open=\033[38;5;196m{len(self.open_ports)}\033[0m  "
              f"filtered={len(self.filtered_ports)}  "
              f"firewall=\033[38;5;208m{len(self.firewall_ports)}\033[0m  "
              f"closed={len(self.closed_ports)}")

        results = []
        for port in sorted(self.open_ports):
            svc = SERVICE_MAP.get(port, f"port/{port}")
            sev = (Severity.CRITICAL if port in CRIT_PORTS
                   else Severity.HIGH if port in HIGH_PORTS else Severity.INFO)
            results.append(ScanResult(
                "syn-scan", self.target, port, "open", sev,
                f"{svc} [SYN-half-open]", {"method": "syn", "service": svc}))
        for port in sorted(self.firewall_ports):
            svc = SERVICE_MAP.get(port, f"port/{port}")
            results.append(ScanResult(
                "syn-scan", self.target, port, "firewall", Severity.HIGH,
                f"{svc} [FIREWALL-BLOCKED]",
                {"method": "syn", "service": svc, "firewall": True}))
        for port in sorted(self.filtered_ports):
            results.append(ScanResult(
                "syn-scan", self.target, port, "filtered", Severity.INFO,
                f"{SERVICE_MAP.get(port,'?')} [filtered/no-response]"))
        seen_hosts = set()
        for r in self.os_results:
            if r.target not in seen_hosts:
                seen_hosts.add(r.target)
                results.append(r)
        return results


def syn_scan_auto(target: str, ports: list, timeout=2.0, threads=100,
                  verbose=False, prefer_c=False, jitter=0.0) -> list:
    """
    Auto-pick best SYN method: C > Scapy > connect fallback.
    jitter: per-packet delay fraction for stealth/IDS-evasion.
    """
    from lightscan.scan.syn_scanner import syn_scan_c, _compile_c_scanner

    if os.geteuid() != 0:
        print("\033[38;5;240m[!] Not root — falling back to connect scan\033[0m")
        return _run_connect_fallback(target, ports, timeout)

    try:
        if prefer_c:
            return syn_scan_c(target, ports, int(timeout))
        return SYNScanner(target, ports, timeout, threads, verbose,
                          jitter=jitter).scan()
    except Exception as e:
        print(f"\033[38;5;240m[!] SYN failed ({e}) — connect scan fallback\033[0m")
        return _run_connect_fallback(target, ports, timeout)


def _run_connect_fallback(target: str, ports: list, timeout: float) -> list:
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(asyncio.run, _async_connect_scan(target, ports, timeout))
        return future.result()


async def _async_connect_scan(target, ports, timeout):
    from lightscan.scan.portscan import tcp_scan
    tasks = [tcp_scan(target, p, timeout, False) for p in ports]
    return [r for r in await asyncio.gather(*tasks) if r]
