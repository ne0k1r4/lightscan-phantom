"""
LightScan v2.0 PHANTOM — Timing & Evasion Engine | Developer: Light
─────────────────────────────────────────────────────────────────────
nmap-compatible timing templates + IDS evasion techniques:

Timing (T0-T5):
  T0  Paranoid   — 1 packet/15s,  max 1 parallel    (IDS evasion)
  T1  Sneaky     — 1 packet/1.5s, max 5 parallel    (IDS evasion)
  T2  Polite     — 1 packet/0.4s, max 10 parallel   (low bandwidth)
  T3  Normal     — default nmap timing               (balanced)
  T4  Aggressive — fast, assumes reliable network    (CTF/lab)
  T5  Insane     — fastest, may miss ports           (LAN only)

Evasion techniques:
  --decoy N         Send N random decoy IPs alongside real probes
  --fragment        Fragment IP packets (evades some IDS/packet filters)
  --ttl N           Set custom TTL (evade TTL-based IDS rules)
  --data-length N   Append random padding to packets
  --randomize-hosts Randomise host scan order
  --bad-checksum    Send probes with bad TCP checksum (firewall test)
  --source-port N   Spoof source port (e.g. 53 to bypass some firewalls)
"""
from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional


@dataclass
class EvasionConfig:
    """Full evasion configuration passed to scanners."""
    # Timing
    timing:         int   = 4       # T0-T5
    min_rate:       float = 0.0     # override packets/sec min (0=use template)
    max_rate:       float = 0.0     # override packets/sec max (0=use template)

    # Packet-level evasion
    ttl:            int   = 64      # IP TTL (64=Linux, 128=Windows, 255=router)
    fragment:       bool  = False   # IP fragmentation
    bad_checksum:   bool  = False   # invalid TCP checksum (firewall probe)
    data_length:    int   = 0       # append N random bytes to payload (0=off)
    source_port:    int   = 0       # fixed source port (0=random, 53=DNS bypass)

    # Scan-level evasion
    decoys:         int   = 0       # number of random decoy IPs
    decoy_ips:      List[str] = field(default_factory=list)  # explicit decoy IPs
    randomize:      bool  = True    # randomise port order
    randomize_hosts:bool  = False   # randomise host order in multi-target scans

    # Timing jitter (adds randomness to inter-packet delays)
    jitter_pct:     float = 0.0     # 0.0-1.0, % of base delay to jitter

    def effective_interval(self, base_interval: float) -> float:
        """Return inter-packet delay with optional jitter applied."""
        if self.jitter_pct > 0:
            jitter = base_interval * self.jitter_pct * random.uniform(-1, 1)
            return max(0.0, base_interval + jitter)
        return base_interval

    def effective_ttl(self) -> int:
        """Return TTL, optionally randomised slightly for evasion."""
        if self.ttl == 0:
            return random.choice([64, 128, 255])
        return self.ttl


class RateLimiter:
    """
    Token-bucket rate limiter for packet sending.
    Enforces min/max rate from timing template.
    """
    def __init__(self, rate: float):
        self._rate      = rate          # tokens per second
        self._tokens    = rate          # start full
        self._last      = time.monotonic()
        self._interval  = 1.0 / rate if rate > 0 else 0.0

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self._last
        self._tokens = min(self._rate, self._tokens + elapsed * self._rate)
        self._last = now

    async def acquire(self):
        """Wait until we have a token to send a packet."""
        while True:
            self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return
            sleep_time = (1.0 - self._tokens) / self._rate
            await asyncio.sleep(sleep_time)

    def acquire_sync(self):
        """Blocking version for threaded code."""
        while True:
            self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return
            sleep_time = (1.0 - self._tokens) / self._rate
            time.sleep(sleep_time)


class ScanScheduler:
    """
    Controls scan pacing, host ordering, and per-host parallelism.
    Used by all scanner modules for consistent timing behaviour.
    """
    def __init__(self, evasion: EvasionConfig):
        from lightscan.scan.rawscan import TIMING
        self.evasion = evasion
        self.tmpl    = TIMING[evasion.timing]

        # Use override rates if provided, else template
        rate = evasion.max_rate if evasion.max_rate > 0 else self.tmpl.max_rate
        self.limiter = RateLimiter(rate)
        self._sem    = asyncio.Semaphore(self.tmpl.parallelism)

    @property
    def timeout(self) -> float:
        return self.tmpl.timeout

    @property
    def retries(self) -> int:
        return self.tmpl.retries

    async def slot(self):
        """Acquire both a rate-limit token and a parallelism slot."""
        await self.limiter.acquire()
        await self._sem.acquire()

    def release(self):
        self._sem.release()

    def order_ports(self, ports: List[int]) -> List[int]:
        """Return ports in scan order (randomised if configured)."""
        result = list(ports)
        if self.evasion.randomize:
            random.shuffle(result)
        return result

    def order_hosts(self, hosts: List[str]) -> List[str]:
        """Return hosts in scan order."""
        result = list(hosts)
        if self.evasion.randomize_hosts:
            random.shuffle(result)
        return result


def parse_timing(spec: str) -> int:
    """Parse timing spec: 'T4', '4', 'aggressive' → int 0-5."""
    spec = spec.strip().upper()
    mapping = {
        "T0": 0, "PARANOID": 0,
        "T1": 1, "SNEAKY": 1,
        "T2": 2, "POLITE": 2,
        "T3": 3, "NORMAL": 3,
        "T4": 4, "AGGRESSIVE": 4,
        "T5": 5, "INSANE": 5,
    }
    if spec in mapping:
        return mapping[spec]
    try:
        v = int(spec.lstrip("T"))
        return max(0, min(5, v))
    except ValueError:
        return 4  # default T4


def build_evasion(
    timing:          int   = 4,
    ttl:             int   = 64,
    fragment:        bool  = False,
    bad_checksum:    bool  = False,
    decoys:          int   = 0,
    decoy_ips:       Optional[List[str]] = None,
    source_port:     int   = 0,
    data_length:     int   = 0,
    randomize:       bool  = True,
    randomize_hosts: bool  = False,
    jitter:          float = 0.0,
    min_rate:        float = 0.0,
    max_rate:        float = 0.0,
) -> EvasionConfig:
    """Convenience constructor for EvasionConfig."""
    return EvasionConfig(
        timing=timing, ttl=ttl, fragment=fragment,
        bad_checksum=bad_checksum, decoys=decoys,
        decoy_ips=decoy_ips or [], source_port=source_port,
        data_length=data_length, randomize=randomize,
        randomize_hosts=randomize_hosts, jitter_pct=jitter,
        min_rate=min_rate, max_rate=max_rate,
    )


# ── CLI helpers ───────────────────────────────────────────────────────────────

def timing_summary(t: int) -> str:
    from lightscan.scan.rawscan import TIMING
    tmpl = TIMING[t]
    return (f"T{t} {tmpl.name}: timeout={tmpl.timeout}s "
            f"rate={tmpl.min_rate:.0f}-{tmpl.max_rate:.0f}pps "
            f"parallelism={tmpl.parallelism} retries={tmpl.retries}")


def print_timing_table():
    from lightscan.scan.rawscan import TIMING
    print("\n\033[38;5;196m[TIMING]\033[0m Available timing templates:\n")
    for i, tmpl in TIMING.items():
        print(f"  T{i}  {tmpl.name:<12} "
              f"timeout={tmpl.timeout:>6.1f}s  "
              f"rate={tmpl.min_rate:>6.0f}-{tmpl.max_rate:>6.0f} pps  "
              f"parallel={tmpl.parallelism:>4}  "
              f"retries={tmpl.retries}")
    print()
