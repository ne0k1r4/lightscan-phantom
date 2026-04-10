"""
LightScan v2.0 PHANTOM — Adaptive Timing Engine | Developer: Light
───────────────────────────────────────────────────────────────────
Adaptive timing: adjusts concurrency + rate based on:
  - RTT to target (latency-aware)
  - Packet loss rate (retry-aware)
  - Host responsiveness score
  - Network congestion signals

Equivalent to nmap's adaptive timing engine.
"""
from __future__ import annotations

import asyncio
import statistics
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class HostStats:
    """Per-host scan statistics for adaptive timing."""
    target:        str
    rtts:          List[float] = field(default_factory=list)
    sent:          int = 0
    responded:     int = 0
    timeouts:      int = 0
    retries:       int = 0
    start_time:    float = field(default_factory=time.monotonic)

    @property
    def loss_rate(self) -> float:
        if self.sent == 0: return 0.0
        return self.timeouts / self.sent

    @property
    def responsiveness(self) -> float:
        """0.0 (unresponsive) to 1.0 (fully responsive)."""
        if self.sent == 0: return 0.5
        return min(1.0, self.responded / max(1, self.sent))

    @property
    def avg_rtt(self) -> float:
        if not self.rtts: return 0.3
        return statistics.mean(self.rtts)

    @property
    def rtt_stddev(self) -> float:
        if len(self.rtts) < 2: return 0.1
        return statistics.stdev(self.rtts)

    def record_rtt(self, rtt: float):
        self.rtts.append(rtt)
        # Keep rolling window of last 50 RTTs
        if len(self.rtts) > 50:
            self.rtts.pop(0)
        self.responded += 1

    def record_timeout(self):
        self.timeouts += 1


class AdaptiveTimingEngine:
    """
    Dynamically adjusts scan rate and concurrency based on network feedback.

    Algorithm:
      1. Start at configured timing template rate
      2. After each response, record RTT
      3. If loss_rate > 20%: halve the rate (network congestion)
      4. If loss_rate < 5% + RTT stable: increase rate by 10%
      5. Concurrency scales with responsiveness score
      6. Per-host retries based on observed packet loss
    """

    def __init__(self, base_timing: int = 4, max_concurrency: int = 512):
        from lightscan.scan.rawscan import TIMING
        self.tmpl           = TIMING[max(0, min(5, base_timing))]
        self.max_concurrency= max_concurrency
        self._rate          = self.tmpl.max_rate
        self._concurrency   = self.tmpl.parallelism
        self._host_stats:   Dict[str, HostStats] = {}
        self._global_sent   = 0
        self._global_recv   = 0
        self._last_adjust   = time.monotonic()
        self._lock          = asyncio.Lock()

    def get_stats(self, host: str) -> HostStats:
        if host not in self._host_stats:
            self._host_stats[host] = HostStats(target=host)
        return self._host_stats[host]

    async def record_response(self, host: str, rtt: float):
        async with self._lock:
            self.get_stats(host).record_rtt(rtt)
            self._global_recv += 1
            await self._maybe_adjust()

    async def record_timeout(self, host: str):
        async with self._lock:
            self.get_stats(host).record_timeout()
            await self._maybe_adjust()

    def record_sent(self, host: str):
        self.get_stats(host).sent += 1
        self._global_sent += 1

    async def _maybe_adjust(self):
        """Adjust rate and concurrency every 100 packets."""
        now = time.monotonic()
        if now - self._last_adjust < 0.5:
            return
        self._last_adjust = now

        if self._global_sent < 50:
            return

        global_loss = 1.0 - (self._global_recv / max(1, self._global_sent))

        if global_loss > 0.30:
            # Severe loss — cut rate by 50%
            self._rate = max(self.tmpl.min_rate, self._rate * 0.5)
            self._concurrency = max(4, self._concurrency // 2)
        elif global_loss > 0.10:
            # Moderate loss — reduce by 25%
            self._rate = max(self.tmpl.min_rate, self._rate * 0.75)
            self._concurrency = max(8, int(self._concurrency * 0.8))
        elif global_loss < 0.02:
            # Low loss — increase by 10% (capped at template max)
            self._rate = min(self.tmpl.max_rate, self._rate * 1.10)
            self._concurrency = min(self.max_concurrency,
                                    int(self._concurrency * 1.05))

    @property
    def current_rate(self) -> float:
        return self._rate

    @property
    def current_concurrency(self) -> int:
        return self._concurrency

    def recommended_timeout(self, host: str) -> float:
        """Calculate per-host timeout based on observed RTT."""
        stats = self.get_stats(host)
        if not stats.rtts:
            return self.tmpl.timeout
        # RTT + 2 standard deviations + base overhead
        timeout = stats.avg_rtt + 2 * stats.rtt_stddev + 0.1
        return max(0.5, min(self.tmpl.timeout, timeout))

    def recommended_retries(self, host: str) -> int:
        """Calculate retries based on packet loss."""
        stats = self.get_stats(host)
        if stats.loss_rate > 0.20:
            return min(3, self.tmpl.retries + 1)
        elif stats.loss_rate < 0.05:
            return max(0, self.tmpl.retries - 1)
        return self.tmpl.retries

    def summary(self) -> str:
        loss = 1.0 - (self._global_recv / max(1, self._global_sent))
        return (f"rate={self._rate:.0f}pps  "
                f"concurrency={self._concurrency}  "
                f"sent={self._global_sent}  "
                f"recv={self._global_recv}  "
                f"loss={loss:.1%}")
