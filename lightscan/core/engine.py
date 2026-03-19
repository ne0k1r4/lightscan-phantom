"""LightScan v2.0 PHANTOM — Core Engine | Developer: Light"""
from __future__ import annotations
import asyncio, time, sys
from dataclasses import dataclass, field, asdict
from enum import Enum

class Severity(str, Enum):
    CRITICAL = "CRITICAL"; HIGH = "HIGH"; MEDIUM = "MEDIUM"
    LOW = "LOW"; INFO = "INFO"

@dataclass
class ScanResult:
    module:    str
    target:    str
    port:      int
    status:    str
    severity:  Severity = Severity.INFO
    detail:    str = ""
    data:      dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    def to_dict(self):
        d = asdict(self); d["severity"] = self.severity.value; return d

class PhantomEngine:
    def __init__(self, concurrency=256, timeout=3.0, verbose=False, rate_limit=0.0):
        self.concurrency = concurrency; self.timeout = timeout
        self.verbose = verbose; self.rate_limit = rate_limit
        self._sem = None; self._results = []; self._errors = []
        self._done = 0; self._total = 0; self._start = 0.0

    def _progress(self, label=""):
        elapsed = time.time() - self._start
        pct = (self._done / self._total * 100) if self._total else 0
        sys.stdout.write(
            f"\r\033[38;5;196m[PHANTOM]\033[0m "
            f"{self._done}/{self._total} ({pct:.1f}%)  "
            f"elapsed={elapsed:.1f}s  {label:<35}"
        ); sys.stdout.flush()

    async def _run_one(self, coro, label=""):
        async with self._sem:
            if self.rate_limit > 0: await asyncio.sleep(self.rate_limit)
            try:
                result = await asyncio.wait_for(coro, timeout=self.timeout)
                if result is not None:
                    if isinstance(result, list): self._results.extend(result)
                    else: self._results.append(result)
            except (asyncio.TimeoutError, Exception) as e:
                if not isinstance(e, asyncio.TimeoutError):
                    self._errors.append(f"{label}: {e}")
            finally:
                self._done += 1
                if not self.verbose: self._progress(label)

    async def run(self, tasks):
        self._sem = asyncio.Semaphore(self.concurrency); self._results = []
        self._errors = []; self._done = 0; self._total = len(tasks); self._start = time.time()
        await asyncio.gather(*[self._run_one(c, l) for c, l in tasks])
        print()
        elapsed = time.time() - self._start
        print(f"\033[38;5;240m[+] Done: {len(self._results)} results · {len(self._errors)} errors · {elapsed:.2f}s\033[0m")
        return self._results

    def run_sync(self, tasks): return asyncio.run(self.run(tasks))
