"""LightScan v2.0 PHANTOM — Brute Force Engine | Developer: Light"""
from __future__ import annotations
import asyncio, random, time, sys
from lightscan.core.engine import ScanResult, Severity

LOCKOUT_SIGS = [
    "account locked","too many attempts","temporarily disabled","account suspended",
    "try again later","locked out","intruder detection","authentication failure limit",
    "exceeded","blocked","banned","disabled","maximum attempts",
]
RATE_SIGS = ["rate limit","too many requests","throttl","429","503","slow down","blocked temporarily"]

class BruteEngine:
    def __init__(self, concurrency=16, timeout=8.0, jitter=(0.0,0.0),
                 lockout_threshold=5, max_retries=2, checkpoint=None, verbose=False):
        self.concurrency=concurrency; self.timeout=timeout; self.jitter=jitter
        self.lockout_threshold=lockout_threshold; self.max_retries=max_retries
        self.checkpoint=checkpoint; self.verbose=verbose
        self._fail={}; self._locked=set(); self._found=[]; self._total=0; self._done=0

    async def _jitter(self):
        lo,hi = self.jitter
        if hi>0: await asyncio.sleep(random.uniform(lo,hi))

    def _check_lockout(self, user, response):
        rl = response.lower()
        if any(s in rl for s in LOCKOUT_SIGS):
            self._locked.add(user)
            if self.checkpoint: self.checkpoint.mark_locked(user)
            return True
        self._fail[user] = self._fail.get(user,0)+1
        if self._fail[user] >= self.lockout_threshold:
            self._locked.add(user)
            if self.checkpoint: self.checkpoint.mark_locked(user)
            return True
        return False

    def _progress(self):
        pct=(self._done/self._total*100) if self._total else 0
        sys.stdout.write(
            f"\r\033[38;5;196m[BRUTE]\033[0m "
            f"{self._done}/{self._total} ({pct:.1f}%)  "
            f"\033[38;5;196mfound={len(self._found)}\033[0m  "
            f"locked={len(self._locked)}"
        ); sys.stdout.flush()

    async def _attempt(self, handler, user, passwd, target, port, protocol):
        async with self._sem:
            if user in self._locked: self._done+=1; return
            if self.checkpoint and self.checkpoint.already_tried(user,passwd):
                self._done+=1; self._progress(); return
            await self._jitter()
            for n in range(self.max_retries):
                try:
                    success, response = await asyncio.wait_for(handler(user,passwd), timeout=self.timeout)
                except asyncio.TimeoutError:
                    if n < self.max_retries-1: await asyncio.sleep(2**n); continue
                    break
                except Exception as e:
                    response=str(e); success=False
                if self.checkpoint: self.checkpoint.mark_tried(user,passwd)
                if success:
                    entry={"target":target,"port":port,"protocol":protocol,
                           "username":user,"password":passwd,"ts":time.time()}
                    self._found.append(entry)
                    if self.checkpoint: self.checkpoint.add_found(entry)
                    print(f"\n\033[38;5;196m[FOUND]\033[0m "
                          f"{protocol}://{target}:{port} → \033[38;5;196m{user}:{passwd}\033[0m")
                    break
                if self._check_lockout(user,response):
                    print(f"\n\033[38;5;240m[LOCKED]\033[0m {user} @ {target}"); break
                if any(s in response.lower() for s in RATE_SIGS):
                    wait=30+random.uniform(0,15)
                    print(f"\n\033[38;5;240m[RATE-LIMIT]\033[0m sleeping {wait:.0f}s")
                    await asyncio.sleep(wait); continue
                break
            self._done+=1; self._progress()

    async def run(self, handler, userlist, passwdlist, target, port, protocol, stop_on_first=False):
        self._found=[]; self._fail={}; self._locked=set(); self._done=0
        self._total=len(userlist)*len(passwdlist)
        self._sem=asyncio.Semaphore(self.concurrency)
        if self.checkpoint:
            for u in userlist:
                if self.checkpoint.is_locked(u): self._locked.add(u)
        tasks=[]
        for user in userlist:
            for passwd in passwdlist:
                tasks.append(self._attempt(handler,user,passwd,target,port,protocol))
                if stop_on_first and self._found: break
            if stop_on_first and self._found: break
        await asyncio.gather(*tasks)
        print()
        if self.checkpoint: self.checkpoint.flush()
        return [ScanResult(f"brute-{protocol}",f["target"],f["port"],
                "credential-found",Severity.CRITICAL,
                f"{f['username']}:{f['password']}",f) for f in self._found]

    def run_sync(self,*a,**k): return asyncio.run(self.run(*a,**k))

class CredentialSpray:
    def __init__(self, window=1800, max_per_window=1):
        self.window=window; self.max_pw=max_per_window; self._log={}
    def can_spray(self, user):
        now=time.time(); recent=[t for t in self._log.get(user,[]) if now-t<self.window]
        self._log[user]=recent; return len(recent)<self.max_pw
    def record(self, user): self._log.setdefault(user,[]).append(time.time())
    async def pairs(self, users, passwords, inter_delay=0.0):
        for passwd in passwords:
            for user in users:
                if self.can_spray(user): self.record(user); yield user, passwd
            if inter_delay>0: await asyncio.sleep(inter_delay)
