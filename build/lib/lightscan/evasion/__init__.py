"""LightScan v2.0 PHANTOM — Evasion Layer | Developer: Light"""
from __future__ import annotations
import asyncio, random, struct, time
from typing import Optional

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "curl/8.7.1", "python-httpx/0.27.0", "Go-http-client/1.1",
]

class Jitter:
    def __init__(self, lo=0.0, hi=0.0): self.lo=lo; self.hi=hi
    async def sleep(self):
        if self.hi > 0: await asyncio.sleep(random.uniform(self.lo, self.hi))
    @classmethod
    def stealth(cls): return cls(2.0, 8.0)
    @classmethod
    def normal(cls): return cls(0.3, 1.5)
    @classmethod
    def off(cls): return cls(0.0, 0.0)

def random_ua(): return random.choice(UA_POOL)

class SOCKS5:
    def __init__(self, host, port, user="", passwd=""):
        self.host=host; self.port=port; self.user=user; self.passwd=passwd
    async def connect(self, dest_host, dest_port, timeout=10.0):
        r, w = await asyncio.wait_for(asyncio.open_connection(self.host, self.port), timeout=timeout)
        if self.user: w.write(b"\x05\x02\x00\x02")
        else:         w.write(b"\x05\x01\x00")
        await w.drain()
        choice = await asyncio.wait_for(r.read(2), timeout=timeout)
        if len(choice)<2 or choice[0]!=5: w.close(); raise ConnectionError("SOCKS5 handshake failed")
        if choice[1]==0x02:
            auth=(bytes([0x01,len(self.user)])+self.user.encode()+
                  bytes([len(self.passwd)])+self.passwd.encode())
            w.write(auth); await w.drain()
            ar=await asyncio.wait_for(r.read(2), timeout=timeout)
            if len(ar)<2 or ar[1]!=0: w.close(); raise ConnectionError("SOCKS5 auth failed")
        elif choice[1]!=0: w.close(); raise ConnectionError(f"SOCKS5 auth method {choice[1]} unsupported")
        dest=dest_host.encode()
        w.write(b"\x05\x01\x00\x03"+bytes([len(dest)])+dest+struct.pack("!H",dest_port))
        await w.drain()
        cr=await asyncio.wait_for(r.read(10), timeout=timeout)
        if len(cr)<2 or cr[1]!=0: w.close(); raise ConnectionError(f"SOCKS5 connect failed: {cr[1] if len(cr)>1 else '?'}")
        return r, w

class ProxyChain:
    def __init__(self, proxies):
        self._p=[SOCKS5(p["host"],p["port"],p.get("user",""),p.get("pass","")) for p in proxies]
        self._i=0
    def next(self): p=self._p[self._i%len(self._p)]; self._i+=1; return p
    def rand(self): return random.choice(self._p)
    async def connect(self, host, port, timeout=10.0): return await self.rand().connect(host,port,timeout)
    @staticmethod
    def from_file(path):
        import re; proxies=[]
        with open(path) as f:
            for line in f:
                line=line.strip()
                if not line or line.startswith("#"): continue
                m=re.match(r"(?:socks5://)?(?:([^:@]+):([^@]+)@)?([^:]+):(\d+)", line)
                if m: proxies.append({"user":m.group(1) or "","pass":m.group(2) or "","host":m.group(3),"port":int(m.group(4))})
        return ProxyChain(proxies)
