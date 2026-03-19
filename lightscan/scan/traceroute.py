"""LightScan v2.0 PHANTOM — Traceroute | Developer: Light"""
from __future__ import annotations
import asyncio, os, socket, struct, time
from lightscan.core.engine import ScanResult, Severity

async def tcp_traceroute(target, port=80, max_hops=30, timeout=2.0, resolve=True):
    try: dest_ip=socket.gethostbyname(target)
    except socket.gaierror: return []
    results=[]
    if os.geteuid()!=0:
        return await _connect_fallback(target, dest_ip, port, timeout)
    try:
        recv=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
        recv.settimeout(timeout)
    except PermissionError:
        return await _connect_fallback(target, dest_ip, port, timeout)
    send=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)
    try:
        for ttl in range(1, max_hops+1):
            send.setsockopt(socket.IPPROTO_IP,socket.IP_TTL,ttl)
            src_port=40000+ttl; t0=time.time()
            pkt=_syn("127.0.0.1",dest_ip,src_port,port)
            send.sendto(pkt,(dest_ip,port))
            hop_ip="*"; rtt=-1.0; hop_host=""
            try:
                _,addr=recv.recvfrom(1024); hop_ip=addr[0]; rtt=(time.time()-t0)*1000
                if resolve:
                    loop=asyncio.get_event_loop()
                    try: hop_host=await loop.run_in_executor(None,lambda ip: socket.gethostbyaddr(ip)[0], hop_ip)
                    except: pass
            except socket.timeout: pass
            lbl=f"{'* (no response)' if hop_ip=='*' else hop_ip}"
            if hop_host: lbl+=f" ({hop_host})"
            if rtt>=0: lbl+=f"  {rtt:.1f}ms"
            results.append(ScanResult("traceroute",target,ttl,"hop",Severity.INFO,
                f"TTL={ttl:2d}  {lbl}",{"ttl":ttl,"hop_ip":hop_ip,"rtt_ms":rtt,"host":hop_host}))
            if hop_ip==dest_ip: break
    finally: recv.close(); send.close()
    return results

def _syn(src,dst,sp,dp):
    ip=struct.pack("!BBHHHBBH4s4s",(4<<4)|5,0,0,54321,0,64,socket.IPPROTO_TCP,0,
        socket.inet_aton("127.0.0.1"),socket.inet_aton(dst))
    tcp=struct.pack("!HHLLBBHHH",sp,dp,0,0,(5<<4),0x002,socket.htons(5840),0,0)
    return ip+tcp

async def _connect_fallback(target, dest_ip, port, timeout):
    results=[]
    t0=time.time()
    try:
        _,w=await asyncio.wait_for(asyncio.open_connection(dest_ip,port),timeout=timeout)
        w.close(); rtt=(time.time()-t0)*1000
        results.append(ScanResult("traceroute",target,port,"hop",Severity.INFO,
            f"Hop ~1: {dest_ip}  {rtt:.1f}ms (TCP connect estimate)",{"ttl":1,"hop_ip":dest_ip,"rtt_ms":rtt}))
    except Exception: pass
    return results
