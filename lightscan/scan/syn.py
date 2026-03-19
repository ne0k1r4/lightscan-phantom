"""
LightScan v2.0 PHANTOM — Raw SYN Scanner
Developer: Light (Neok1ra)

Integration of:
  • Python/Scapy SYN scanner (threaded, full open/filtered/closed classification)
  • C SYN scanner (compiled at runtime for max speed if gcc available)

Modes:
  syn_scan_scapy()   → Scapy-based, requires root, cross-platform
  syn_scan_c()       → Compiled C binary, fastest (~nmap speed), Linux only
  syn_scan_auto()    → Auto-picks best available method

Half-open scan: sends SYN → receives SYN-ACK → immediately sends RST
  • Never completes TCP handshake
  • Leaves fewer log entries than connect scan
  • 5-10x faster than connect scan on large ranges
"""
from __future__ import annotations
import asyncio, os, socket, struct, sys, time
from threading import Thread, Lock
from queue import Queue
from typing import Optional
from lightscan.core.engine import ScanResult, Severity
from lightscan.scan.portscan import SERVICE_MAP, CRIT_PORTS, HIGH_PORTS


# ─── Scapy SYN Scanner (your uploaded code — integrated + extended) ───────────

class SYNScanner:
    """
    Raw SYN scanner — port of your scapy implementation,
    integrated with LightScan's ScanResult system.
    """
    def __init__(self, target: str, ports: list, timeout=2.0, threads=100,
                 verbose=False, os_fingerprint=True):
        self.target   = target
        self.ports    = ports
        self.timeout  = timeout
        self.threads  = threads
        self.verbose  = verbose
        self.os_fingerprint = os_fingerprint
        self.open_ports     = []
        self.filtered_ports = []
        self.closed_ports   = []
        self.os_results     = []   # passive OS fingerprint results
        self.lock  = Lock()
        self.total = len(ports)
        self.done  = 0
        self._q    = None

    def _scan_port(self, port: int):
        """Send raw SYN, classify response — your algorithm + passive OS fingerprint"""
        try:
            from scapy.all import IP, TCP, sr1, send, RandShort
            ip  = IP(dst=self.target)
            tcp = TCP(sport=RandShort(), dport=port, flags="S", seq=1000)
            resp = sr1(ip/tcp, timeout=self.timeout, verbose=0)

            with self.lock:
                self.done += 1
                self._progress(port)

            if resp is None:
                with self.lock: self.filtered_ports.append(port)
                return

            if resp.haslayer(TCP):
                flags = resp.getlayer(TCP).flags
                if flags == 0x12:   # SYN-ACK → OPEN
                    with self.lock:
                        self.open_ports.append(port)
                        # ── Passive OS fingerprint from this SYN-ACK (zero extra packets)
                        if self.os_fingerprint:
                            try:
                                from lightscan.scan.os_detect import passive_engine
                                os_r = passive_engine().fingerprint_synack(resp, self.target, port)
                                if os_r: self.os_results.append(os_r)
                            except Exception: pass
                    # Send RST — don't complete handshake (stays half-open / stealthy)
                    rst = IP(dst=self.target) / TCP(
                        sport=resp.getlayer(TCP).dport,
                        dport=port,
                        flags="R",
                        seq=resp.getlayer(TCP).ack
                    )
                    send(rst, verbose=0)
                elif flags in (0x14, 0x04):   # RST-ACK or RST → CLOSED
                    with self.lock: self.closed_ports.append(port)

        except ImportError:
            raise RuntimeError("scapy required: pip install scapy")
        except Exception as e:
            if self.verbose: print(f"\n  [!] port {port}: {e}")

    def _progress(self, port):
        if self.verbose: return
        pct = (self.done / self.total * 100)
        sys.stdout.write(
            f"\r\033[38;5;196m[SYN]\033[0m "
            f"{self.done}/{self.total} ({pct:.1f}%)  "
            f"open=\033[38;5;196m{len(self.open_ports)}\033[0m  "
            f"port={port:<6}"
        )
        sys.stdout.flush()

    def _worker(self):
        while True:
            port = self._q.get()
            if port is None: break
            self._scan_port(port)
            self._q.task_done()

    def scan(self) -> list:
        if os.geteuid() != 0:
            raise PermissionError("SYN scan requires root (raw socket)")
        try:
            self.target = socket.gethostbyname(self.target)
        except Exception: pass

        print(f"\033[38;5;196m[SYN]\033[0m {self.target} | {self.total} ports | {self.threads} threads | half-open")
        t0 = time.time()
        self._q = Queue()
        for p in self.ports: self._q.put(p)

        threads = []
        for _ in range(self.threads):
            t = Thread(target=self._worker); t.daemon=True; t.start(); threads.append(t)

        self._q.join()
        for _ in range(self.threads): self._q.put(None)
        for t in threads: t.join()

        elapsed = time.time() - t0
        print(f"\n\033[38;5;196m[SYN]\033[0m Done in {elapsed:.2f}s — "
              f"open=\033[38;5;196m{len(self.open_ports)}\033[0m  "
              f"filtered={len(self.filtered_ports)}  closed={len(self.closed_ports)}")

        results = []
        for port in sorted(self.open_ports):
            sev = Severity.CRITICAL if port in CRIT_PORTS else Severity.HIGH if port in HIGH_PORTS else Severity.INFO
            service = SERVICE_MAP.get(port, f"port/{port}")
            results.append(ScanResult(
                "syn-scan", self.target, port, "open",
                sev, f"{service} [SYN-half-open]",
                {"method": "syn", "service": service}
            ))
        for port in sorted(self.filtered_ports):
            results.append(ScanResult(
                "syn-scan", self.target, port, "filtered",
                Severity.INFO, f"{SERVICE_MAP.get(port,'?')} [filtered/no-response]"
            ))
        # Attach deduplicated passive OS fingerprint results
        seen_hosts = set()
        for r in self.os_results:
            if r.target not in seen_hosts:
                seen_hosts.add(r.target)
                results.append(r)
        return results


# ─── C SYN Scanner (your uploaded C code — compiled at runtime) ───────────────

_C_SRC = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>

#define MAX_PORTS 65536
#define THREADS 100

struct pseudo_header {
    uint32_t src; uint32_t dst;
    uint8_t  placeholder; uint8_t protocol; uint16_t tcp_length;
};

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b; unsigned int sum=0; unsigned short result;
    for(sum=0;len>1;len-=2) sum += *buf++;
    if(len==1) sum += *(unsigned char*)buf;
    sum = (sum>>16)+(sum&0xFFFF); sum += (sum>>16); result=~sum; return result;
}

int raw_sock;
char open_ports[MAX_PORTS];
char filtered_ports[MAX_PORTS];

// Receive thread — sniffs for SYN-ACK / RST replies
void *recv_thread(void *arg) {
    int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(recv_sock < 0) return NULL;
    struct timeval tv = {5, 0};
    setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    char buf[4096];
    time_t *stop = (time_t*)arg;
    while(time(NULL) < *stop) {
        int n = recv(recv_sock, buf, sizeof(buf), 0);
        if(n < 1) continue;
        struct iphdr  *iph  = (struct iphdr*)buf;
        if(iph->protocol != IPPROTO_TCP) continue;
        struct tcphdr *tcph = (struct tcphdr*)(buf + iph->ihl*4);
        int sport = ntohs(tcph->source);
        if(sport < 1 || sport > 65535) continue;
        if(tcph->syn && tcph->ack) {
            open_ports[sport] = 1;
            // Send RST
            char pkt[sizeof(struct iphdr)+sizeof(struct tcphdr)];
            memset(pkt,0,sizeof(pkt));
            struct iphdr  *ri = (struct iphdr*)pkt;
            struct tcphdr *rt = (struct tcphdr*)(pkt+sizeof(struct iphdr));
            ri->ihl=5; ri->version=4; ri->ttl=64; ri->protocol=IPPROTO_TCP;
            ri->tot_len = htons(sizeof(pkt));
            ri->saddr = iph->daddr; ri->daddr = iph->saddr;
            rt->source = tcph->dest; rt->dest = tcph->source;
            rt->seq = tcph->ack_seq; rt->doff=5; rt->rst=1; rt->window=0;
            struct pseudo_header ph={ri->saddr,ri->daddr,0,IPPROTO_TCP,htons(sizeof(struct tcphdr))};
            char pg[sizeof(ph)+sizeof(struct tcphdr)];
            memcpy(pg,&ph,sizeof(ph)); memcpy(pg+sizeof(ph),rt,sizeof(struct tcphdr));
            rt->check = checksum(pg,sizeof(pg));
            ri->check = checksum(pkt,sizeof(struct iphdr));
            struct sockaddr_in dst={AF_INET,rt->dest,{ri->daddr}};
            sendto(raw_sock,pkt,sizeof(pkt),0,(struct sockaddr*)&dst,sizeof(dst));
        }
    }
    close(recv_sock); return NULL;
}

typedef struct { struct in_addr target; int *ports; int count; } tdata;

void *send_thread(void *arg) {
    tdata *d = (tdata*)arg;
    for(int i=0;i<d->count;i++) {
        int port=d->ports[i]; int sp=1024+(rand()%60000);
        char pkt[sizeof(struct iphdr)+sizeof(struct tcphdr)];
        memset(pkt,0,sizeof(pkt));
        struct iphdr  *iph  = (struct iphdr*)pkt;
        struct tcphdr *tcph = (struct tcphdr*)(pkt+sizeof(struct iphdr));
        iph->ihl=5; iph->version=4; iph->tos=0;
        iph->tot_len=htons(sizeof(pkt)); iph->id=htonl(54321);
        iph->ttl=64; iph->protocol=IPPROTO_TCP; iph->daddr=d->target.s_addr;
        tcph->source=htons(sp); tcph->dest=htons(port);
        tcph->seq=htonl(1000); tcph->doff=5; tcph->syn=1; tcph->window=htons(4096);
        struct pseudo_header ph={iph->saddr,iph->daddr,0,IPPROTO_TCP,htons(sizeof(struct tcphdr))};
        char pg[sizeof(ph)+sizeof(struct tcphdr)];
        memcpy(pg,&ph,sizeof(ph)); memcpy(pg+sizeof(ph),tcph,sizeof(struct tcphdr));
        tcph->check=checksum(pg,sizeof(pg));
        iph->check=checksum(pkt,sizeof(struct iphdr));
        struct sockaddr_in dst={AF_INET,tcph->dest,{iph->daddr}};
        sendto(raw_sock,pkt,ntohs(iph->tot_len),0,(struct sockaddr*)&dst,sizeof(dst));
        usleep(500);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    if(argc < 3) { fprintf(stderr,"usage: %s <ip> <p1,p2,p3 or start-end>\n",argv[0]); return 1; }
    if(geteuid()!=0) { fprintf(stderr,"need root\n"); return 1; }
    raw_sock = socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
    if(raw_sock<0) { perror("socket"); return 1; }
    int one=1; setsockopt(raw_sock,IPPROTO_IP,IP_HDRINCL,&one,sizeof(one));
    struct in_addr target; inet_aton(argv[1],&target);
    int ports[MAX_PORTS]; int pc=0;
    if(strchr(argv[2],'-') && !strchr(argv[2],',')) {
        int s,e; sscanf(argv[2],"%d-%d",&s,&e);
        for(int i=s;i<=e&&pc<MAX_PORTS;i++) ports[pc++]=i;
    } else {
        char tmp[65536]; strncpy(tmp,argv[2],sizeof(tmp)-1);
        char *tok=strtok(tmp,",");
        while(tok&&pc<MAX_PORTS) { ports[pc++]=atoi(tok); tok=strtok(NULL,","); }
    }
    memset(open_ports,0,MAX_PORTS); memset(filtered_ports,0,MAX_PORTS);
    time_t stop_recv=time(NULL)+10;
    pthread_t rt; pthread_create(&rt,NULL,recv_thread,&stop_recv);
    pthread_t threads[THREADS]; tdata td[THREADS];
    int ppt=pc/THREADS;
    for(int i=0;i<THREADS;i++) {
        int si=i*ppt; int cnt=(i==THREADS-1)?(pc-si):ppt;
        td[i]=(tdata){target,&ports[si],cnt};
        pthread_create(&threads[i],NULL,send_thread,&td[i]);
    }
    for(int i=0;i<THREADS;i++) pthread_join(threads[i],NULL);
    stop_recv=time(NULL)+2; pthread_join(rt,NULL);
    for(int p=1;p<MAX_PORTS;p++) if(open_ports[p]) printf("OPEN %d\n",p);
    close(raw_sock); return 0;
}
"""

_C_BIN: Optional[str] = None

def _compile_c_scanner():
    global _C_BIN
    if _C_BIN: return _C_BIN
    import tempfile, subprocess, shutil
    if not shutil.which("gcc"): return None
    src = tempfile.NamedTemporaryFile(suffix=".c", delete=False, mode="w")
    src.write(_C_SRC); src.close()
    bin_path = src.name.replace(".c","")
    r = subprocess.run(["gcc","-O2","-o",bin_path,src.name,"-lpthread"],
                       capture_output=True, text=True)
    if r.returncode == 0:
        _C_BIN = bin_path
        print(f"\033[38;5;196m[SYN-C]\033[0m Compiled C scanner: {bin_path}")
        return bin_path
    return None

def syn_scan_c(target: str, ports: list, timeout=5) -> list:
    """Run compiled C SYN scanner — fastest, ~nmap speed"""
    import subprocess, shutil
    if os.geteuid() != 0:
        raise PermissionError("C SYN scan requires root")
    bin_path = _compile_c_scanner()
    if not bin_path:
        raise RuntimeError("gcc not found — use scapy mode")

    port_str = ",".join(str(p) for p in ports)
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        ip = target

    t0 = time.time()
    print(f"\033[38;5;196m[SYN-C]\033[0m {ip} | {len(ports)} ports | compiled C + pthreads")
    r = subprocess.run([bin_path, ip, port_str], capture_output=True, text=True, timeout=timeout+15)
    elapsed = time.time() - t0

    results = []
    for line in r.stdout.splitlines():
        if line.startswith("OPEN "):
            port = int(line.split()[1])
            sev  = Severity.CRITICAL if port in CRIT_PORTS else Severity.HIGH if port in HIGH_PORTS else Severity.INFO
            service = SERVICE_MAP.get(port, f"port/{port}")
            results.append(ScanResult(
                "syn-scan-c", ip, port, "open", sev,
                f"{service} [SYN/C]", {"method":"syn-c","service":service}
            ))
    print(f"\033[38;5;196m[SYN-C]\033[0m Done in {elapsed:.2f}s — open={len(results)}")
    return results

def syn_scan_auto(target: str, ports: list, timeout=2.0, threads=100, verbose=False, prefer_c=False) -> list:
    """Auto-pick best SYN method: C > Scapy > connect fallback"""
    if os.geteuid() != 0:
        print("\033[38;5;240m[!] Not root — SYN scan unavailable, falling back to connect scan\033[0m")
        from lightscan.scan.portscan import build_scan_tasks
        from lightscan.core.engine import PhantomEngine
        engine = PhantomEngine(concurrency=256, timeout=timeout)
        tasks  = build_scan_tasks([target], ports, timeout)
        return engine.run_sync(tasks)

    try:
        if prefer_c:
            return syn_scan_c(target, ports, int(timeout))
        else:
            return SYNScanner(target, ports, timeout, threads, verbose).scan()
    except Exception as e:
        print(f"\033[38;5;240m[!] SYN mode failed ({e}) — falling back to connect scan\033[0m")
        from lightscan.scan.portscan import build_scan_tasks
        from lightscan.core.engine import PhantomEngine
        engine = PhantomEngine(concurrency=256, timeout=timeout)
        tasks  = build_scan_tasks([target], ports, timeout)
        return engine.run_sync(tasks)
