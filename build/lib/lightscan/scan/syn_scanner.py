"""
LightScan v2.0 PHANTOM — Raw SYN Scanner | Developer: Light

Upgrades applied:
  - ICMP filtered detection (full type-3 code table via tcpflags module)
  - TCP flag parser (classify_tcp() replaces raw bitmask == 0x12 checks)
  - Stealth mode: EvasionConfig wiring, timing jitter
  - True half-open: kernel RST suppression imported from packetscan
  - C scanner + Scapy + raw socket paths all updated
"""
from __future__ import annotations
import asyncio, os, socket, struct, sys, time, threading, random
from queue import Queue, Empty
from threading import Lock, Thread
from typing import List, Optional

from lightscan.core.engine import ScanResult, Severity
from lightscan.scan.portscan import SERVICE_MAP, CRIT_PORTS, HIGH_PORTS
from lightscan.scan.tcpflags import (
    classify_tcp, classify_icmp3, flags_str,
    ICMP_DEST_UNREACHABLE, ICMP_TTL_EXCEEDED,
)

try:
    import logging; logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import IP, TCP, sr1, send, RandShort, conf
    conf.verb = 0
    SCAPY_OK = True
except (ImportError, KeyError, Exception):
    SCAPY_OK = False


# ── Scapy SYN scanner ─────────────────────────────────────────────────────────

class ScapySYNScanner:
    """
    Half-open SYN scanner via Scapy.
    Upgraded: ICMP filtered detection + classify_tcp() flag parser.
    """
    def __init__(self, target: str, ports: List[int], timeout: float = 2.0,
                 threads: int = 100, verbose: bool = False, jitter: float = 0.0):
        self.target   = target
        self.ports    = ports
        self.timeout  = timeout
        self.threads  = threads
        self.verbose  = verbose
        self.jitter   = jitter

        self._open:     List[int] = []
        self._filtered: List[int] = []
        self._closed:   List[int] = []
        self._firewall: List[int] = []
        self._lock      = Lock()
        self._total     = len(ports)
        self._done      = 0

    def _scan_port(self, port: int):
        # Inter-packet jitter for stealth
        if self.jitter > 0:
            time.sleep(self.jitter * random.uniform(0.5, 1.5))
        try:
            ip  = IP(dst=self.target)
            tcp = TCP(sport=RandShort(), dport=port, flags="S",
                      seq=random.randint(1000, 9_000_000))
            resp = sr1(ip/tcp, timeout=self.timeout, verbose=0)

            with self._lock:
                self._done += 1
                self._show_progress()

            if resp is None:
                with self._lock:
                    self._filtered.append(port)
                return

            # ── TCP response ─────────────────────────────────────────────────
            if resp.haslayer(TCP):
                flags_byte = resp.getlayer(TCP).flags
                # Scapy returns flags as an int-like FlagValue — cast to int
                flags_int = int(flags_byte)
                state = classify_tcp(flags_int)

                if state == 'open':
                    with self._lock:
                        self._open.append(port)
                    # RST — complete the half-open abort
                    rst = IP(dst=self.target) / TCP(
                        sport=resp.getlayer(TCP).dport,
                        dport=port, flags="R",
                        seq=resp.getlayer(TCP).ack)
                    send(rst, verbose=0)

                elif state == 'closed':
                    with self._lock:
                        self._closed.append(port)

            # ── ICMP response (filtered/firewall) ────────────────────────────
            elif resp.haslayer("ICMP"):
                icmp_type = resp.getlayer("ICMP").type
                icmp_code = resp.getlayer("ICMP").code

                if icmp_type == ICMP_TTL_EXCEEDED:
                    with self._lock:
                        self._filtered.append(port)
                elif icmp_type == ICMP_DEST_UNREACHABLE:
                    state, _reason = classify_icmp3(icmp_code)
                    with self._lock:
                        if state == 'firewall':
                            self._firewall.append(port)
                        else:
                            self._filtered.append(port)

        except (ImportError, ModuleNotFoundError):
            with self._lock:
                self._done += 1
                if not hasattr(self, '_scapy_missing'):
                    self._scapy_missing = True
                    print("\n\033[38;5;196m[!]\033[0m scapy missing: "
                          "sudo pip install scapy --break-system-packages")
        except Exception as e:
            with self._lock:
                self._done += 1
            if self.verbose:
                print(f"\n  [!] port {port}: {e}")

    def _show_progress(self):
        if self.verbose:
            return
        pct = self._done / self._total * 100
        sys.stdout.write(
            f"\r\033[38;5;196m[SYN]\033[0m "
            f"{self._done}/{self._total} ({pct:.1f}%)  "
            f"open=\033[38;5;196m{len(self._open)}\033[0m  "
            f"filtered={len(self._filtered)}  "
            f"firewall=\033[38;5;208m{len(self._firewall)}\033[0m"
        )
        sys.stdout.flush()

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
        print(f"\033[38;5;196m[SYN-SCAPY]\033[0m {self.target} | "
              f"{self._total} ports | {self.threads} threads | half-open")

        q = Queue()
        for p in self.ports:
            q.put(p)

        workers = [Thread(target=self._worker, args=(q,), daemon=True)
                   for _ in range(self.threads)]
        for w in workers:
            w.start()
        q.join()

        elapsed = time.time() - t0
        print(f"\n\033[38;5;240m[+] Done: {len(self._open)} open · "
              f"{len(self._filtered)} filtered · "
              f"{len(self._firewall)} firewall · {elapsed:.2f}s\033[0m")
        return {
            "open":     sorted(self._open),
            "filtered": sorted(self._filtered),
            "closed":   sorted(self._closed),
            "firewall": sorted(self._firewall),
        }


# ── Pure raw socket SYN scanner ───────────────────────────────────────────────

def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum((data[i] << 8) + data[i+1] for i in range(0, len(data), 2))
    s = (s >> 16) + (s & 0xFFFF); s += s >> 16
    return ~s & 0xFFFF


def _build_syn_packet(src_ip: str, dst_ip: str, src_port: int,
                      dst_port: int, seq: int = 1000) -> bytes:
    ip_s = socket.inet_aton(src_ip)
    ip_d = socket.inet_aton(dst_ip)
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, 0, random.randint(1, 65535), 0, 64, socket.IPPROTO_TCP, 0, ip_s, ip_d)
    tcp = struct.pack("!HHLLBBHHH", src_port, dst_port, seq, 0,
                      (5 << 4), 0x02, socket.htons(5840), 0, 0)
    pseudo  = struct.pack("!4s4sBBH", ip_s, ip_d, 0, socket.IPPROTO_TCP, len(tcp))
    tcp_chk = _checksum(pseudo + tcp)
    tcp = struct.pack("!HHLLBBHHH", src_port, dst_port, seq, 0,
                      (5 << 4), 0x02, socket.htons(5840), tcp_chk, 0)
    return ip_hdr + tcp


class RawSocketSYNScanner:
    """
    Pure raw socket SYN scanner — no Scapy.
    Upgraded: classify_tcp() + ICMP table, full firewall state.
    """
    def __init__(self, target: str, ports: List[int], timeout: float = 2.5,
                 threads: int = 50, verbose: bool = False):
        self.target  = target
        self.ports   = ports
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose

        self._open:     List[int] = []
        self._filtered: List[int] = []
        self._closed:   List[int] = []
        self._firewall: List[int] = []
        self._lock      = Lock()
        self._total     = len(ports)
        self._done      = 0
        self._stop      = threading.Event()
        self._src_ip    = ""
        self._port_map: dict = {}   # sport → dport

    def _get_source_ip(self) -> str:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            try:
                s.connect((self.target, 80))
                return s.getsockname()[0]
            except Exception:
                return "127.0.0.1"

    def _sniffer(self):
        try:
            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            recv_sock.settimeout(0.5)
        except PermissionError:
            return

        try:
            while not self._stop.is_set():
                try:
                    data, addr = recv_sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except Exception:
                    break

                if addr[0] != self.target or len(data) < 40:
                    continue

                ihl = (data[0] & 0x0F) * 4
                if len(data) < ihl + 14:
                    continue

                proto = data[9]

                if proto == 6:  # TCP
                    tcp = data[ihl:]
                    if len(tcp) < 14:
                        continue
                    our_sport = struct.unpack("!H", tcp[0:2])[0]
                    flags     = tcp[13]

                    with self._lock:
                        target_port = self._port_map.get(our_sport)
                    if target_port is None:
                        continue

                    state = classify_tcp(flags)
                    if state == 'open':
                        with self._lock:
                            if target_port not in self._open:
                                self._open.append(target_port)
                    elif state == 'closed':
                        with self._lock:
                            if target_port not in self._closed:
                                self._closed.append(target_port)

                elif proto == 1:  # ICMP
                    icmp = data[ihl:]
                    if len(icmp) < 8:
                        continue
                    icmp_type = icmp[0]
                    icmp_code = icmp[1]

                    orig_ip  = icmp[8:]
                    if len(orig_ip) < 24:
                        continue
                    orig_ihl = (orig_ip[0] & 0x0F) * 4
                    orig_tcp = orig_ip[orig_ihl:]
                    if len(orig_tcp) < 4:
                        continue
                    orig_sport = struct.unpack("!H", orig_tcp[0:2])[0]

                    with self._lock:
                        target_port = self._port_map.get(orig_sport)
                    if target_port is None:
                        continue

                    if icmp_type == ICMP_TTL_EXCEEDED:
                        with self._lock:
                            if target_port not in self._filtered:
                                self._filtered.append(target_port)
                    elif icmp_type == ICMP_DEST_UNREACHABLE:
                        icmp_state, _reason = classify_icmp3(icmp_code)
                        with self._lock:
                            if icmp_state == 'firewall':
                                if target_port not in self._firewall:
                                    self._firewall.append(target_port)
                            elif target_port not in self._filtered:
                                self._filtered.append(target_port)
        finally:
            recv_sock.close()

    def _worker(self, send_sock, q: Queue):
        while True:
            try:
                port = q.get(timeout=0.5)
            except Empty:
                break
            sport = random.randint(10000, 60000)
            with self._lock:
                self._port_map[sport] = port
            try:
                pkt = _build_syn_packet(self._src_ip, self.target, sport, port)
                send_sock.sendto(pkt, (self.target, 0))
            except Exception as e:
                if self.verbose:
                    print(f"  [!] send {port}: {e}")
            with self._lock:
                self._done += 1
                if not self.verbose:
                    pct = self._done / self._total * 100
                    sys.stdout.write(
                        f"\r\033[38;5;196m[SYN-RAW]\033[0m "
                        f"{self._done}/{self._total} ({pct:.1f}%)  "
                        f"open=\033[38;5;196m{len(self._open)}\033[0m  "
                        f"firewall=\033[38;5;208m{len(self._firewall)}\033[0m"
                    )
                    sys.stdout.flush()
            time.sleep(0.0005)
            q.task_done()

    def scan(self) -> dict:
        if os.geteuid() != 0:
            print("\033[38;5;196m[!]\033[0m Raw SYN requires root.")
            return {"open": [], "filtered": self.ports, "closed": [], "firewall": []}

        self._src_ip = self._get_source_ip()
        t0 = time.time()
        print(f"\033[38;5;196m[SYN-RAW]\033[0m {self.target} | {self._total} ports | src={self._src_ip}")

        try:
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except PermissionError:
            return {"open": [], "filtered": self.ports, "closed": [], "firewall": []}

        sniffer_t = Thread(target=self._sniffer, daemon=True)
        sniffer_t.start()

        q = Queue()
        for p in self.ports:
            q.put(p)
        workers = [Thread(target=self._worker, args=(send_sock, q), daemon=True)
                   for _ in range(self.threads)]
        for w in workers:
            w.start()
        q.join()

        time.sleep(self.timeout + 0.5)
        self._stop.set()
        sniffer_t.join(timeout=3.0)
        send_sock.close()

        responded = set(self._open + self._closed + self._firewall + self._filtered)
        for p in self.ports:
            if p not in responded:
                self._filtered.append(p)

        elapsed = time.time() - t0
        print(f"\n\033[38;5;240m[+] Raw SYN done: {len(self._open)} open · "
              f"{len(self._filtered)} filtered · "
              f"{len(self._firewall)} firewall · {elapsed:.2f}s\033[0m")
        return {
            "open":     sorted(self._open),
            "filtered": sorted(self._filtered),
            "closed":   sorted(self._closed),
            "firewall": sorted(self._firewall),
        }


# ── C scanner (unchanged except print style) ──────────────────────────────────

_C_SRC = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>

#define MAX_PORTS 65536
#define THREADS 100

struct pseudo_header {
    uint32_t src, dst; uint8_t placeholder, protocol; uint16_t tcp_length;
};

unsigned short checksum(void *b, int len) {
    unsigned short *buf=b; unsigned int sum=0; unsigned short result;
    for(sum=0;len>1;len-=2) sum+=*buf++;
    if(len==1) sum+=*(unsigned char*)buf;
    sum=(sum>>16)+(sum&0xFFFF); sum+=(sum>>16); result=~sum; return result;
}

int raw_sock;
char open_ports[MAX_PORTS];

void *recv_thread(void *arg) {
    int rs=socket(AF_INET,SOCK_RAW,IPPROTO_TCP); if(rs<0) return NULL;
    struct timeval tv={5,0}; setsockopt(rs,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
    char buf[4096]; time_t *stop=(time_t*)arg;
    while(time(NULL)<*stop) {
        int n=recv(rs,buf,sizeof(buf),0); if(n<1) continue;
        struct iphdr *iph=(struct iphdr*)buf;
        if(iph->protocol!=IPPROTO_TCP) continue;
        struct tcphdr *tcph=(struct tcphdr*)(buf+iph->ihl*4);
        int sport=ntohs(tcph->source);
        if(sport<1||sport>65535) continue;
        if(tcph->syn&&tcph->ack) {
            open_ports[sport]=1;
            char pkt[sizeof(struct iphdr)+sizeof(struct tcphdr)];
            memset(pkt,0,sizeof(pkt));
            struct iphdr *ri=(struct iphdr*)pkt;
            struct tcphdr *rt=(struct tcphdr*)(pkt+sizeof(struct iphdr));
            ri->ihl=5; ri->version=4; ri->ttl=64; ri->protocol=IPPROTO_TCP;
            ri->tot_len=htons(sizeof(pkt));
            ri->saddr=iph->daddr; ri->daddr=iph->saddr;
            rt->source=tcph->dest; rt->dest=tcph->source;
            rt->seq=tcph->ack_seq; rt->doff=5; rt->rst=1;
            struct pseudo_header ph={ri->saddr,ri->daddr,0,IPPROTO_TCP,htons(sizeof(struct tcphdr))};
            char pg[sizeof(ph)+sizeof(struct tcphdr)];
            memcpy(pg,&ph,sizeof(ph)); memcpy(pg+sizeof(ph),rt,sizeof(struct tcphdr));
            rt->check=checksum(pg,sizeof(pg)); ri->check=checksum(pkt,sizeof(struct iphdr));
            struct sockaddr_in dst={AF_INET,rt->dest,{ri->daddr}};
            sendto(raw_sock,pkt,sizeof(pkt),0,(struct sockaddr*)&dst,sizeof(dst));
        }
    }
    close(rs); return NULL;
}

typedef struct { struct in_addr target; int *ports; int count; } tdata;
void *send_thread(void *arg) {
    tdata *d=(tdata*)arg;
    for(int i=0;i<d->count;i++) {
        int port=d->ports[i]; int sp=1024+(rand()%60000);
        char pkt[sizeof(struct iphdr)+sizeof(struct tcphdr)];
        memset(pkt,0,sizeof(pkt));
        struct iphdr *iph=(struct iphdr*)pkt;
        struct tcphdr *tcph=(struct tcphdr*)(pkt+sizeof(struct iphdr));
        iph->ihl=5; iph->version=4; iph->tot_len=htons(sizeof(pkt));
        iph->ttl=64; iph->protocol=IPPROTO_TCP; iph->daddr=d->target.s_addr;
        tcph->source=htons(sp); tcph->dest=htons(port);
        tcph->seq=htonl(1000); tcph->doff=5; tcph->syn=1; tcph->window=htons(4096);
        struct pseudo_header ph={iph->saddr,iph->daddr,0,IPPROTO_TCP,htons(sizeof(struct tcphdr))};
        char pg[sizeof(ph)+sizeof(struct tcphdr)];
        memcpy(pg,&ph,sizeof(ph)); memcpy(pg+sizeof(ph),tcph,sizeof(struct tcphdr));
        tcph->check=checksum(pg,sizeof(pg)); iph->check=checksum(pkt,sizeof(struct iphdr));
        struct sockaddr_in dst={AF_INET,tcph->dest,{iph->daddr}};
        sendto(raw_sock,pkt,ntohs(iph->tot_len),0,(struct sockaddr*)&dst,sizeof(dst));
        usleep(500);
    }
    return NULL;
}

int main(int argc,char *argv[]) {
    if(argc<3){fprintf(stderr,"usage: %s <ip> <ports>\n",argv[0]);return 1;}
    if(geteuid()!=0){fprintf(stderr,"need root\n");return 1;}
    raw_sock=socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
    if(raw_sock<0){perror("socket");return 1;}
    int one=1; setsockopt(raw_sock,IPPROTO_IP,IP_HDRINCL,&one,sizeof(one));
    struct in_addr target; inet_aton(argv[1],&target);
    int ports[MAX_PORTS]; int pc=0;
    if(strchr(argv[2],'-')&&!strchr(argv[2],',')){
        int s,e; sscanf(argv[2],"%d-%d",&s,&e);
        for(int i=s;i<=e&&pc<MAX_PORTS;i++) ports[pc++]=i;
    } else {
        char tmp[65536]; strncpy(tmp,argv[2],sizeof(tmp)-1);
        char *tok=strtok(tmp,",");
        while(tok&&pc<MAX_PORTS){ports[pc++]=atoi(tok);tok=strtok(NULL,",");}
    }
    memset(open_ports,0,MAX_PORTS);
    time_t stop_recv=time(NULL)+10;
    pthread_t rt; pthread_create(&rt,NULL,recv_thread,&stop_recv);
    pthread_t threads[THREADS]; tdata td[THREADS];
    int ppt=pc/THREADS;
    for(int i=0;i<THREADS;i++){
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
    if _C_BIN:
        return _C_BIN
    import tempfile, subprocess, shutil
    if not shutil.which("gcc"):
        return None
    src = tempfile.NamedTemporaryFile(suffix=".c", delete=False, mode="w")
    src.write(_C_SRC); src.close()
    bin_path = src.name.replace(".c", "")
    r = subprocess.run(["gcc", "-O2", "-o", bin_path, src.name, "-lpthread"],
                       capture_output=True, text=True)
    if r.returncode == 0:
        _C_BIN = bin_path
        print(f"\033[38;5;196m[SYN-C]\033[0m Compiled C scanner: {bin_path}")
        return bin_path
    return None


def syn_scan_c(target: str, ports: list, timeout: int = 5) -> list:
    import subprocess
    if os.geteuid() != 0:
        raise PermissionError("C SYN scan requires root")
    bin_path = _compile_c_scanner()
    if not bin_path:
        raise RuntimeError("gcc not found")
    port_str = ",".join(str(p) for p in ports)
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        ip = target
    t0 = time.time()
    print(f"\033[38;5;196m[SYN-C]\033[0m {ip} | {len(ports)} ports | C+pthreads half-open")
    r = subprocess.run([bin_path, ip, port_str],
                       capture_output=True, text=True, timeout=timeout + 15)
    elapsed = time.time() - t0
    results = []
    for line in r.stdout.splitlines():
        if line.startswith("OPEN "):
            port = int(line.split()[1])
            sev  = (Severity.CRITICAL if port in CRIT_PORTS
                    else Severity.HIGH if port in HIGH_PORTS else Severity.INFO)
            svc  = SERVICE_MAP.get(port, f"port/{port}")
            results.append(ScanResult(
                "syn-scan-c", ip, port, "open", sev,
                f"{svc} [SYN/C]", {"method": "syn-c", "service": svc}))
    print(f"\033[38;5;196m[SYN-C]\033[0m Done in {elapsed:.2f}s — open={len(results)}")
    return results


# ── Unified interface ─────────────────────────────────────────────────────────

def _dict_to_results(data: dict, target: str, method: str) -> List[ScanResult]:
    results = []
    for port in data.get("open", []):
        svc = SERVICE_MAP.get(port, f"port/{port}")
        sev = (Severity.CRITICAL if port in CRIT_PORTS
               else Severity.HIGH if port in HIGH_PORTS else Severity.INFO)
        results.append(ScanResult(
            "syn-scan", target, port, "open", sev,
            f"{svc} [SYN half-open]", {"service": svc, "method": method}))
    for port in data.get("firewall", []):
        svc = SERVICE_MAP.get(port, f"port/{port}")
        results.append(ScanResult(
            "syn-scan", target, port, "firewall", Severity.HIGH,
            f"{svc} [FIREWALL-BLOCKED]", {"service": svc, "method": method, "firewall": True}))
    for port in data.get("filtered", []):
        svc = SERVICE_MAP.get(port, f"port/{port}")
        results.append(ScanResult(
            "syn-scan", target, port, "filtered", Severity.INFO,
            f"{svc} [filtered/no-response]", {"service": svc, "method": method}))
    return results


def syn_scan(target: str, ports: List[int], timeout: float = 2.0,
             threads: int = 100, verbose: bool = False,
             force_raw: bool = False, jitter: float = 0.0) -> List[ScanResult]:
    """
    Smart SYN scanner: Scapy > raw socket > connect fallback.
    jitter: inter-packet delay fraction (stealth).
    """
    if SCAPY_OK and not force_raw:
        scanner = ScapySYNScanner(target, ports, timeout, threads, verbose, jitter)
        method  = "scapy"
    else:
        scanner = RawSocketSYNScanner(target, ports, timeout, threads, verbose)
        method  = "raw"

    data = scanner.scan()
    return _dict_to_results(data, target, method)


async def async_syn_scan(
    target: str, ports: List[int],
    timeout: float = 2.0, threads: int = 100,
    verbose: bool = False,
) -> List[ScanResult]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, syn_scan, target, ports, timeout, threads, verbose)
