"""
LightScan v2.0 PHANTOM — CLI Entry Point
Developer: Light (Neok1ra)

Usage:
  lightscan --scan -t 192.168.1.0/24 -p top100
  lightscan --brute ssh -t 10.0.0.1 -U root,admin -W rockyou.txt
  lightscan --dns target.com
  lightscan --cve -t 10.0.0.1 --scan
  lightscan --oauth https://login.target.com/oauth/authorize --oauth-client CLIENT_ID
  lightscan --diff old.json new.json
"""
from __future__ import annotations
import argparse, asyncio, sys, time

from lightscan.banner import print_banner
from lightscan.core.engine import PhantomEngine, ScanResult, Severity
from lightscan.core.target import parse_targets, parse_ports
from lightscan.core.checkpoint import Checkpoint
from lightscan.core.reporter import Reporter
from lightscan.scan.portscan import build_scan_tasks
from lightscan.scan.dns import full_dns_enum
from lightscan.scan.traceroute import tcp_traceroute
from lightscan.scan.diff import diff_scans
from lightscan.brute.engine import BruteEngine, CredentialSpray
from lightscan.brute.mutation import MutationEngine, COMMON_PASSWORDS
from lightscan.brute.handlers import get_handler, PROTOCOLS
from lightscan.cve.checker import CVEChecker
from lightscan.cve.oauth import OAuthScanner


def build_parser():
    p = argparse.ArgumentParser(
        prog="lightscan",
        description="LightScan v2.0 PHANTOM — Async Network Recon & Attack Framework",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    # Target
    tg = p.add_argument_group("Target")
    tg.add_argument("-t","--target", help="IP / CIDR / range / hostname / file:path.txt")
    tg.add_argument("-p","--ports",  default="top100", help="Ports: 22,80,443 · 1-1024 · top100 (default)")
    tg.add_argument("--udp",         action="store_true", help="Include UDP scan (53,123,161)")
    tg.add_argument("--syn",         action="store_true", help="SYN half-open scan (requires root + scapy)")
    tg.add_argument("--syn-c",       action="store_true", help="SYN scan using compiled C binary (fastest, root+gcc)")
    tg.add_argument("--threads",     type=int, default=100, help="SYN scanner threads (default:100)")
    tg.add_argument("--raw",         action="store_true", help="Raw async SYN scan (root, epoll, nmap speed)")
    tg.add_argument("-T","--timing",  type=str, default="T4", metavar="T0-T5", help="Timing template: T0(paranoid) to T5(insane) [default: T4]")
    tg.add_argument("--ttl",         type=int, default=64,  help="IP TTL for raw scans (default: 64)")
    tg.add_argument("--decoy",       type=int, default=0,   metavar="N", help="Send N random decoy IPs alongside probes")
    tg.add_argument("--fragment",    action="store_true",   help="Fragment IP packets (IDS evasion)")
    tg.add_argument("--source-port", type=int, default=0,   metavar="PORT", help="Fix source port (e.g. 53 for firewall bypass)")
    tg.add_argument("--randomize",   action="store_true", default=True, help="Randomise port scan order (default: on)")
    tg.add_argument("--no-randomize",action="store_true",   help="Disable port order randomisation")
    tg.add_argument("-6","--ipv6",   action="store_true",   help="IPv6 scan (dual-stack resolution)")
    tg.add_argument("--ipv6-only",   action="store_true",   help="Scan IPv6 addresses only")
    tg.add_argument("--dual-stack",  action="store_true",   help="Scan both IPv4 and IPv6 addresses")
    tg.add_argument("--os-v2",       action="store_true",   help="Use improved OS fingerprint database (120+ signatures)")

    # Modules
    m = p.add_argument_group("Modules")
    m.add_argument("--scan",         action="store_true", help="Port scan")
    m.add_argument("--dns",          metavar="DOMAIN",    help="Full DNS enum on DOMAIN")
    m.add_argument("--no-axfr",      action="store_true", help="Skip AXFR zone transfer")
    m.add_argument("--no-crtsh",     action="store_true", help="Skip crt.sh CT lookup")
    m.add_argument("--no-brute-dns", action="store_true", help="Skip subdomain brute")
    m.add_argument("--os-probe",     action="store_true", help="Active T2-T7 OS fingerprinting (root+scapy, 6 extra packets per host)")
    m.add_argument("--os-passive",   action="store_true", help="Passive OS fingerprint from SYN-ACK (auto with --syn, zero extra packets)")
    m.add_argument("--os-port",      type=int,            help="Open port for --os-probe (auto-detected if omitted)")
    m.add_argument("--web-scan",     metavar="URL",       help="Full web application scan on URL (dir, tech, sqli, xss, cors, creds, jwt, files, secrets)")
    m.add_argument("--web-checks",   nargs="+", metavar="CHECK",
                   help="Web checks to run (dir tech sqli xss redirect cors creds jwt files secrets)")
    m.add_argument("--web-wordlist", metavar="FILE",      help="Wordlist file for --web-scan directory brute")
    m.add_argument("--web-threads",  type=int, default=10, help="Threads for web dir brute (default 10)")
    m.add_argument("--rdp-probe",    metavar="HOST",      help="RDP fingerprint probe (NLA/SSL/cert info)")
    m.add_argument("--cve",           action="store_true", help="CVE + template checks on open ports (legacy + template engine)")
    m.add_argument("--cve-list",      nargs="+",
        help="Specific CVEs: eternalblue log4shell spring4shell heartbleed shellshock redis-unauth mongo-unauth elastic-unauth")
    m.add_argument("--log4shell-callback", default="", help="Log4Shell OAST callback (e.g. your.interactsh.com)")
    m.add_argument("--templates",     action="store_true", help="Run template engine only (no legacy CVE checks)")
    m.add_argument("--template-dir",  metavar="DIR",       help="Extra template directory")
    m.add_argument("--template-tags", nargs="+", metavar="TAG", help="Filter templates by tag (redis unauth rce ...)")
    m.add_argument("--template-ids",  nargs="+", metavar="ID",  help="Run specific template IDs only")
    m.add_argument("--list-templates",action="store_true", help="List all loaded templates and exit")
    m.add_argument("--oauth",        metavar="AUTH_URL",  help="OAuth 2.0 audit on AUTH_URL")
    m.add_argument("--oauth-client", metavar="CLIENT_ID", help="OAuth client_id")
    m.add_argument("--oauth-redirect",metavar="URI",      help="OAuth redirect_uri")
    m.add_argument("--diff",         nargs=2, metavar=("OLD.json","NEW.json"), help="Diff two scan JSONs")
    m.add_argument("--traceroute",   metavar="HOST",      help="TCP traceroute to HOST")

    # Brute force
    bf = p.add_argument_group("Brute Force")
    bf.add_argument("--brute",       metavar="PROTO", help=f"Protocol: {', '.join(PROTOCOLS)}")
    bf.add_argument("--brute-port",  type=int,        help="Override brute port")
    bf.add_argument("-U","--users",  help="Users: admin,root | file:users.txt")
    bf.add_argument("-W","--wordlist",help="Passwords: file:path | 'common' | word1,word2")
    bf.add_argument("--mutate",      action="store_true", help="Apply smart mutation engine to wordlist")
    bf.add_argument("--spray",       action="store_true", help="Credential spray mode (1 pass × N users)")
    bf.add_argument("--spray-window",type=int,default=1800,help="Spray window seconds (default:1800)")
    bf.add_argument("--brute-conc",  type=int,default=16,  help="Brute concurrency (default:16)")
    bf.add_argument("--stop-first",  action="store_true",  help="Stop after first credential found")
    bf.add_argument("--jitter",      nargs=2,type=float,metavar=("MIN","MAX"),help="Brute jitter: --jitter 0.5 3.0")

    # HTTP brute
    hb = p.add_argument_group("HTTP Brute (--brute http)")
    hb.add_argument("--http-url",        help="Login form URL")
    hb.add_argument("--http-user-field", default="username")
    hb.add_argument("--http-pass-field", default="password")
    hb.add_argument("--http-success",    default="", help="Text on successful login")
    hb.add_argument("--http-failure",    default="", help="Text on failed login")
    hb.add_argument("--http-basic",      action="store_true", help="HTTP Basic Auth mode")

    # Engine
    en = p.add_argument_group("Engine")
    en.add_argument("--concurrency", type=int,   default=256,  help="Scan concurrency (default:256)")
    en.add_argument("--timeout",     type=float, default=3.0,  help="Connection timeout (default:3.0)")

    # Evasion
    ev = p.add_argument_group("Evasion")
    ev.add_argument("--proxy-file",  help="SOCKS5 proxy file (socks5://host:port per line)")

    # Output
    out = p.add_argument_group("Output")
    out.add_argument("-o","--output",     default=".", help="Output directory (default: .)")
    out.add_argument("--basename",        default="lightscan_report")
    out.add_argument("--no-report",       action="store_true", help="Skip file reports")
    out.add_argument("--resume",          action="store_true", help="Resume from checkpoint")
    out.add_argument("--clear-checkpoint",action="store_true", help="Clear checkpoint and start fresh")
    out.add_argument("-v","--verbose",    action="store_true", help="Verbose output")
    return p


def parse_userlist(spec):
    if not spec:
        return ["admin","root","administrator","user","test","guest","service","operator"]
    if spec.startswith("file:"):
        with open(spec[5:]) as f: return [l.strip() for l in f if l.strip()]
    return [u.strip() for u in spec.split(",")]

def parse_passwdlist(spec, users=None, target_info=None, mutate=False):
    if not spec: return list(COMMON_PASSWORDS)
    if spec.lower()=="common": base=list(COMMON_PASSWORDS)
    elif spec.startswith("file:"): base=MutationEngine.load_wordlist(spec[5:])
    else: base=[p.strip() for p in spec.split(",")]
    if mutate:
        eng=MutationEngine(base_words=base,target_info=target_info or {})
        expanded=[]
        for u in (users or [""]): expanded.extend(eng.generate(username=u))
        return list(dict.fromkeys(expanded))
    return base


async def async_main(args):
    print_banner()
    t_start=time.time(); all_results=[]; open_ports={}
    # Build target string — prefer --target, fall back to --web-scan URL
    _target = args.target or getattr(args, 'web_scan', None) or ""
    meta={"target":_target,"timestamp":t_start,"duration":0,"command":" ".join(sys.argv)}

    cp=Checkpoint()
    if args.clear_checkpoint: cp.clear()
    if args.target: cp.set_target(args.target)

    # ── Diff
    if args.diff:
        old_f,new_f=args.diff
        results,summary=diff_scans(old_f,new_f)
        print(f"\033[38;5;196m[DIFF]\033[0m {summary}")
        all_results.extend(results)

    # ── DNS
    if args.dns:
        r=await full_dns_enum(args.dns,axfr=not args.no_axfr,
            brute=not args.no_brute_dns,use_crtsh=not args.no_crtsh)
        all_results.extend(r)

    # ── Active OS Fingerprinting (T2-T7 multi-probe)
    if getattr(args, 'os_probe', False) and args.target:
        from lightscan.scan.os_detect import os_probe_async
        hosts = parse_targets(args.target)
        print(f"\033[38;5;196m[OS-PROBE]\033[0m Active fingerprinting {len(hosts)} host(s)")
        for host in hosts:
            # Use first known open port, or fall back to 80
            probe_port = getattr(args, 'os_port', None)
            if not probe_port:
                probe_port = open_ports.get(host, [80])[0] if open_ports.get(host) else 80
            os_results = await os_probe_async(host, probe_port)
            for r in os_results:
                print(f"  \033[38;5;196m[OS]\033[0m {r.target} → {r.detail}")
            all_results.extend(os_results)

    # ── Passive OS detection standalone (--os-passive without --syn)
    if getattr(args, 'os_passive', False) and not (args.syn or getattr(args,'syn_c',False)) and args.target:
        print(f"\033[38;5;240m[!] --os-passive works best with --syn (reads SYN-ACK packets)\033[0m")
        print(f"\033[38;5;240m    Without --syn, TTL-only estimation will be LOW confidence\033[0m")

    # ── Web Application Scan
    if getattr(args, 'web_scan', None):
        from lightscan.web.scanner import web_scan_async
        print(f"\033[38;5;196m[WEB-SCAN]\033[0m {args.web_scan}")
        web_results = await web_scan_async(
            args.web_scan,
            wordlist_file = getattr(args, 'web_wordlist', None),
            timeout  = args.timeout,
            threads  = getattr(args, 'web_threads', 10),
            checks   = getattr(args, 'web_checks', None),
        )
        all_results.extend(web_results)
        counts = {}
        for r in web_results:
            counts[r.severity.value] = counts.get(r.severity.value, 0) + 1
        SEV_ORDER = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
        summary = " | ".join(
            f"{counts[s]} {s}" for s in SEV_ORDER if s in counts
        )
        print(f"  \033[38;5;196m[WEB-SCAN DONE]\033[0m {len(web_results)} findings — {summary}")

        # ── Grouped terminal summary ──────────────────────────────────────
        from lightscan.core.reporter import _group_results
        raw_dicts = [r.to_dict() for r in web_results]
        grouped   = _group_results(raw_dicts)
        SEV_COLOR = {"CRITICAL":"\033[38;5;196m","HIGH":"\033[38;5;208m",
                     "MEDIUM":"\033[38;5;226m","LOW":"\033[38;5;40m","INFO":"\033[38;5;240m"}
        for r in grouped:
            sev = r.get("severity","INFO")
            if sev not in ("CRITICAL","HIGH","MEDIUM"): continue
            col  = SEV_COLOR.get(sev,"\033[0m")
            cnt  = r.get("count","")
            tag  = f" ×{cnt}" if cnt else ""
            det  = str(r.get("detail",""))
            print(f"    {col}[{sev}]\033[0m {r.get('module','')} — {det}{tag}")
            for url in r.get("urls",[])[:5]:
                print(f"      \033[38;5;240m↳ {url}\033[0m")


    # ── RDP Probe
    if getattr(args, 'rdp_probe', None):
        from lightscan.brute.handlers.rdp_raw import make_rdp_probe, RawRDPHandler
        print(f"\033[38;5;196m[RDP-PROBE]\033[0m {args.rdp_probe}")
        info = make_rdp_probe(args.rdp_probe, timeout=args.timeout)
        for k, v in info.items():
            print(f"  {k:<18}: {v}")
        sev = Severity.HIGH if info.get("nla_required") else Severity.CRITICAL
        all_results.append(ScanResult("rdp-probe", args.rdp_probe, 3389,
            info.get("status","?"), sev,
            f"RDP proto={info.get('protocol','?')} NLA={info.get('nla_required','?')}",
            info))

    # ── Traceroute
    if args.traceroute:
        tr=await tcp_traceroute(args.traceroute,timeout=args.timeout)
        for hop in tr: print(f"  {hop.detail}")
        all_results.extend(tr)

    # ── SYN Scan (half-open, raw socket)
    if (args.syn or getattr(args, 'syn_c', False)) and args.target:
        from lightscan.scan.syn import syn_scan_auto
        hosts = parse_targets(args.target); ports = parse_ports(args.ports)
        syn_results = []
        for host in hosts:
            r = syn_scan_auto(host, ports, args.timeout,
                              getattr(args,'threads',100), args.verbose,
                              prefer_c=getattr(args,'syn_c',False))
            syn_results.extend(r)
            for res in r:
                if res.status == "open":
                    open_ports.setdefault(res.target, []).append(res.port)
                    print(f"  \033[38;5;196mOPEN\033[0m  {res.target}:{res.port:<6} {res.detail}")
        all_results.extend(syn_results)

    # ── UDP Scan (dedicated module with ICMP classification)
    if args.udp and args.target:
        from lightscan.scan.udp import udp_scan
        udp_ports_default = [53, 67, 68, 69, 111, 123, 137, 161, 162,
                             389, 500, 514, 520, 1900, 4500, 5353, 5060]
        ports = parse_ports(args.ports) if args.ports else udp_ports_default
        hosts = parse_targets(args.target)
        udp_results = []
        for host in hosts:
            r = udp_scan(host, ports, args.timeout,
                         getattr(args, 'threads', 50), args.verbose)
            udp_results.extend(r)
        for res in udp_results:
            colour = "\033[38;5;196m" if res.status == "open" else "\033[38;5;240m"
            print(f"  {colour}{res.status.upper():<13}\033[0m  "
                  f"{res.target}:{res.port:<6} {res.detail}")
        all_results.extend(udp_results)

    # ── Raw async SYN scan (epoll, nmap speed)
    if getattr(args, 'raw', False) and args.target:
        from lightscan.scan.rawscan import async_raw_scan
        from lightscan.scan.evasion import parse_timing
        hosts  = parse_targets(args.target)
        ports  = parse_ports(args.ports)
        timing = parse_timing(getattr(args, 'timing', 'T4'))
        ttl    = getattr(args, 'ttl', 64)
        decoys = getattr(args, 'decoy', 0)
        frag   = getattr(args, 'fragment', False)
        rand   = not getattr(args, 'no_randomize', False)
        ipv6   = getattr(args, 'ipv6', False)
        print(f"\033[38;5;196m[RAW-SCAN]\033[0m {len(hosts)} host(s) × {len(ports)} ports | "
              f"T{timing} | ttl={ttl} | decoys={decoys} | frag={frag}")
        for host in hosts:
            r = await async_raw_scan(host, ports, timing=timing, ttl=ttl,
                                     decoys=decoys, fragment=frag, randomize=rand,
                                     grab_banner=True, verbose=args.verbose, ipv6=ipv6)
            all_results.extend(r)
            for res in r:
                if res.status == "open":
                    open_ports.setdefault(res.target, []).append(res.port)
                    print(f"  \033[38;5;196mOPEN\033[0m  {res.target}:{res.port:<6} {res.detail}")

    # ── IPv6 scan
    if getattr(args, 'ipv6', False) and args.target and not getattr(args, 'raw', False):
        from lightscan.scan.ipv6scan import scan_ipv6, dual_stack_scan
        hosts = parse_targets(args.target)
        ports = parse_ports(args.ports)
        for host in hosts:
            if getattr(args, 'dual_stack', False):
                r = await dual_stack_scan(host, ports, args.timeout,
                                          args.concurrency, verbose=args.verbose)
            else:
                r = await scan_ipv6(host, ports, args.timeout,
                                    args.concurrency, verbose=args.verbose)
            all_results.extend(r)
            for res in r:
                if res.status == "open":
                    open_ports.setdefault(res.target, []).append(res.port)
                    print(f"  \033[38;5;196mOPEN\033[0m  {res.target}:{res.port:<6} {res.detail}")

    # ── OS fingerprint v2
    if getattr(args, 'os_v2', False) and args.target:
        from lightscan.scan.osdb import probe_os
        hosts = parse_targets(args.target)
        print(f"\033[38;5;196m[OS-V2]\033[0m Fingerprinting {len(hosts)} host(s)")
        for host in hosts:
            port = list(open_ports.get(host, [0]))[0] if open_ports.get(host) else 0
            r = await probe_os(host, port, args.timeout)
            all_results.extend(r)
            for res in r:
                print(f"  \033[38;5;196m[OS]\033[0m {res.target} → {res.detail}")

    # ── Port Scan
    if args.scan and args.target:
        hosts=parse_targets(args.target); ports=parse_ports(args.ports)
        print(f"\033[38;5;196m[SCAN]\033[0m {len(hosts)} host(s) × {len(ports)} port(s) | concurrency={args.concurrency}")
        engine=PhantomEngine(concurrency=args.concurrency,timeout=args.timeout,verbose=args.verbose)
        tasks=build_scan_tasks(hosts,ports,args.timeout,args.udp)
        scan_r=await engine.run(tasks)
        all_results.extend(scan_r)
        for r in scan_r:
            if r and r.status=="open":
                open_ports.setdefault(r.target,[]).append(r.port)
                print(f"  \033[38;5;196mOPEN\033[0m  {r.target}:{r.port:<6} {r.detail}")

    # ── List templates
    if getattr(args, 'list_templates', False):
        from lightscan.cve.template_engine import TemplateLibrary
        from pathlib import Path
        dirs = [str(Path(__file__).parent / "templates")]
        if getattr(args, 'template_dir', None): dirs.append(args.template_dir)
        lib = TemplateLibrary(dirs)
        print(f"\033[38;5;196m[TEMPLATES]\033[0m {lib.summary()}")
        for t in sorted(lib, key=lambda x: (x.severity.value, x.id)):
            cve = f" {t.cve}" if t.cve else ""
            tags = ",".join(t.tags[:4])
            print(f"  {t.severity.value:<8} {t.id:<35}{cve:<22} [{tags}]  port={t.port}")
        return all_results

    # ── CVE + Templates
    run_cve       = args.cve
    run_templates = getattr(args, 'templates', False)
    if (run_cve or run_templates) and args.target:
        from lightscan.cve.bridge import run_all_checks
        hosts = parse_targets(args.target) if not open_ports else list(open_ports.keys())
        extra_dirs = [args.template_dir] if getattr(args, 'template_dir', None) else None
        t_tags     = getattr(args, 'template_tags', None)
        t_ids      = getattr(args, 'template_ids', None)
        cb         = args.log4shell_callback or ""
        use_legacy = run_cve  # legacy checks only with --cve, not --templates alone
        print(f"\033[38;5;196m[{'CVE+TPL' if run_cve else 'TEMPLATES'}]\033[0m {len(hosts)} host(s)")
        for host in hosts:
            r = await run_all_checks(
                host, open_ports.get(host, []),
                template_dirs=extra_dirs,
                template_tags=t_tags,
                template_ids=t_ids,
                use_legacy=use_legacy,
                log4shell_callback=cb,
                timeout=args.timeout,
            )
            all_results.extend(r)
            for res in r:
                if res.status not in ("not_vuln","not_detected","error","no_response",
                                      "timeout","not_tls","not_enabled"):
                    print(f"  \033[38;5;196m[{res.severity.value}]\033[0m "
                          f"{res.module} @ {res.target}:{res.port} — {res.detail[:80]}")

    # ── OAuth
    if args.oauth:
        cid=args.oauth_client or "00000000-0000-0000-0000-000000000000"
        red=args.oauth_redirect or "https://localhost/callback"
        scanner=OAuthScanner(args.oauth,cid,red,args.timeout)
        all_results.extend(await scanner.scan_all())

    # ── Brute
    if args.brute and args.target:
        proto=args.brute.lower(); hosts=parse_targets(args.target)
        users=parse_userlist(args.users)
        target_info={"domain":args.target if "." in args.target else ""}
        passwords=parse_passwdlist(args.wordlist,users,target_info,args.mutate)
        jitter=tuple(args.jitter) if args.jitter else (0.0,0.0)
        brute=BruteEngine(concurrency=args.brute_conc,timeout=args.timeout,
                          jitter=jitter,checkpoint=cp if args.resume else None,verbose=args.verbose)
        print(f"\033[38;5;196m[BRUTE]\033[0m {proto.upper()} | {len(hosts)} host(s) | {len(users)} users | {len(passwords)} passwords")

        for host in hosts:
            port=args.brute_port
            if proto=="http":
                if not args.http_url: print("  [!] --http-url required for --brute http"); continue
                handler=get_handler(proto,host,port,url=args.http_url,
                    user_field=args.http_user_field,pass_field=args.http_pass_field,
                    success_text=args.http_success,failure_text=args.http_failure,
                    basic_auth=args.http_basic)
            else:
                handler=get_handler(proto,host,port)

            from lightscan.brute.handlers import PROTOCOLS as PH
            _,dport=PH[proto]; actual_port=port or dport

            if args.spray:
                spray=CredentialSpray(args.spray_window)
                pairs=[(u,p) async for u,p in spray.pairs(users,passwords)]
                u_s=list(dict.fromkeys(u for u,_ in pairs))
                p_s=list(dict.fromkeys(p for _,p in pairs))
                r=await brute.run(handler,u_s,p_s,host,actual_port,proto,args.stop_first)
            else:
                r=await brute.run(handler,users,passwords,host,actual_port,proto,args.stop_first)
            all_results.extend(r)

    # ── Summary
    elapsed=time.time()-t_start; meta["duration"]=elapsed
    crit=sum(1 for r in all_results if hasattr(r,"severity") and r.severity.value=="CRITICAL")
    high=sum(1 for r in all_results if hasattr(r,"severity") and r.severity.value=="HIGH")
    print()
    print(f"\033[38;5;196m{'─'*65}\033[0m")
    print(f"\033[38;5;196m[DONE]\033[0m {len(all_results)} findings  |  "
          f"\033[38;5;196m{crit} CRITICAL\033[0m  |  {high} HIGH  |  {elapsed:.1f}s")
    print(f"\033[38;5;196m{'─'*65}\033[0m")

    if not args.no_report and all_results:
        Reporter(args.output).save(all_results, meta, args.basename)
    cp.flush()
    return all_results


def main():
    p=build_parser()
    args=p.parse_args()
    if len(sys.argv)==1: p.print_help(); sys.exit(0)
    try: asyncio.run(async_main(args))
    except KeyboardInterrupt: print("\n\033[38;5;240m[!] Interrupted — checkpoint saved\033[0m")


if __name__=="__main__": main()
