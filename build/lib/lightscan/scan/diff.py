"""LightScan v2.0 PHANTOM — Scan Diff | Developer: Light"""
import json
from lightscan.core.engine import ScanResult, Severity

def load_report(path):
    with open(path) as f: data=json.load(f)
    return data.get("results",data) if isinstance(data,dict) else data

def diff_scans(old_path, new_path):
    def key(r): return f"{r.get('target')}:{r.get('port')}:{r.get('module')}:{r.get('status')}"
    old={key(r):r for r in load_report(old_path)}
    new={key(r):r for r in load_report(new_path)}
    appeared={k:v for k,v in new.items() if k not in old}
    resolved={k:v for k,v in old.items() if k not in new}
    results=[]
    for k,r in appeared.items():
        try: sev=Severity[r.get("severity","INFO")]
        except: sev=Severity.INFO
        results.append(ScanResult(f"diff:NEW:{r.get('module','')}",r.get("target",""),
            r.get("port",0),f"new:{r.get('status','')}",sev,f"[NEW] {r.get('detail','')}"))
    for k,r in resolved.items():
        results.append(ScanResult(f"diff:RESOLVED:{r.get('module','')}",r.get("target",""),
            r.get("port",0),f"resolved:{r.get('status','')}",Severity.INFO,f"[RESOLVED] {r.get('detail','')}"))
    summary=f"Diff: {len(appeared)} new, {len(resolved)} resolved | old={len(old)} new={len(new)}"
    return results, summary
