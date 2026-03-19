"""
LightScan v2.0 PHANTOM — OS Fingerprinting Engine
Developer: Light (Neok1ra)

Integration of uploaded MultiProbeOSDetector (Doc 6) + 53-entry signature DB (Doc 5).

Method:
  Layer 1 — SYN-ACK passive analysis (TTL, window, TCP options, DF bit)
             Runs automatically when SYN scanner receives a response.
             Zero extra packets. Pure read of what we already got.

  Layer 2 — T2-T7 active probes (Nmap methodology, your uploaded code)
             6 extra packets to one open + one closed port.
             Needs root + scapy. Much higher confidence.
             --os-probe flag triggers this layer.

Scoring (weighted):
  TTL match          → 25 pts  (strongest single signal)
  Window match       → 20 pts
  DF bit match       → 15 pts
  Options order      → 15 pts  (exact) / 10 pts (subset)
  SACK match         → 10 pts
  WScale match       → 10 pts
  Timestamps match   →  5 pts
  T2-T7 flag match   →  5 pts each (up to 30 pts extra)

Confidence levels:
  >= 80  HIGH     (single match, report as-is)
  50-79  MEDIUM   (report top candidate + alternatives)
  < 50   LOW      (family-level guess only)
"""
from __future__ import annotations
import json, os, random, socket, struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from lightscan.core.engine import ScanResult, Severity

_DB_PATH = Path(__file__).parent.parent / "data" / "os_signatures.json"

# ─── Data model ──────────────────────────────────────────────────────────────

@dataclass
class TCPFeatures:
    """Features extracted from a SYN-ACK or probe response."""
    ttl:           int
    window:        int
    df:            bool
    mss:           Optional[int]      = None
    sack:          bool               = False
    timestamps:    bool               = False
    wscale:        Optional[int]      = None
    options_order: list               = field(default_factory=list)
    flags_str:     str                = ""      # e.g. "SA", "R", "RA"
    ip_id:         int                = 0
    raw_options:   list               = field(default_factory=list)

@dataclass
class OSMatch:
    name:       str
    family:     str
    score:      int
    confidence: str   # HIGH / MEDIUM / LOW
    max_score:  int   = 100

    def __str__(self):
        return f"{self.name} [{self.family}] score={self.score}/{self.max_score} ({self.confidence})"


# ─── Signature DB ────────────────────────────────────────────────────────────

class SignatureDB:
    def __init__(self, path: Path = _DB_PATH):
        with open(path) as f:
            self._sigs = json.load(f)

    def __len__(self): return len(self._sigs)

    def match(self, feat: TCPFeatures, probe_flags: dict | None = None) -> list[OSMatch]:
        """Score all signatures against features. Returns sorted list."""
        results = []
        for sig in self._sigs:
            score = 0; max_score = 85

            # TTL — strongest signal (normalise by rounding up to nearest 64/128/255)
            ttl_norm = _normalise_ttl(feat.ttl)
            if ttl_norm == sig["ttl"]:           score += 25
            elif abs(ttl_norm - sig["ttl"]) <= 5: score += 10  # forwarded hops

            # Window size
            if feat.window == sig["window"]:     score += 20
            elif abs(feat.window - sig["window"]) < 1000: score += 8

            # DF bit
            if feat.df == sig["df"]:             score += 15

            # Options order
            sig_opts = sig.get("options_order", [])
            if sig_opts:
                if feat.options_order == sig_opts:         score += 15
                elif set(feat.options_order) == set(sig_opts): score += 10
                elif any(o in feat.options_order for o in sig_opts): score += 3

            # SACK
            if feat.sack == sig["sack"]:         score += 10

            # WScale
            sig_ws = sig.get("wscale")
            if feat.wscale == sig_ws:            score += 10
            elif sig_ws is None and feat.wscale is None: score += 10

            # Timestamps
            if feat.timestamps == sig["timestamps"]: score += 5

            # T2-T7 probe flags (30 pts extra)
            if probe_flags:
                max_score = 85 + 30
                for t_key in ("T2","T3","T4","T5","T6","T7"):
                    obs = probe_flags.get(t_key)
                    exp = sig.get(f"{t_key.lower()}_flags")
                    if obs and exp and obs == exp: score += 5

            pct = round(score / max_score * 100)
            conf = "HIGH" if pct >= 80 else "MEDIUM" if pct >= 50 else "LOW"
            results.append(OSMatch(sig["name"], sig["family"], pct, conf, 100))

        results.sort(key=lambda x: x.score, reverse=True)
        return results


# ─── Feature extractor (from Scapy packet) ───────────────────────────────────

def _normalise_ttl(ttl: int) -> int:
    """Guess the original TTL by rounding up to nearest standard value."""
    for std in (32, 64, 128, 255):
        if ttl <= std: return std
    return 255

def _option_name(opt) -> str:
    """Convert Scapy TCP option tuple/str to canonical name."""
    if isinstance(opt, tuple): opt = opt[0]
    mapping = {
        "MSS": "MSS", "NOP": "NOP", "SAckOK": "SACK", "Timestamp": "Timestamp",
        "WScale": "WScale", "SAck": "SACK", "EOL": "EOL",
        2: "MSS", 0: "EOL", 1: "NOP", 4: "SACK", 8: "Timestamp", 3: "WScale",
    }
    return mapping.get(opt, str(opt))

def extract_features_from_scapy(pkt) -> TCPFeatures | None:
    """Parse a Scapy IP/TCP SYN-ACK into TCPFeatures."""
    try:
        from scapy.all import IP, TCP
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return None
        ip_l  = pkt[IP]
        tcp_l = pkt[TCP]
        opts_raw = tcp_l.options or []
        mss, wscale, has_sack, has_ts = None, None, False, False
        order = []
        for opt in opts_raw:
            name = _option_name(opt)
            order.append(name)
            if name == "MSS" and isinstance(opt, tuple): mss = opt[1]
            elif name == "WScale" and isinstance(opt, tuple): wscale = opt[1]
            elif name == "SACK": has_sack = True
            elif name == "Timestamp": has_ts = True

        flags = _flags_to_str(int(tcp_l.flags))
        return TCPFeatures(
            ttl=ip_l.ttl, window=tcp_l.window,
            df=bool(ip_l.flags & 0x2), mss=mss, sack=has_sack,
            timestamps=has_ts, wscale=wscale, options_order=order,
            flags_str=flags, ip_id=ip_l.id, raw_options=opts_raw
        )
    except Exception:
        return None

def extract_features_from_banner(banner_data: dict) -> TCPFeatures | None:
    """
    Lightweight path — build TCPFeatures from what the connect scanner
    can observe: just TTL (via IP headers) and banner text.
    Used when scapy not available / not root.
    """
    ttl = banner_data.get("ttl", 0)
    if not ttl: return None
    return TCPFeatures(ttl=ttl, window=0, df=False)


def _flags_to_str(flags: int) -> str:
    """Your uploaded _flags_to_str() — kept identical."""
    s = ""
    if flags & 0x01: s += "F"
    if flags & 0x02: s += "S"
    if flags & 0x04: s += "R"
    if flags & 0x08: s += "P"
    if flags & 0x10: s += "A"
    if flags & 0x20: s += "U"
    if flags & 0x40: s += "E"
    if flags & 0x80: s += "C"
    return s if s else "0"


# ─── Active T2-T7 probe engine (your MultiProbeOSDetector — rewritten async) ─

class MultiProbeOSDetector:
    """
    Your uploaded MultiProbeOSDetector — integrated into LightScan.
    Changes:
      • Async-compatible (run_in_executor wrapper)
      • Feeds into SignatureDB.match() for scoring
      • Returns LightScan ScanResult objects
      • Closed port auto-discovered if not supplied
    """
    FLAG_T2 = 0x00           # NULL
    FLAG_T3 = 0x2B           # SYN|URG|PSH|FIN
    FLAG_T4 = 0x10           # ACK
    FLAG_T5 = 0x02           # SYN   (→ closed port)
    FLAG_T6 = 0x10           # ACK   (→ closed port)
    FLAG_T7 = 0x29           # FIN|PSH|URG (→ closed port)

    def __init__(self, db: SignatureDB | None = None, timeout=2.0):
        self.db      = db or SignatureDB()
        self.timeout = timeout

    def _probe(self, target: str, port: int, flags: int) -> dict | None:
        """Your _send_probe() — returns parsed feature dict."""
        try:
            from scapy.all import IP, TCP, sr1, ICMP
            sport = random.randint(1024, 65535)
            ip    = IP(dst=target)
            tcp   = TCP(sport=sport, dport=port,
                        flags=flags, seq=random.randint(0, 2**32-1))
            r = sr1(ip/tcp, timeout=self.timeout, verbose=0)
            if r is None: return None
            from scapy.all import TCP as ScapyTCP, ICMP as ScapyICMP
            if r.haslayer(ScapyTCP):
                t = r[ScapyTCP]; i = r[IP]
                return {
                    "flags":   _flags_to_str(int(t.flags)),
                    "window":  t.window, "ttl": i.ttl,
                    "options": [_option_name(o) for o in (t.options or [])],
                    "df":      bool(i.flags & 0x2), "ip_id": i.id,
                }
            if r.haslayer(ScapyICMP):
                ic = r[ScapyICMP]
                return {"icmp": f"{ic.type}/{ic.code}"}
        except Exception: pass
        return None

    def run_probes(self, target: str, open_port: int,
                   closed_port: int | None = None) -> dict:
        """
        Your probe_sequence() — T2-T7 against open+closed ports.
        Returns raw probe dict: {"T2": {...}, "T3": {...}, ...}
        """
        if closed_port is None:
            closed_port = random.randint(49152, 65534)

        probes = {
            "T2": (open_port,   self.FLAG_T2),
            "T3": (open_port,   self.FLAG_T3),
            "T4": (open_port,   self.FLAG_T4),
            "T5": (closed_port, self.FLAG_T5),
            "T6": (closed_port, self.FLAG_T6),
            "T7": (closed_port, self.FLAG_T7),
        }
        results = {}
        for key, (port, flags) in probes.items():
            r = self._probe(target, port, flags)
            results[key] = r
            if r and "flags" in r:
                print(f"  \033[38;5;240m{key} → {r['flags']}\033[0m", end="  ", flush=True)
        print()
        return results

    def probe_flags_for_scoring(self, probe_results: dict) -> dict:
        """Your extract_features_from_probes() — convert to flag strings for DB scoring."""
        out = {}
        for key, resp in probe_results.items():
            if resp and "flags" in resp:
                out[key] = resp["flags"]
            elif resp is None:
                out[key] = None
        return out

    def detect(self, target: str, open_port: int,
               synack_feat: TCPFeatures | None = None,
               closed_port: int | None = None) -> list[OSMatch]:
        """
        Your detect() — full pipeline:
          run_probes → extract flags → match signature DB
        Combines T2-T7 probe flags with SYN-ACK features if available.
        """
        print(f"\033[38;5;196m[OS-PROBE]\033[0m T2-T7 probes → {target}:{open_port}", flush=True)
        raw = self.run_probes(target, open_port, closed_port)
        probe_flags = self.probe_flags_for_scoring(raw)

        feat = synack_feat
        if feat is None:
            # Reconstruct minimal features from T5 SYN-ACK if possible
            t5 = raw.get("T5")
            if t5 and "ttl" in t5:
                feat = TCPFeatures(ttl=t5["ttl"], window=t5.get("window",0),
                                   df=t5.get("df",False))
        if feat is None:
            feat = TCPFeatures(ttl=0, window=0, df=False)

        return self.db.match(feat, probe_flags)


# ─── Passive fingerprinter (no extra packets) ────────────────────────────────

class PassiveFingerprintEngine:
    """
    Runs automatically during SYN scan — zero extra packets.
    Reads SYN-ACK packet features the scanner already received.
    """
    def __init__(self, db: SignatureDB | None = None):
        self.db = db or SignatureDB()

    def fingerprint_synack(self, pkt, host: str, port: int) -> ScanResult | None:
        """Called with each SYN-ACK scapy packet from the SYN scanner."""
        feat = extract_features_from_scapy(pkt)
        if not feat: return None
        matches = self.db.match(feat)
        if not matches or matches[0].score < 20: return None
        best = matches[0]
        alts = [m.name for m in matches[1:3] if m.score >= 40]
        detail = (f"{best.name} [{best.family}] confidence={best.confidence}"
                  + (f" | alt: {', '.join(alts)}" if alts else ""))
        sev = Severity.INFO
        return ScanResult("os-detect", host, port, "fingerprinted",
                          sev, detail,
                          {"os": best.name, "family": best.family,
                           "confidence": best.confidence, "score": best.score,
                           "ttl_observed": feat.ttl, "window": feat.window,
                           "df": feat.df, "options": feat.options_order,
                           "alternatives": alts})

    def fingerprint_synack_dict(self, host: str, ttl: int, window: int,
                                df: bool, options: list,
                                sack=False, ts=False, wscale=None) -> ScanResult | None:
        """
        Dict-based path — for when Scapy packet not available
        (e.g. connect scanner with partial IP header info).
        """
        feat = TCPFeatures(ttl=ttl, window=window, df=df,
                           sack=sack, timestamps=ts, wscale=wscale,
                           options_order=options)
        matches = self.db.match(feat)
        if not matches or matches[0].score < 20: return None
        best = matches[0]
        alts = [m.name for m in matches[1:3] if m.score >= 40]
        detail = (f"{best.name} [{best.family}] confidence={best.confidence}"
                  + (f" | alt: {', '.join(alts)}" if alts else ""))
        return ScanResult("os-detect", host, 0, "fingerprinted",
                          Severity.INFO, detail,
                          {"os": best.name, "family": best.family,
                           "confidence": best.confidence, "score": best.score})


# ─── Public API ───────────────────────────────────────────────────────────────

_shared_db  = None
_shared_pfp = None
_shared_mpo = None

def _db() -> SignatureDB:
    global _shared_db
    if _shared_db is None: _shared_db = SignatureDB()
    return _shared_db

def passive_engine() -> PassiveFingerprintEngine:
    global _shared_pfp
    if _shared_pfp is None: _shared_pfp = PassiveFingerprintEngine(_db())
    return _shared_pfp

def active_engine() -> MultiProbeOSDetector:
    global _shared_mpo
    if _shared_mpo is None: _shared_mpo = MultiProbeOSDetector(_db())
    return _shared_mpo

async def os_probe_async(target: str, open_port: int,
                         closed_port: int | None = None,
                         synack_feat: TCPFeatures | None = None) -> list[ScanResult]:
    """Async wrapper — runs active T2-T7 probes in thread pool."""
    import asyncio
    loop = asyncio.get_event_loop()
    eng  = active_engine()
    matches = await loop.run_in_executor(
        None, eng.detect, target, open_port, synack_feat, closed_port)
    if not matches: return []
    results = []
    for m in matches[:3]:  # top 3 candidates
        detail = f"{m.name} [{m.family}] confidence={m.confidence} score={m.score}/100"
        results.append(ScanResult("os-detect-active", target, open_port,
            "fingerprinted", Severity.INFO, detail,
            {"os": m.name, "family": m.family, "confidence": m.confidence,
             "score": m.score}))
    return results
