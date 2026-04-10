"""
LightScan v2.0 PHANTOM — CVE Checker + Template Engine Bridge
Developer: Light (Neok1ra)

Runs both:
  1. Legacy hardcoded checks (EternalBlue, Log4Shell, etc.)  — kept for raw protocol accuracy
  2. Template engine checks for the same + 30 new templates  — extensible
Results are deduplicated by template_id / module name.
"""
from __future__ import annotations
import asyncio
from pathlib import Path

from lightscan.cve.checker import CVEChecker
from lightscan.cve.template_engine import TemplateLibrary, run_templates
from lightscan.core.engine import ScanResult


async def run_all_checks(host: str, open_ports: list[int],
                         template_dirs: list[str] | None = None,
                         template_tags: list[str] | None = None,
                         template_ids:  list[str] | None = None,
                         use_legacy: bool = True,
                         log4shell_callback: str = "",
                         timeout: float = 8.0,
                         concurrency: int = 32) -> list[ScanResult]:
    """
    Unified check runner — legacy CVEChecker + template engine.

    Args:
        host:               target IP / hostname
        open_ports:         list of confirmed open ports
        template_dirs:      extra template directories (besides built-in)
        template_tags:      filter templates by tag  (e.g. ['redis','unauth'])
        template_ids:       run specific template IDs only
        use_legacy:         also run hardcoded CVE checks
        log4shell_callback: OAST callback URL for Log4Shell OOB detection
        timeout / concurrency: passed to runner

    Returns:
        Deduplicated list of ScanResult
    """
    results: list[ScanResult] = []
    seen: set[str] = set()

    def _dedup(r: ScanResult) -> bool:
        key = f"{r.module}:{r.target}:{r.port}"
        if key in seen: return False
        seen.add(key); return True

    # ── Template engine ───────────────────────────────────────────────────────
    dirs = [str(Path(__file__).parent.parent / "templates")]
    if template_dirs: dirs.extend(template_dirs)
    lib = TemplateLibrary(dirs)

    tpls = lib.filter(tags=template_tags, ids=template_ids)
    if not tpls and not template_tags and not template_ids:
        tpls = lib.for_ports(open_ports)

    tpl_results = await run_templates(tpls, host, open_ports, timeout, concurrency)
    for r in tpl_results:
        if _dedup(r): results.append(r)

    # ── Legacy hardcoded checks ───────────────────────────────────────────────
    if use_legacy:
        checker = CVEChecker(host, timeout=timeout)
        port_set = set(open_ports)

        tasks = []
        if 445 in port_set:
            tasks.append(checker.check_eternalblue())
        if 80 in port_set or 8080 in port_set or 443 in port_set:
            tasks.append(checker.check_log4shell(log4shell_callback))
            tasks.append(checker.check_spring4shell())
            tasks.append(checker.check_shellshock())
        if 443 in port_set or 8443 in port_set:
            tasks.append(checker.check_heartbleed())
        if 6379 in port_set:
            tasks.append(checker.check_redis_unauth())
        if 27017 in port_set:
            tasks.append(checker.check_mongodb_unauth())
        if 9200 in port_set:
            tasks.append(checker.check_elasticsearch_unauth())

        legacy_results = await asyncio.gather(*tasks)
        for batch in legacy_results:
            for r in (batch if isinstance(batch, list) else [batch]):
                if r and _dedup(r): results.append(r)

    return results


async def run_templates_only(host: str, open_ports: list[int],
                             extra_dirs: list[str] | None = None,
                             tags: list[str] | None = None,
                             ids:  list[str] | None = None,
                             timeout=8.0) -> list[ScanResult]:
    """Thin wrapper — template engine only, no legacy checks."""
    return await run_all_checks(
        host, open_ports,
        template_dirs=extra_dirs,
        template_tags=tags,
        template_ids=ids,
        use_legacy=False,
        timeout=timeout,
    )
