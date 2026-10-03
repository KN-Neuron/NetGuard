"""Render a Report as plain text, JSON or a standalone HTML page."""

from __future__ import annotations

import html
import json

from .models import Status
from .util import now_iso

_SYMBOL = {
    Status.PASS: "[ OK ]",
    Status.INFO: "[INFO]",
    Status.WARN: "[WARN]",
    Status.FAIL: "[FAIL]",
    Status.SKIP: "[SKIP]",
}

_LEVEL_CLASS = {
    "SAFE": "safe",
    "CAUTION": "caution",
    "UNSAFE": "unsafe",
    "UNKNOWN": "unknown",
}


def render_text(report) -> str:
    state = report.state
    verdict = report.verdict
    lines = []
    lines.append("=" * 70)
    lines.append(f"NetGuard posture report    {now_iso()}")
    lines.append("=" * 70)
    lines.append(f"Network : {state.label}")
    link = f"{state.interface or '?'} ({state.device_type or 'unknown'})"
    if state.is_wifi:
        link += f"  ·  security: {state.security or 'OPEN'}"
    lines.append(f"Link    : {link}")
    if state.gateway:
        gw = state.gateway + (f"  (mac {state.gateway_mac})" if state.gateway_mac else "")
        lines.append(f"Gateway : {gw}")
    if state.dns_servers:
        lines.append(f"DNS     : {', '.join(state.dns_servers)}")
    lines.append(f"Verdict : {verdict.level.value}  ({verdict.score}/100) — {verdict.headline}")
    if report.simulated:
        lines.append("NOTE    : SIMULATED scenario for demonstration — no real traffic")
    lines.append("-" * 70)
    for result in report.results:
        lines.append(f"{_SYMBOL[result.status]} {result.title}: {result.summary}")
        if result.detail and result.status in (Status.FAIL, Status.WARN):
            lines.append(f"       {result.detail}")
    lines.append("-" * 70)

    problems = [r for r in report.results if r.status in (Status.FAIL, Status.WARN)]
    if problems:
        lines.append("Recommended actions:")
        for result in problems:
            if result.remediation:
                lines.append(f"  • {result.remediation}")
    else:
        lines.append("No issues found — this network passed every posture check.")
    lines.append("")
    return "\n".join(lines)


def render_json(report) -> str:
    payload = report.to_dict() if hasattr(report, "to_dict") else report
    return json.dumps(payload, indent=2)


def render_html(report) -> str:
    payload = report.to_dict() if hasattr(report, "to_dict") else report
    verdict = payload["verdict"]
    network = payload["network"]
    results = payload["results"]

    level = verdict["level"]
    level_class = _LEVEL_CLASS.get(level, "unknown")

    rows = []
    for result in results:
        status = result["status"]
        remediation = ""
        if result.get("remediation") and status in ("fail", "warn"):
            remediation = f'<div class="fix">↳ {html.escape(result["remediation"])}</div>'
        detail = ""
        if result.get("detail") and status in ("fail", "warn"):
            detail = f'<div class="detail">{html.escape(result["detail"])}</div>'
        rows.append(
            f'<div class="card {status}">'
            f'<div class="card-head"><span class="pill {status}">{status.upper()}</span>'
            f'<span class="card-title">{html.escape(result["title"])}</span></div>'
            f'<div class="summary">{html.escape(result["summary"])}</div>'
            f"{detail}{remediation}"
            f'<div class="meta">severity: {result["severity"]}</div>'
            f"</div>"
        )

    net_bits = [network.get("interface", ""), network.get("device_type", "")]
    subtitle = " · ".join(b for b in net_bits if b)
    if network.get("is_wifi"):
        subtitle += f" · {network.get('ssid') or '?'} ({'OPEN' if network.get('is_open') else network.get('security') or '?'})"

    simulated = (
        '<div class="sim">SIMULATED SCENARIO — demonstration data, no live traffic</div>'
        if payload.get("simulated")
        else ""
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>NetGuard report — {html.escape(network.get('label',''))}</title>
<style>
  :root {{ --bg:#0b1020; --panel:#151b30; --text:#e8ecf5; --muted:#9aa4bf;
           --safe:#2ecc71; --caution:#f4b400; --unsafe:#ff4d5e; --info:#5aa9ff; --skip:#6b7392; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--text);
          font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }}
  .wrap {{ max-width:920px; margin:0 auto; padding:32px 20px 64px; }}
  header {{ display:flex; justify-content:space-between; align-items:flex-start; gap:24px; flex-wrap:wrap; }}
  h1 {{ margin:0 0 4px; font-size:26px; }}
  .sub {{ color:var(--muted); font-size:14px; }}
  .score {{ text-align:center; min-width:170px; }}
  .score .num {{ font-size:44px; font-weight:700; }}
  .score .lvl {{ font-weight:700; letter-spacing:1px; }}
  .safe .num,.lvl.safe {{ color:var(--safe); }} .caution .num,.lvl.caution {{ color:var(--caution); }}
  .unsafe .num,.lvl.unsafe {{ color:var(--unsafe); }} .unknown .num,.lvl.unknown {{ color:var(--skip); }}
  .headline {{ margin:18px 0 6px; font-size:18px; }}
  .sim {{ background:#3a2a00; color:#ffce54; border:1px solid #5c4400; padding:8px 12px;
          border-radius:8px; font-size:13px; margin:16px 0; }}
  .cards {{ display:grid; gap:12px; margin-top:20px; }}
  .card {{ background:var(--panel); border-radius:12px; padding:14px 16px;
           border-left:4px solid var(--skip); }}
  .card.pass {{ border-left-color:var(--safe); }}
  .card.info {{ border-left-color:var(--info); }}
  .card.warn {{ border-left-color:var(--caution); }}
  .card.fail {{ border-left-color:var(--unsafe); }}
  .card-head {{ display:flex; align-items:center; gap:10px; }}
  .card-title {{ font-weight:600; }}
  .summary {{ margin-top:6px; }}
  .detail {{ color:var(--muted); font-size:13px; margin-top:4px; }}
  .fix {{ color:var(--caution); font-size:13px; margin-top:6px; }}
  .meta {{ color:#5b6482; font-size:11px; margin-top:8px; text-transform:uppercase; letter-spacing:.5px; }}
  .pill {{ font-size:11px; font-weight:700; padding:2px 8px; border-radius:20px; color:#0b1020; }}
  .pill.pass {{ background:var(--safe); }} .pill.info {{ background:var(--info); }}
  .pill.warn {{ background:var(--caution); }} .pill.fail {{ background:var(--unsafe); color:#fff; }}
  .pill.skip {{ background:var(--skip); color:#fff; }}
  footer {{ color:#5b6482; font-size:12px; margin-top:28px; }}
</style></head>
<body><div class="wrap">
  <header>
    <div>
      <h1>{html.escape(network.get('label','Network'))}</h1>
      <div class="sub">{html.escape(subtitle)}<br>Gateway {html.escape(str(network.get('gateway','—')))} ·
      DNS {html.escape(', '.join(network.get('dns_servers') or ['—']))}</div>
    </div>
    <div class="score {level_class}">
      <div class="num">{verdict['score']}</div>
      <div class="lvl {level_class}">{level}</div>
      <div class="sub">posture score /100</div>
    </div>
  </header>
  {simulated}
  <div class="headline">{html.escape(verdict['headline'])}</div>
  <div class="cards">{''.join(rows)}</div>
  <footer>Generated by NetGuard {html.escape(payload.get('timestamp',''))} ·
  {len(results)} checks · tool: netguard</footer>
</div></body></html>"""
