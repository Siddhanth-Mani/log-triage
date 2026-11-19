"""Text, JSON and HTML output. The HTML report is one self-contained file with no scripts."""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from html import escape
from typing import Optional

from . import __version__
from .detectors import RANK, SEVERITIES, Finding
from .parsers import ParseResult


def summary(result: ParseResult, findings: list[Finding]) -> dict:
    sev = Counter(f.severity for f in findings)
    failed = [e for e in result.auth if e.kind in ("failed", "invalid_user")]
    top_ssh = Counter(e.ip for e in failed if e.ip).most_common(10)
    web_err = Counter(e.ip for e in result.web if e.status >= 400).most_common(10)
    times = [e.time for e in result.auth] + [e.time for e in result.web]
    return {
        "lines": result.lines, "skipped": result.skipped,
        "auth_events": len(result.auth), "web_requests": len(result.web),
        "failed_logins": len(failed),
        "accepted_logins": sum(1 for e in result.auth if e.kind == "accepted"),
        "start": min(times).isoformat() if times else None,
        "end": max(times).isoformat() if times else None,
        "findings": {s: sev.get(s, 0) for s in reversed(SEVERITIES)},
        "top_failed_login_ips": top_ssh,
        "top_web_error_ips": web_err,
    }


# ---------------------------------------------------------------- text

def to_text(result: ParseResult, findings: list[Finding], color: bool = False) -> str:
    s = summary(result, findings)
    paint = {
        "critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m",
    } if color else {}
    reset = "\033[0m" if color else ""
    lines = [
        f"Read {s['lines']} lines: {s['auth_events']} auth events, {s['web_requests']} web requests"
        + (f", {s['skipped']} {'line' if s['skipped'] == 1 else 'lines'} not recognised" if s["skipped"] else "") + ".",
    ]
    if s["start"]:
        lines.append(f"Time span: {s['start'].replace('T', ' ')} to {s['end'].replace('T', ' ')}")
    counts = ", ".join(f"{n} {k}" for k, n in s["findings"].items() if n)
    lines.append(f"Findings: {counts or 'none'}")
    lines.append("")
    for f in findings:
        tag = f"{paint.get(f.severity, '')}{f.severity.upper():<8}{reset}"
        lines.append(f"{tag} {f.title}")
        lines.append(f"         {f.detail}")
        lines.append(f"         {f.first_seen:%Y-%m-%d %H:%M:%S} to {f.last_seen:%Y-%m-%d %H:%M:%S}   rule: {f.rule}")
        lines.append("")
    if not findings:
        lines.append("Nothing matched any rule. That does not prove nothing happened; it means none of the known patterns showed up.")
    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------- JSON

def to_json(result: ParseResult, findings: list[Finding]) -> str:
    return json.dumps({
        "generator": f"log-triage {__version__}",
        "summary": summary(result, findings),
        "findings": [f.to_dict() for f in findings],
    }, indent=2)


# ---------------------------------------------------------------- HTML

CSS = """
:root{--bg:#fff;--soft:#f6f7f8;--text:#1c1f23;--muted:#5f6670;--line:#dde1e5;
--critical:#a1161b;--high:#c4410c;--medium:#946200;--low:#1d63a8;--info:#5f6670;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--bg:#151719;--soft:#1c1f22;--text:#e4e6e9;--muted:#9aa2ab;--line:#30353a;
--critical:#ff8a8e;--high:#ff9a6b;--medium:#e3b34c;--low:#7fb2ea;--info:#9aa2ab}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif}
main{max-width:1000px;margin:0 auto;padding:28px 20px 48px}h1{font-size:24px;margin:0 0 4px}
h2{font-size:17px;margin:32px 0 10px}.muted{color:var(--muted)}code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:18px 0}
.stat{border:1px solid var(--line);border-radius:8px;padding:10px 14px}.stat b{display:block;font-size:22px}.stat span{color:var(--muted);font-size:13px}
.finding{border:1px solid var(--line);border-left:4px solid var(--sev);border-radius:0 8px 8px 0;padding:12px 16px;margin:10px 0}
.finding h3{margin:0 0 4px;font-size:16px}.sev{display:inline-block;font-size:11.5px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;color:var(--sev);margin-right:8px}
.finding p{margin:4px 0}.meta{font-size:13px;color:var(--muted)}
details{margin-top:8px}summary{cursor:pointer;color:var(--muted);font-size:13px}
pre{background:var(--soft);border:1px solid var(--line);border-radius:6px;padding:10px 12px;overflow-x:auto;white-space:pre;margin:6px 0 0}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line)}
th{font-size:12.5px;color:var(--muted)}td.n{text-align:right;font-variant-numeric:tabular-nums}
.two{display:grid;grid-template-columns:1fr 1fr;gap:24px}@media (max-width:700px){.two{grid-template-columns:1fr}}
.note{border:1px solid var(--line);background:var(--soft);border-radius:8px;padding:10px 14px}
footer{margin-top:40px;font-size:13px;color:var(--muted);border-top:1px solid var(--line);padding-top:12px}
"""


def to_html(result: ParseResult, findings: list[Finding], sources: Optional[list[str]] = None,
            generated: Optional[datetime] = None, note: str = "") -> str:
    s = summary(result, findings)
    generated = generated or datetime.now(timezone.utc)
    e = escape

    def ip_table(rows, label):
        if not rows:
            return f"<p class='muted'>None.</p>"
        body = "".join(f"<tr><td><code>{e(ip)}</code></td><td class='n'>{n}</td></tr>" for ip, n in rows)
        return f"<table><thead><tr><th>Address</th><th>{e(label)}</th></tr></thead><tbody>{body}</tbody></table>"

    stats = [
        (s["lines"], "lines read"), (s["failed_logins"], "failed SSH logins"),
        (s["accepted_logins"], "successful SSH logins"), (s["web_requests"], "web requests"),
        (sum(s["findings"].values()), "findings"),
    ]
    stat_html = "".join(f"<div class='stat'><b>{n:,}</b><span>{e(label)}</span></div>" for n, label in stats)

    items = []
    for f in findings:
        who = " · ".join(x for x in [f"IP {f.ip}" if f.ip else "", f"user {f.user}" if f.user else ""] if x)
        items.append(
            f"<section class='finding' style='--sev:var(--{f.severity})'>"
            f"<h3><span class='sev'>{e(f.severity)}</span>{e(f.title)}</h3>"
            f"<p>{e(f.detail)}</p>"
            f"<p class='meta'>{f.first_seen:%Y-%m-%d %H:%M:%S} to {f.last_seen:%Y-%m-%d %H:%M:%S}"
            f"{' · ' + e(who) if who else ''} · rule <code>{e(f.rule)}</code></p>"
            f"<details><summary>Evidence ({len(f.evidence)} lines)</summary><pre>{e(chr(10).join(f.evidence))}</pre></details>"
            "</section>")
    findings_html = "".join(items) or "<p>No rule matched. None of the known attack patterns showed up in these logs.</p>"

    span = f"{s['start'].replace('T', ' ')} to {s['end'].replace('T', ' ')}" if s["start"] else "no timestamps"
    src = ", ".join(e(x) for x in (sources or [])) or "standard input"
    counts = ", ".join(f"{n} {k}" for k, n in s["findings"].items() if n) or "none"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Log triage report</title><style>{CSS}</style></head>
<body><main>
<h1>Log triage report</h1>
<p class="muted">{src} · {e(span)}</p>
{f'<p class="note">{e(note)}</p>' if note else ''}
<div class="stats">{stat_html}</div>
<h2>Findings ({e(counts)})</h2>
{findings_html}
<div class="two">
<div><h2>Most failed SSH logins</h2>{ip_table(s['top_failed_login_ips'], 'Failures')}</div>
<div><h2>Most web errors (4xx/5xx)</h2>{ip_table(s['top_web_error_ips'], 'Errors')}</div>
</div>
<footer>Generated by log-triage {e(__version__)} on {generated:%Y-%m-%d %H:%M} UTC. Times are shown as written in the logs
(the server's local time). {s['skipped']} {'line was' if s['skipped'] == 1 else 'lines were'} not recognised and skipped.</footer>
</main></body></html>
"""


def at_least(findings: list[Finding], severity: str) -> list[Finding]:
    return [f for f in findings if RANK[f.severity] >= RANK[severity]]
