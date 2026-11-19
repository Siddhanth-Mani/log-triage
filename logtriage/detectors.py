"""Rules that turn parsed events into findings.

Every threshold lives in `Settings` so it can be tuned from the command line. Rules work on
one source IP (or one user) at a time and keep a few raw lines as evidence.
"""
from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable, Optional
from urllib.parse import unquote_plus

from .parsers import AuthEvent, WebEvent, iter_window

SEVERITIES = ["info", "low", "medium", "high", "critical"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}
EVIDENCE_LINES = 5


@dataclass
class Settings:
    ssh_failures: int = 10            # failed logins from one IP ...
    ssh_window: timedelta = timedelta(minutes=10)  # ... inside this window = brute force
    spray_users: int = 5              # distinct usernames tried by one IP
    compromise_failures: int = 3      # failures before a success from the same IP
    web_errors: int = 30              # 4xx responses from one IP ...
    web_window: timedelta = timedelta(minutes=5)   # ... inside this window = scanner
    sensitive_hits: int = 3           # requests for files that should never be public
    error_burst: int = 20             # 5xx responses in one minute
    sudo_failures: int = 3
    ignore_networks: list = field(default_factory=list)  # ip_network objects to skip (your own office, monitoring)


@dataclass
class Finding:
    severity: str
    rule: str
    title: str
    detail: str
    first_seen: datetime
    last_seen: datetime
    count: int
    ip: Optional[str] = None
    user: Optional[str] = None
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "severity": self.severity, "rule": self.rule, "title": self.title, "detail": self.detail,
            "ip": self.ip, "user": self.user, "count": self.count,
            "first_seen": self.first_seen.isoformat(), "last_seen": self.last_seen.isoformat(),
            "evidence": self.evidence,
        }


def _ignored(ip: Optional[str], settings: Settings) -> bool:
    if not ip or not settings.ignore_networks:
        return False
    addr = ipaddress.ip_address(ip)
    return any(addr.version == n.version and addr in n for n in settings.ignore_networks)


def _evidence(events) -> list[str]:
    evs = list(events)
    if len(evs) <= EVIDENCE_LINES:
        return [e.raw for e in evs]
    # first few and the last one, so the reader sees how it started and that it kept going
    return [e.raw for e in evs[:EVIDENCE_LINES - 1]] + [f"... {len(evs) - EVIDENCE_LINES} more ...", evs[-1].raw]


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


# ---------------------------------------------------------------- SSH rules

def ssh_findings(events: list[AuthEvent], s: Settings) -> list[Finding]:
    out: list[Finding] = []
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for e in sorted(events, key=lambda e: e.time):
        if e.ip and not _ignored(e.ip, s):
            by_ip[e.ip].append(e)

    for ip, evs in by_ip.items():
        fails = [e for e in evs if e.kind in ("failed", "invalid_user")]
        # an "Invalid user" line is usually followed by a "Failed password for invalid user" line
        # for the same attempt, so count failures from the "failed" lines when there are any
        counted = [e for e in fails if e.kind == "failed"] or fails

        # brute force: the busiest window
        if len(counted) >= s.ssh_failures:
            times = [e.time for e in counted]
            best = max(iter_window(times, s.ssh_window), key=lambda p: p[1] - p[0])
            n = best[1] - best[0] + 1
            if n >= s.ssh_failures:
                users = Counter(e.user for e in counted)
                top = ", ".join(f"{u} ({c})" for u, c in users.most_common(5))
                out.append(Finding(
                    "high", "ssh-bruteforce", f"SSH brute force from {ip}",
                    f"{_plural(len(counted), 'failed login')} in total, {n} within {int(s.ssh_window.total_seconds() // 60)} minutes. "
                    f"Usernames tried: {top}{' and others' if len(users) > 5 else ''}.",
                    counted[0].time, counted[-1].time, len(counted), ip=ip, evidence=_evidence(counted)))

        # password spraying / username enumeration
        users = {e.user for e in fails}
        if len(users) >= s.spray_users:
            sample = ", ".join(sorted(users)[:8])
            out.append(Finding(
                "medium", "ssh-user-enumeration", f"{len(users)} different usernames tried from {ip}",
                f"Guessing account names ({sample}{', ...' if len(users) > 8 else ''}). "
                "Consider key-only authentication and a tool such as fail2ban.",
                fails[0].time, fails[-1].time, len(fails), ip=ip, evidence=_evidence(fails)))

        # a success after failures from the same address is the one to look at first
        failures_so_far = 0
        reported = set()
        for e in evs:
            if e.kind == "failed":
                failures_so_far += 1
            elif e.kind == "accepted" and failures_so_far >= s.compromise_failures and e.user not in reported:
                reported.add(e.user)
                prior = [x for x in evs if x.kind == "failed" and x.time <= e.time]
                out.append(Finding(
                    "critical", "ssh-login-after-failures", f"Successful login as {e.user} from {ip} after {failures_so_far} failures",
                    f"{ip} logged in with {e.method} at {e.time:%Y-%m-%d %H:%M:%S} after failing {failures_so_far} times. "
                    "If this was not a person who mistyped their password, treat the account as compromised: "
                    "end its sessions, rotate its credentials and check ~/.ssh/authorized_keys and crontab.",
                    prior[0].time if prior else e.time, e.time, failures_so_far + 1, ip=ip, user=e.user,
                    evidence=_evidence(prior[-(EVIDENCE_LINES - 1):]) + [e.raw]))

    # root logins at all
    roots = [e for e in events if e.kind == "accepted" and e.user == "root" and not _ignored(e.ip, s)]
    if roots:
        roots.sort(key=lambda e: e.time)
        ips = sorted({e.ip for e in roots})
        out.append(Finding(
            "medium", "ssh-root-login", f"Direct root login over SSH ({_plural(len(roots), 'time')})",
            f"From {', '.join(ips[:5])}{' and others' if len(ips) > 5 else ''}. "
            "Set PermitRootLogin no and use sudo from a named account so actions can be traced to a person.",
            roots[0].time, roots[-1].time, len(roots), user="root", evidence=_evidence(roots)))
    return out


def sudo_findings(events: list[AuthEvent], s: Settings) -> list[Finding]:
    out = []
    by_user: dict[str, list[AuthEvent]] = defaultdict(list)
    for e in events:
        if e.kind == "sudo_fail":
            by_user[e.user].append(e)
    for user, evs in by_user.items():
        if len(evs) >= s.sudo_failures:
            evs.sort(key=lambda e: e.time)
            out.append(Finding(
                "medium", "sudo-failures", f"{_plural(len(evs), 'failed sudo attempt')} by {user}",
                f"Someone using the {user} account repeatedly failed the sudo password check.",
                evs[0].time, evs[-1].time, len(evs), user=user, evidence=_evidence(evs)))
    return out


# ---------------------------------------------------------------- web rules

SENSITIVE = re.compile(
    r"(?i)(?:^|/)(?:\.env(?:\.\w+)?|\.git/(?:config|HEAD)|\.svn/|\.aws/credentials|\.ssh/|id_rsa|"
    r"wp-config\.php(?:\.bak)?|config\.php\.bak|phpinfo\.php|server-status|\.DS_Store|"
    r"backup\.(?:zip|tar\.gz|sql)|dump\.sql|database\.sql|web\.config|\.htpasswd|actuator/(?:env|heapdump))(?:$|[?#])")
PROBES = re.compile(r"(?i)^/(?:wp-login\.php|xmlrpc\.php|wp-admin/|phpmyadmin/?|pma/|cgi-bin/|boaform/|HNAP1|vendor/phpunit)")

ATTACKS = [  # (name, rule id, pattern)
    ("SQL injection", "web-sqli", re.compile(r"(?i)(?:union(?:\s|\+|/\*.*?\*/)+(?:all\s+)?select|'\s*or\s*'?\d+'?\s*=\s*'?\d|\bor\s+1\s*=\s*1\b|sleep\(\s*\d+\s*\)|benchmark\(|information_schema|;\s*drop\s+table)")),
    ("Path traversal", "web-path-traversal", re.compile(r"(?:\.\./|\.\.\\|%2e%2e(?:%2f|/)|/etc/passwd|c:\\windows\\win\.ini)", re.I)),
    ("Cross-site scripting", "web-xss", re.compile(r"(?i)(?:<script\b|javascript:|onerror\s*=|onload\s*=|<svg[^>]*on\w+\s*=|alert\()")),
    ("Command injection", "web-command-injection", re.compile(r"(?i)(?:;|\||`|\$\()\s*(?:cat|wget|curl|id|uname|whoami|nc|bash|sh)\b")),
    ("Log4Shell / JNDI", "web-log4shell", re.compile(r"(?i)\$\{jndi:")),
]


def _decoded(path: str) -> str:
    # decode twice: scanners often double-encode to slip past simple filters
    once = unquote_plus(path)
    return unquote_plus(once)


def web_findings(events: list[WebEvent], s: Settings) -> list[Finding]:
    out: list[Finding] = []
    by_ip: dict[str, list[WebEvent]] = defaultdict(list)
    for e in sorted(events, key=lambda e: e.time):
        if not _ignored(e.ip, s):
            by_ip[e.ip].append(e)

    for ip, evs in by_ip.items():
        errors = [e for e in evs if 400 <= e.status < 500]
        if len(errors) >= s.web_errors:
            best = max(iter_window([e.time for e in errors], s.web_window), key=lambda p: p[1] - p[0])
            n = best[1] - best[0] + 1
            if n >= s.web_errors:
                paths = Counter(e.path.split("?")[0] for e in errors)
                out.append(Finding(
                    "high", "web-scanner", f"Scanner activity from {ip}",
                    f"{_plural(len(errors), 'request')} answered 4xx, {n} of them within {int(s.web_window.total_seconds() // 60)} minutes. "
                    f"Most requested: {', '.join(p for p, _ in paths.most_common(4))}.",
                    errors[0].time, errors[-1].time, len(errors), ip=ip, evidence=_evidence(errors)))

        sensitive = [e for e in evs if SENSITIVE.search(e.path.split("?")[0]) or PROBES.search(e.path)]
        if len(sensitive) >= s.sensitive_hits:
            served = [e for e in sensitive if 200 <= e.status < 300 and SENSITIVE.search(e.path.split("?")[0])]
            out.append(Finding(
                "critical" if served else "medium", "web-sensitive-files",
                f"{ip} asked for files that should never be public" + (" and got some" if served else ""),
                (f"{_plural(len(served), 'request')} for secrets or backups returned 2xx: "
                 f"{', '.join(sorted({e.path for e in served})[:4])}. Check those files are not really exposed. " if served else "")
                + f"{_plural(len(sensitive), 'request')} for paths like .env, .git/config, wp-login.php or phpMyAdmin.",
                sensitive[0].time, sensitive[-1].time, len(sensitive), ip=ip, evidence=_evidence(served or sensitive)))

        hits: dict[tuple[str, str], list[WebEvent]] = defaultdict(list)
        for e in evs:
            text = _decoded(e.path) + " " + _decoded(e.agent)
            for name, rule, rx in ATTACKS:
                if rx.search(text):
                    hits[(name, rule)].append(e)
        for (name, rule), matched in hits.items():
            ok = [e for e in matched if 200 <= e.status < 300]
            out.append(Finding(
                "high" if ok else "medium", rule,
                f"{name} attempts from {ip}",
                f"{_plural(len(matched), 'request')} matched {name} patterns"
                + (f"; {len(ok)} returned 2xx, so check how the application handled them." if ok else ", all refused or failed."),
                matched[0].time, matched[-1].time, len(matched), ip=ip, evidence=_evidence(matched)))

    # bursts of server errors, per minute, across all clients
    per_minute: dict[datetime, list[WebEvent]] = defaultdict(list)
    for e in events:
        if e.status >= 500:
            per_minute[e.time.replace(second=0, microsecond=0)].append(e)
    bursts = sorted((m, evs) for m, evs in per_minute.items() if len(evs) >= s.error_burst)
    if bursts:
        total = sum(len(v) for _, v in bursts)
        worst_minute, worst = max(bursts, key=lambda b: len(b[1]))
        out.append(Finding(
            "medium", "web-5xx-burst", f"Server errors spiked in {_plural(len(bursts), 'minute')}",
            f"{total} responses with status 5xx in those minutes; the worst was {worst_minute:%Y-%m-%d %H:%M} with {len(worst)}. "
            "Check the application and upstream logs for that time.",
            bursts[0][0], bursts[-1][0] + timedelta(seconds=59), total, evidence=_evidence(worst)))
    return out


def run_all(auth: Iterable[AuthEvent], web: Iterable[WebEvent], settings: Optional[Settings] = None) -> list[Finding]:
    settings = settings or Settings()
    auth, web = list(auth), list(web)
    findings = ssh_findings(auth, settings) + sudo_findings(auth, settings) + web_findings(web, settings)
    findings.sort(key=lambda f: (-RANK[f.severity], -f.count, f.first_seen))
    return findings
