"""Turn raw log lines into events.

Two formats are understood:
  * OpenSSH / sudo lines from syslog (auth.log, secure), with either the classic
    "Nov 18 03:14:07" timestamp or the RFC 3339 one newer rsyslog/journald writes.
  * Web server access logs in the common or combined format (nginx and Apache defaults).

Lines that match neither are counted and skipped, never fatal.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable, Iterator, Optional

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


@dataclass(frozen=True)
class AuthEvent:
    time: datetime
    host: str
    kind: str            # failed, invalid_user, accepted, sudo_fail, sudo_ok
    user: str
    ip: Optional[str]
    method: str = ""     # password / publickey for accepted logins, command for sudo
    raw: str = field(default="", compare=False, repr=False)


@dataclass(frozen=True)
class WebEvent:
    time: datetime
    ip: str
    method: str
    path: str
    status: int
    size: int
    referrer: str
    agent: str
    raw: str = field(default="", compare=False, repr=False)


# ---------------------------------------------------------------- timestamps

_SYSLOG_CLASSIC = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<time>\d\d:\d\d:\d\d) (?P<host>\S+) (?P<rest>.*)$")
_SYSLOG_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?) (?P<host>\S+) (?P<rest>.*)$")


class YearGuesser:
    """Classic syslog lines have no year. Assume `year`, and step forward a year when the
    month goes backwards (a log that runs from December into January)."""

    def __init__(self, year: int):
        self.year = year
        self.last_month = 0

    def resolve(self, month: int) -> int:
        if self.last_month and month < self.last_month and self.last_month - month > 6:
            self.year += 1
        self.last_month = month
        return self.year


def _parse_iso(ts: str) -> datetime:
    ts = ts.replace("Z", "+00:00")
    if re.search(r"[+-]\d{4}$", ts):
        ts = ts[:-2] + ":" + ts[-2:]
    # fromisoformat accepts at most 6 fractional digits
    ts = re.sub(r"(\.\d{6})\d+", r"\1", ts)
    return datetime.fromisoformat(ts)


# ---------------------------------------------------------------- auth / sshd

_SSHD = re.compile(r"^sshd(?:-session)?\[\d+\]: (?P<msg>.*)$")
_SUDO = re.compile(r"^sudo(?:\[\d+\])?: +(?P<msg>.*)$")

_FAILED = re.compile(
    r"^Failed (?:password|publickey|keyboard-interactive/pam|none) for (?P<invalid>invalid user )?(?P<user>.*?) "
    r"from (?P<ip>[0-9A-Fa-f:.]+) port \d+")
_INVALID = re.compile(r"^Invalid user (?P<user>.*?) from (?P<ip>[0-9A-Fa-f:.]+)(?: port \d+)?$")
_ACCEPTED = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9A-Fa-f:.]+) port \d+")
_REPEATED = re.compile(r"^message repeated (?P<n>\d+) times: \[ ?(?P<msg>.*?) ?\]$")
_SUDO_FAIL = re.compile(r"^(?P<user>\S+) : (?:\d+ incorrect password attempts?|a password is required) ;")
_SUDO_OK = re.compile(r"^(?P<user>\S+) : (?:TTY=\S+ ; )?PWD=\S+ ; USER=\S+ ; COMMAND=(?P<cmd>.*)$")


def _valid_ip(text: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def parse_auth_line(line: str, years: YearGuesser) -> list[AuthEvent]:
    """Return the events on one auth.log line (a 'message repeated N times' line gives N)."""
    line = line.rstrip("\r\n")
    m = _SYSLOG_CLASSIC.match(line)
    if m:
        month = MONTHS.get(m["mon"])
        if not month:
            return []
        h, mi, s = (int(x) for x in m["time"].split(":"))
        try:
            when = datetime(years.resolve(month), month, int(m["day"]), h, mi, s)
        except ValueError:
            return []
    else:
        m = _SYSLOG_ISO.match(line)
        if not m:
            return []
        try:
            when = _parse_iso(m["ts"])
        except ValueError:
            return []
        when = when.replace(tzinfo=None)  # wall-clock time as written, like the classic format
    host, rest = m["host"], m["rest"]

    sm = _SSHD.match(rest)
    if sm:
        msg, times = sm["msg"], 1
        rep = _REPEATED.match(msg)
        if rep:
            msg, times = rep["msg"], int(rep["n"])
        ev = _sshd_event(msg, when, host, line)
        return [ev] * times if ev else []

    um = _SUDO.match(rest)
    if um:
        msg = um["msg"]
        f = _SUDO_FAIL.match(msg)
        if f:
            return [AuthEvent(when, host, "sudo_fail", f["user"], None, "", line)]
        ok = _SUDO_OK.match(msg)
        if ok:
            return [AuthEvent(when, host, "sudo_ok", ok["user"], None, ok["cmd"].strip(), line)]
    return []


def _sshd_event(msg: str, when: datetime, host: str, raw: str) -> Optional[AuthEvent]:
    m = _FAILED.match(msg)
    if m and _valid_ip(m["ip"]):
        return AuthEvent(when, host, "failed", m["user"], _valid_ip(m["ip"]),
                         "invalid" if m["invalid"] else "", raw)
    m = _INVALID.match(msg)
    if m and _valid_ip(m["ip"]):
        return AuthEvent(when, host, "invalid_user", m["user"], _valid_ip(m["ip"]), "", raw)
    m = _ACCEPTED.match(msg)
    if m and _valid_ip(m["ip"]):
        return AuthEvent(when, host, "accepted", m["user"], _valid_ip(m["ip"]), m["method"], raw)
    return None


# ---------------------------------------------------------------- access logs

_ACCESS = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<req>[^"\\]*(?:\\.[^"\\]*)*)" (?P<status>\d{3}) (?P<size>\d+|-)'
    r'(?: "(?P<ref>[^"\\]*(?:\\.[^"\\]*)*)" "(?P<agent>[^"\\]*(?:\\.[^"\\]*)*)")?')


def parse_access_line(line: str) -> Optional[WebEvent]:
    line = line.rstrip("\r\n")
    m = _ACCESS.match(line)
    if not m:
        return None
    ip = _valid_ip(m["ip"])
    if not ip:
        return None
    try:
        when = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None
    parts = m["req"].split(" ")
    if len(parts) >= 2:
        method, path = parts[0], parts[1]
    else:  # garbage request lines from scanners, e.g. "\x16\x03\x01..." or "-"
        method, path = "", m["req"]
    # Keep the wall-clock time as written. auth.log has no offset at all, so this lines both logs
    # from the same server up, and naive datetimes sort together without timezone errors.
    return WebEvent(when.replace(tzinfo=None), ip, method, path, int(m["status"]),
                    0 if m["size"] == "-" else int(m["size"]), m["ref"] or "", m["agent"] or "", line)


# ---------------------------------------------------------------- whole files

@dataclass
class ParseResult:
    auth: list[AuthEvent] = field(default_factory=list)
    web: list[WebEvent] = field(default_factory=list)
    lines: int = 0
    skipped: int = 0


def parse_lines(lines: Iterable[str], year: int, result: Optional[ParseResult] = None) -> ParseResult:
    """Parse a mix of auth and access log lines; each line is tried against both formats."""
    result = result or ParseResult()
    years = YearGuesser(year)
    for line in lines:
        if not line.strip():
            continue
        result.lines += 1
        web = parse_access_line(line)
        if web:
            result.web.append(web)
            continue
        auth = parse_auth_line(line, years)
        if auth:
            result.auth.extend(auth)
        else:
            result.skipped += 1
    return result


def iter_window(times: list[datetime], window: timedelta) -> Iterator[tuple[int, int]]:
    """For sorted times, yield (start, end) index pairs of the busiest stretch beginning at each event."""
    j = 0
    for i in range(len(times)):
        if j < i:
            j = i
        while j + 1 < len(times) and times[j + 1] - times[i] <= window:
            j += 1
        yield i, j
