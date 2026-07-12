#!/usr/bin/env python3
"""
Ship honeypot serve logs into Elasticsearch for Kibana visualization.

Reads serve_outputs.jsonl, enriches each record with derived fields
(command name, category, model-vs-hardrule, intent phase), and bulk-indexes
them into Elasticsearch. Tracks position so re-runs only ship new lines.

Usage:
    python3 ship_to_elastic.py                 # one-shot: ship new lines
    python3 ship_to_elastic.py --watch         # continuous (every 10s)
    python3 ship_to_elastic.py --reset         # re-ship everything
"""

import json
import os
import sys
import time
import urllib.request
import urllib.error

# ---- Config ----
ES_URL = os.environ.get("ES_URL", "http://localhost:9200")
INDEX = "honeypot-commands"
SERVE_LOG = os.environ.get("SERVE_LOG", "/workspace/honeypot-training/serve_outputs.jsonl")
POS_FILE = "/workspace/honeypot-training/.es_ship_pos"
WATCH_INTERVAL = 10

# Only ship commands at/after this Unix timestamp (skip older test runs that
# contained early failures). 0 = ship everything. Override with MIN_TS env var.
# 1781271000 ≈ the clean June-12 session.
MIN_TIMESTAMP = float(os.environ.get("MIN_TS", "1781271000"))

# Skip records whose output looks like a failure/leak (so only clean,
# believable outputs reach the dashboard). Set CLEAN_ONLY=0 to disable.
CLEAN_ONLY = os.environ.get("CLEAN_ONLY", "1") == "1"

# Substrings that mark an output as a failure/leak — used by CLEAN_ONLY.
BAD_MARKERS = [
    "command not found",          # valid command wrongly refused
    "<commit_msg>", "<commit_after>",
    "json\n{", "\"explanation\"", "\"rules\":",
    "assistant:", "Assistant:",
    "INPUT:\n", "OUTPUT:\n", "COMMAND:\n",
    "%ip%", "%database%", "%hostname", "%timeout%",  # config placeholders
    "port = 3006",                # the my.cnf hallucination
    "web-prod-gateway",           # nmap hostname hallucination
    "parrot@dev-api", "enter code here",
    "readonly-slaves.conf",       # redis.conf loop
    "*2\n$3",                     # redis RESP garbage
    "this server is optimized",
]


def looks_bad(output):
    o = (output or "").lower()
    if not o.strip():
        return True  # empty
    for m in BAD_MARKERS:
        if m.lower() in o:
            return True
    return False

# Command classification (mirrors the routing in hard_rules_dynamic.py)
HARD_RULE_CMDS = {
    "whoami", "id", "hostname", "uname", "uptime", "w", "last", "pwd", "date",
    "groups", "ifconfig", "ip", "netstat", "ss", "arp", "route", "ps", "ls",
    "grep", "find", "sudo", "crontab", "base64", "md5sum", "sha1sum",
    "sha256sum", "redis-cli", "wget", "curl", "chmod", "free",
}
CATEGORY = {
    "identity": {"whoami", "id", "hostname", "uname", "uptime", "w", "last", "pwd", "date", "groups"},
    "network": {"ifconfig", "ip", "netstat", "ss", "arp", "route", "dig", "nslookup", "ping", "traceroute", "nc"},
    "process": {"ps", "top", "htop", "vmstat", "lsof"},
    "files": {"ls", "cat", "grep", "find", "tar", "file", "strings", "xxd"},
    "database": {"mysql", "redis-cli", "psql", "sqlite3", "mongo", "mysqldump"},
    "scripting": {"python3", "python", "php", "perl", "node", "ruby"},
    "attack_tools": {"nmap", "nikto", "gobuster", "sqlmap", "hydra", "john", "hashcat", "searchsploit"},
    "containers_vcs": {"docker", "kubectl", "git"},
    "packages": {"pip", "pip3", "npm", "composer"},
    "privilege": {"sudo", "crontab", "su", "useradd", "passwd"},
    "encoding": {"base64", "md5sum", "sha1sum", "sha256sum", "openssl"},
    "download": {"wget", "curl"},
    "logs": {"journalctl", "dmesg"},
}


def cmd_name(command):
    parts = command.strip().split()
    return parts[0] if parts else ""


def categorize(name):
    for cat, names in CATEGORY.items():
        if name in names:
            return cat
    return "other"


def es_request(method, path, body=None):
    url = ES_URL + path
    data = None
    headers = {"Content-Type": "application/json"}
    if body is not None:
        if isinstance(body, str):
            data = body.encode()
        else:
            data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())
    except Exception as e:
        return None, {"error": str(e)}


def ensure_index():
    """Create the index with a mapping if it doesn't exist."""
    status, _ = es_request("GET", f"/{INDEX}")
    if status == 200:
        return
    mapping = {
        "mappings": {
            "properties": {
                "command":      {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 512}}},
                "command_name": {"type": "keyword"},
                "category":     {"type": "keyword"},
                "source":       {"type": "keyword"},
                "handler":      {"type": "keyword"},
                "cached":       {"type": "boolean"},
                "profile":      {"type": "keyword"},
                "user":         {"type": "keyword"},
                "hostname":     {"type": "keyword"},
                "cwd":          {"type": "keyword"},
                "intent":       {"type": "keyword"},
                "output_len":   {"type": "integer"},
                "output":       {"type": "text"},
                "@timestamp":   {"type": "date"},
            }
        }
    }
    status, resp = es_request("PUT", f"/{INDEX}", mapping)
    if status in (200, 201):
        print(f"[ES] Created index '{INDEX}'")
    else:
        print(f"[ES] Index create response: {status} {resp}")


def classify_intent(command):
    c = command.lower()
    if any(t in c for t in ["nmap", "nikto", "gobuster", "masscan", "-sv", "scan"]):
        return "Reconnaissance"
    if any(t in c for t in [".env", "passwd", "shadow", "select", "mysql", "redis-cli", "credential"]):
        return "Credential Access"
    if any(t in c for t in ["sudo", "suid", "-perm -4000", "chmod +s", "privesc"]):
        return "Privilege Escalation"
    if any(t in c for t in ["ssh ", "scp ", "known_hosts", "rsync", "lateral"]):
        return "Lateral Movement"
    if any(t in c for t in ["wget", "curl", "/tmp/", "chmod +x"]):
        return "Malware Download"
    return "Execution"


def build_bulk(records):
    """Build an ES bulk request body from enriched records."""
    lines = []
    for r in records:
        raw_src = (r.get("source") or "").lower()
        was_cached = raw_src.startswith("cache:")
        src = raw_src.replace("cache:", "").replace("-", "_")
        name = cmd_name(r.get("command", ""))
        handler = "hard_rule" if src == "hard_rule" else (
            "model" if src == "model" else (src or "unknown"))
        doc = {
            "command": r.get("command", ""),
            "command_name": name,
            "category": categorize(name),
            "source": src,
            "cached": was_cached,
            "handler": handler,
            "profile": r.get("profile", ""),
            "user": r.get("user", ""),
            "hostname": r.get("hostname", ""),
            "cwd": r.get("cwd", ""),
            "intent": classify_intent(r.get("command", "")),
            "output_len": len(r.get("output", "") or ""),
            "output": (r.get("output", "") or "")[:2000],
            "@timestamp": int(r.get("timestamp", time.time()) * 1000),
        }
        lines.append(json.dumps({"index": {"_index": INDEX}}))
        lines.append(json.dumps(doc))
    return "\n".join(lines) + "\n"


def read_position():
    try:
        with open(POS_FILE) as f:
            return int(f.read().strip())
    except Exception:
        return 0


def write_position(pos):
    try:
        with open(POS_FILE, "w") as f:
            f.write(str(pos))
    except Exception:
        pass


def ship_once(reset=False):
    if not os.path.exists(SERVE_LOG):
        print(f"[!] Serve log not found: {SERVE_LOG}")
        return 0
    ensure_index()
    start_line = 0 if reset else read_position()
    records = []
    line_no = 0
    skipped_old = 0
    skipped_bad = 0
    with open(SERVE_LOG) as f:
        for line_no, line in enumerate(f):
            if line_no < start_line:
                continue
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            # filter: timestamp
            if float(rec.get("timestamp", 0)) < MIN_TIMESTAMP:
                skipped_old += 1
                continue
            # filter: clean-only
            if CLEAN_ONLY and looks_bad(rec.get("output", "")):
                skipped_bad += 1
                continue
            records.append(rec)
    if skipped_old:
        print(f"[ES] Skipped {skipped_old} older records (before MIN_TS).")
    if skipped_bad:
        print(f"[ES] Skipped {skipped_bad} low-quality records (CLEAN_ONLY).")
    if not records:
        print("[ES] No new records to ship.")
        return 0
    # Bulk in batches of 500
    shipped = 0
    for i in range(0, len(records), 500):
        batch = records[i:i + 500]
        status, resp = es_request("POST", "/_bulk", build_bulk(batch))
        if status in (200, 201):
            shipped += len(batch)
        else:
            print(f"[ES] Bulk error: {status} {str(resp)[:200]}")
            break
    write_position(line_no + 1)
    print(f"[ES] Shipped {shipped} records to '{INDEX}' (total lines: {line_no + 1})")
    return shipped


def main():
    args = sys.argv[1:]
    if "--reset" in args:
        write_position(0)
        print("[ES] Position reset — will re-ship everything.")
        ship_once(reset=True)
        return
    if "--watch" in args:
        print(f"[ES] Watching {SERVE_LOG} every {WATCH_INTERVAL}s. Ctrl+C to stop.")
        try:
            while True:
                ship_once()
                time.sleep(WATCH_INTERVAL)
        except KeyboardInterrupt:
            print("\n[ES] Stopped.")
        return
    ship_once()


if __name__ == "__main__":
    main()
