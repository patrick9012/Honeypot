import os
import json
import time
import re
from collections import defaultdict

# ============================================================
# AUTOMATED LEARNING PIPELINE
# Addresses supervisor feedback:
# "Attack Logs → Failure Detection → Dataset Generation
#  → LoRA Retraining → Evaluation → Deployment"
#
# Replaces the manual:
# "Manual testing → Find weakness → Create repair dataset → Retrain"
# ============================================================

COWRIE_LOG_PATH = "/home/azzi89/cowrie/var/log/cowrie/cowrie.json"
FAILURE_LOG_PATH = "/workspace/honeypot-training/failure_log.jsonl"
REPAIR_DATASET_PATH = "/workspace/honeypot-training/auto_repair_dataset.jsonl"
PIPELINE_STATE_FILE = "/workspace/honeypot-training/pipeline_state.json"

# ── AUTO-MODE CONFIG ────────────────────────────────────────
# How often the watcher checks for new failures (seconds)
WATCH_INTERVAL = 3600          # 1 hour
# Minimum new failures before auto-retraining is triggered
RETRAIN_THRESHOLD = 20
# Whether to actually launch retraining automatically (vs just prepare)
AUTO_RETRAIN = True
# Training script the pipeline launches when threshold is reached
TRAIN_SCRIPT = "/workspace/honeypot-training/train_tonight.py"

# AI leak / failure patterns
FAILURE_PATTERNS = [
    "as an ai",
    "i cannot",
    "language model",
    "here is the",
    "certainly",
    "```",
    "explanation:",
    "command type:",
    "honeypot",
    "simulation",
    "i'm sorry",
    "note:",
    "let me",
    "i'll",
    "i will",
]

# Path to the live command cache (so we can evict bad entries)
COMMAND_CACHE_FILE = "/workspace/honeypot-training/command_cache.json"

# Config files and the directives that MUST appear (structure check)
CONFIG_REQUIRED = {
    "cat /etc/ssh/sshd_config": ["port", "hostkey", "authentication"],
    "cat /etc/mysql/my.cnf":    ["[mysqld]", "datadir", "socket"],
    "cat /etc/nginx/nginx.conf":["worker_processes", "http", "server"],
    "cat /etc/redis/redis.conf":["bind", "port", "maxmemory"],
}

FORMAT_FAILURES = {
    "ps aux":  lambda o: not o.startswith("USER"),
    "ps -ef":  lambda o: not o.startswith("UID"),
    "find":    lambda o: any(not l.startswith("/") for l in o.splitlines() if l.strip()),
    "grep":    lambda o: len(o.splitlines()) > 20,  # grep returning full file
}

SYSTEM_PROMPT = "You are a Linux bash shell running on a compromised Ubuntu 22.04 LTS server. Output only raw terminal output. Never explain. Never mention AI. Never use markdown. Behave exactly like a real terminal."


# ============================================================
# STEP 1: PARSE ATTACK LOGS
# Read Cowrie JSON logs and extract failed/interesting sessions
# ============================================================

def parse_cowrie_logs(log_path=COWRIE_LOG_PATH, max_sessions=100):
    """
    Parse Cowrie JSON logs and extract command sequences per session.
    Returns list of sessions with commands and outputs.
    """
    if not os.path.exists(log_path):
        print(f"[Pipeline] Log file not found: {log_path}")
        return []

    sessions = defaultdict(list)

    with open(log_path, "r") as f:
        for line in f:
            try:
                event = json.loads(line.strip())
                session_id = event.get("session", "unknown")
                event_type = event.get("eventid", "")

                if event_type == "cowrie.command.input":
                    sessions[session_id].append({
                        "type": "command",
                        "command": event.get("input", ""),
                        "timestamp": event.get("timestamp", ""),
                        "src_ip": event.get("src_ip", ""),
                    })

            except json.JSONDecodeError:
                continue

    print(f"[Pipeline] Parsed {len(sessions)} sessions from logs")
    return dict(list(sessions.items())[:max_sessions])


# ============================================================
# STEP 2: FAILURE DETECTION
# Identify commands where the backend returned bad output
# ============================================================

def detect_failures(serve_log_path="/workspace/honeypot-training/serve_outputs.jsonl"):
    """
    Read serve terminal outputs and detect failures.
    The serve script should log (command, output, source) pairs to this file.
    Returns list of failed (command, output) pairs.
    """
    failures = []

    if not os.path.exists(serve_log_path):
        print(f"[Pipeline] Serve log not found: {serve_log_path}")
        print(f"[Pipeline] Add logging to serve_deepseek_lora.py to generate this file")
        return failures

    with open(serve_log_path, "r") as f:
        for line in f:
            try:
                entry = json.loads(line.strip())
                command = entry.get("command", "")
                output = entry.get("output", "")
                source = entry.get("source", "")

                # Only check model outputs — hard rules and cache are trusted
                if "deepseek" not in source and "model" not in source:
                    continue

                failure_reason = _check_failure(command, output)
                if failure_reason:
                    failures.append({
                        "command": command,
                        "output": output,
                        "source": source,
                        "failure_reason": failure_reason,
                        "timestamp": entry.get("timestamp", ""),
                    })

            except json.JSONDecodeError:
                continue

    print(f"[Pipeline] Detected {len(failures)} failures from serve log")
    return failures


def _check_failure(command, output):
    """Check if an output is a failure. Returns reason string or None."""
    output_lower = output.lower()

    # AI leakage check
    for pattern in FAILURE_PATTERNS:
        if pattern in output_lower:
            return f"ai_leak: '{pattern}'"

    # ── CONSISTENCY CHECK (PIDs / ports must match the VMS facts) ──
    # Now that ps/netstat/proc go to the model, verify the model used the
    # correct PID->service and port->service mapping. A wrong PID here is a
    # consistency failure even if the output "looks" fine.
    consistency = _check_consistency(command, output)
    if consistency:
        return consistency

    # Format failure check
    c = command.lower().strip()
    if c == "ps aux" and not output.startswith("USER"):
        return "format: ps aux missing USER header"

    if c == "ps -ef" and not output.startswith("UID"):
        return "format: ps -ef missing UID header"

    if c.startswith("find ") and output:
        for line in output.splitlines():
            if line.strip() and not line.strip().startswith("/"):
                return f"format: find returned non-path line: {line[:50]}"

    if c.startswith("grep ") and "DB_PASSWORD" in c:
        if output and len(output.splitlines()) > 5:
            return "format: grep returned too many lines (likely full file)"

    # ── CONFIG STRUCTURE CHECK ───────────────────────────────
    # Config files must contain their required directives. If a model
    # output for a known config is missing them, it's a failure.
    for cfg_cmd, required in CONFIG_REQUIRED.items():
        if c == cfg_cmd or c.startswith(cfg_cmd):
            if output.strip():
                missing = [r for r in required if r not in output_lower]
                if missing:
                    return f"config: {cfg_cmd} missing {missing}"

    # Empty output for non-empty commands
    if not output.strip() and c not in ["chmod ", "echo "]:
        return "empty_output"

    return None


def evict_from_cache(commands_to_remove, cache_file=COMMAND_CACHE_FILE):
    """
    Remove flagged bad outputs from the live command cache so they stop
    being served. Returns the number of entries removed.
    """
    if not os.path.exists(cache_file):
        return 0
    try:
        with open(cache_file) as f:
            cache = json.load(f)
    except Exception:
        return 0

    removed = 0
    # cache keys may be the command or a hash; match by the stored command field
    keys_to_delete = []
    for key, entry in cache.items():
        cmd = entry.get("command", key) if isinstance(entry, dict) else key
        if cmd in commands_to_remove:
            keys_to_delete.append(key)
    for k in keys_to_delete:
        del cache[k]
        removed += 1

    if removed:
        try:
            with open(cache_file, "w") as f:
                json.dump(cache, f, indent=2)
            print(f"[Pipeline] Evicted {removed} bad entr(ies) from cache")
        except Exception as e:
            print(f"[Pipeline] Cache eviction write error: {e}")
    return removed


# ── KNOWN-GOOD FACTS (must match virtual_fs.py for the ubuntu_web profile) ──
# The canonical PID -> service and port -> service mapping. If a model output
# contradicts these, it's a consistency failure.
CANONICAL_PID_SERVICE = {
    "742": "sshd",
    "841": "nginx",
    "1021": "mysqld",
    "1110": "redis",
}
CANONICAL_PORT_SERVICE = {
    "22": "sshd",
    "80": "nginx",
    "3306": "mysql",
    "6379": "redis",
}


def _check_consistency(command, output):
    """
    For model-handled ps/netstat/proc commands, verify the PIDs and ports
    match the canonical VMS facts. Returns a failure reason or None.
    """
    c = command.lower().strip()
    out = output.lower()

    # ps aux / ps -ef: if a known service appears, it must use the right PID
    if c.startswith("ps "):
        for pid, svc in CANONICAL_PID_SERVICE.items():
            if svc in out:
                # the service is mentioned; the correct PID should be near it
                # (same line). Check no WRONG pid is bound to this service.
                for line in output.splitlines():
                    if svc in line.lower() and pid not in line:
                        # service line exists but without the canonical PID
                        return f"consistency: {svc} should be PID {pid} in ps"

    # cat /proc/PID/status: the Name must match the canonical service for that PID
    m = re.search(r"/proc/(\d+)/status", c)
    if m:
        pid = m.group(1)
        expected = CANONICAL_PID_SERVICE.get(pid)
        if expected and expected not in out:
            return f"consistency: /proc/{pid}/status should be {expected}"

    # netstat / ss: each known port should map to the right service
    if c.startswith("netstat") or c.startswith("ss "):
        for port, svc in CANONICAL_PORT_SERVICE.items():
            for line in output.splitlines():
                if f":{port} " in line or line.strip().endswith(f":{port}"):
                    if svc not in line.lower():
                        # port shown but wrong/missing service
                        # (only flag if some other service name is on the line)
                        if any(s in line.lower() for s in
                               CANONICAL_PORT_SERVICE.values() if s != svc):
                            return f"consistency: port {port} should be {svc}"

    return None


# ============================================================
# STEP 3: DATASET GENERATION
# Auto-generate repair examples from failures
# ============================================================

REPAIR_TEMPLATES = {
    # These are templates for MODEL-handled commands. ps/netstat/redis/base64/
    # mysql-show are hard rules now, so they never reach the model and need no
    # repair templates. The model handles configs, scripting, and queries —
    # these templates give the correct output when the model fails on them.
    "cat /etc/ssh/sshd_config": {
        "output": (
            "Include /etc/ssh/sshd_config.d/*.conf\n"
            "Port 22\n"
            "PermitRootLogin yes\n"
            "PasswordAuthentication yes\n"
            "PubkeyAuthentication yes\n"
            "AuthorizedKeysFile .ssh/authorized_keys\n"
            "ChallengeResponseAuthentication no\n"
            "UsePAM yes\n"
            "X11Forwarding yes\n"
            "PrintMotd no\n"
            "AcceptEnv LANG LC_*\n"
            "Subsystem sftp /usr/lib/openssh/sftp-server"
        )
    },
    'python3 -c "import os; print(os.getuid())"': {
        "output": "0"
    },
    "python3 --version": {
        "output": "Python 3.10.12"
    },
}

# Knowledge base of correct outputs for model commands. Loaded from
# model_training_data.jsonl so the pipeline can repair ANY model command
# it has a known-good example for. Add examples to that file to teach the
# pipeline more commands — no code change needed.
MODEL_KB_FILE = "/workspace/honeypot-training/model_training_data.jsonl"


def load_model_kb(path=MODEL_KB_FILE):
    """Load correct command->output pairs from the training examples file."""
    kb = {}
    if not os.path.exists(path):
        return kb
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                ex = json.loads(line)
                msgs = ex.get("messages", [])
                user = next((m["content"] for m in msgs if m["role"] == "user"), "")
                assistant = next((m["content"] for m in msgs if m["role"] == "assistant"), "")
                if "COMMAND:" in user and assistant:
                    cmd = user.split("COMMAND:", 1)[1].strip().splitlines()[0].strip()
                    kb[cmd] = assistant
    except Exception as e:
        print(f"[Pipeline] Could not load model KB: {e}")
    return kb


# Loaded once at import
MODEL_KB = load_model_kb()


# Substring repair: command CONTAINS this -> correct output. Used for
# parametrised model commands like scripting where exact match won't hit.
REPAIR_SUBSTRING = [
    ("getuid()", "0"),
    ("getgid()", "0"),
    ("python3 --version", "Python 3.10.12"),
    ("python -V", "Python 3.10.12"),
]


def generate_repair_dataset(failures, output_path=REPAIR_DATASET_PATH):
    """
    Generate JSONL repair examples from detected failures.
    Uses templates for known failure types, skips unknown.
    """
    examples = []
    skipped = 0

    for failure in failures:
        command = failure["command"]
        reason = failure["failure_reason"]
        c = command.lower().strip()

        # Use template if available
        template_key = None
        for key in REPAIR_TEMPLATES:
            if c == key or c.startswith(key):
                template_key = key
                break

        if template_key:
            correct_output = REPAIR_TEMPLATES[template_key]["output"]
        elif command.strip() in MODEL_KB:
            # exact match against the training knowledge base
            correct_output = MODEL_KB[command.strip()]
        elif any(sub in command for sub, _ in REPAIR_SUBSTRING):
            # match a parametrised model command (e.g. python3 -c with getuid)
            correct_output = next(out for sub, out in REPAIR_SUBSTRING if sub in command)
        elif "ai_leak" in reason:
            # For AI leakage, the correct output is "command not found"
            cmd_name = command.split()[0]
            correct_output = f"bash: {cmd_name}: command not found"
        else:
            skipped += 1
            continue

        example = {
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"STATE:\nhostname=svr04\nuser=root\ncwd=/var/www/html\n"
                        f"recent_commands=[]\n\nCOMMAND:\n{command}"
                    )
                },
                {"role": "assistant", "content": correct_output},
            ],
            "metadata": {
                "source": "auto_repair",
                "failure_reason": reason,
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
        }
        examples.append(example)

    if examples:
        with open(output_path, "w") as f:
            for ex in examples:
                f.write(json.dumps(ex) + "\n")
        print(f"[Pipeline] Generated {len(examples)} repair examples → {output_path}")
    else:
        print(f"[Pipeline] No repair examples generated ({skipped} skipped)")

    return examples


# ============================================================
# STEP 4: RETRAIN TRIGGER
# Generate the training command for LoRA retraining
# ============================================================

def generate_retrain_command(
    repair_dataset_path=REPAIR_DATASET_PATH,
    base_adapter="Patrick123345/deepseek-v2-coder-relearned",
    output_adapter="/workspace/honeypot-training/deepseek-v2-coder-repaired",
    num_examples=None,
):
    """
    Print the LoRA retraining command with the repair dataset.
    Does not execute — prints for developer to run.
    """
    if not os.path.exists(repair_dataset_path):
        print(f"[Pipeline] Repair dataset not found: {repair_dataset_path}")
        return

    with open(repair_dataset_path) as f:
        count = sum(1 for _ in f)

    if num_examples is None:
        num_examples = count

    print(f"\n[Pipeline] Ready to retrain with {count} repair examples")
    print(f"[Pipeline] Run this command on RunPod:\n")
    print(f"""python3 train_lora.py \\
  --base_model deepseek-ai/DeepSeek-Coder-V2-Lite-Instruct \\
  --adapter_path {base_adapter} \\
  --train_data {repair_dataset_path} \\
  --output_dir {output_adapter} \\
  --num_train_epochs 1 \\
  --per_device_train_batch_size 2 \\
  --learning_rate 2e-4 \\
  --max_examples {num_examples}
""")
    return count


# ============================================================
# STEP 5: SAVE PIPELINE STATE
# Track pipeline runs for comparison
# ============================================================

def save_pipeline_state(failures, repair_count, metrics_summary=None):
    state = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "failures_detected": len(failures),
        "repair_examples_generated": repair_count,
        "failure_breakdown": defaultdict(int),
        "metrics": metrics_summary or {},
    }

    for f in failures:
        category = f["failure_reason"].split(":")[0]
        state["failure_breakdown"][category] += 1

    state["failure_breakdown"] = dict(state["failure_breakdown"])

    history = []
    if os.path.exists(PIPELINE_STATE_FILE):
        try:
            with open(PIPELINE_STATE_FILE) as f:
                history = json.load(f)
        except Exception:
            history = []

    history.append(state)

    with open(PIPELINE_STATE_FILE, "w") as f:
        json.dump(history, f, indent=2)

    print(f"[Pipeline] State saved → {PIPELINE_STATE_FILE}")
    return state


# ============================================================
# FULL PIPELINE RUN
# ============================================================

def run_pipeline(cowrie_log=COWRIE_LOG_PATH,
                 serve_log="/workspace/honeypot-training/serve_outputs.jsonl"):
    print("=" * 70)
    print("AUTOMATED LEARNING PIPELINE")
    print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    # Step 1 — Cowrie logs are OPTIONAL. The serve log (serve_outputs.jsonl)
    # is the primary source and already captures every command + output.
    print("\n[Step 1] Parsing attack logs...")
    if os.path.exists(cowrie_log):
        sessions = parse_cowrie_logs(cowrie_log)
        print(f"  Found {len(sessions)} attacker sessions (from Cowrie)")
    else:
        sessions = []
        print("  Cowrie log not used — relying on serve log (serve_outputs.jsonl)")

    # Step 2
    print("\n[Step 2] Detecting failures...")
    failures = detect_failures(serve_log)
    print(f"  Found {len(failures)} failed outputs")

    if not failures:
        print("  No failures detected — pipeline complete, no retraining needed")
        return

    # Step 3
    print("\n[Step 3] Generating repair dataset...")
    examples = generate_repair_dataset(failures)

    # Step 3b — evict the bad outputs from the live cache so they stop
    # being served immediately (don't wait for retraining)
    bad_commands = {f["command"] for f in failures}
    evict_from_cache(bad_commands)

    # Step 4
    print("\n[Step 4] Retraining command:")
    repair_count = generate_retrain_command()

    # Step 5
    print("\n[Step 5] Saving pipeline state...")
    save_pipeline_state(failures, len(examples) if examples else 0)

    print("\n[Pipeline] Complete.")
    print(f"  Failures detected: {len(failures)}")
    print(f"  Repair examples:   {len(examples) if examples else 0}")

    # ── AUTO-RETRAIN TRIGGER ─────────────────────────────────
    n_failures = len(failures)
    if AUTO_RETRAIN and n_failures >= RETRAIN_THRESHOLD:
        print(f"\n[Pipeline] Failure count ({n_failures}) >= threshold "
              f"({RETRAIN_THRESHOLD}) -> LAUNCHING AUTO-RETRAIN")
        launch_retraining()
    else:
        print(f"\n[Pipeline] {n_failures} failures (threshold {RETRAIN_THRESHOLD}). "
              f"No retrain yet.")
        print(f"  Next step: accumulate more attack data, or run retraining manually.")

    return n_failures


def launch_retraining():
    """Actually launch the LoRA retraining as a background process."""
    import subprocess
    if not os.path.exists(TRAIN_SCRIPT):
        print(f"  [!] Training script not found: {TRAIN_SCRIPT}")
        return
    try:
        log = open("/workspace/honeypot-training/auto_retrain.log", "a")
        log.write(f"\n=== Auto-retrain started {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
        log.flush()
        # Launch training in the background; output goes to the log
        subprocess.Popen(
            ["python3", TRAIN_SCRIPT],
            stdout=log, stderr=log,
            cwd="/workspace/honeypot-training",
        )
        print(f"  [+] Retraining launched in background.")
        print(f"      Monitor: tail -f /workspace/honeypot-training/auto_retrain.log")
        print(f"      After it finishes, deploy the new checkpoint and restart serve_final.py")
    except Exception as e:
        print(f"  [!] Failed to launch retraining: {e}")


def watch_loop():
    """Run the pipeline continuously on a schedule (automatic mode)."""
    print("=" * 70)
    print("PIPELINE AUTO-WATCH MODE")
    print(f"  Checking every {WATCH_INTERVAL}s ({WATCH_INTERVAL//60} min)")
    print(f"  Auto-retrain at >= {RETRAIN_THRESHOLD} failures")
    print(f"  Press Ctrl+C to stop")
    print("=" * 70)
    try:
        while True:
            run_pipeline()
            print(f"\n[Watch] Sleeping {WATCH_INTERVAL//60} min until next check...\n")
            time.sleep(WATCH_INTERVAL)
    except KeyboardInterrupt:
        print("\n[Watch] Stopped by user.")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] in ("--watch", "-w", "--auto"):
        watch_loop()
    else:
        run_pipeline()
        print("\n(Tip: run 'python3 pipeline.py --watch' for continuous automatic mode)")
