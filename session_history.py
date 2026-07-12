"""
session_history.py
==================
Tracks attacker command history per session so the model can:
  1. See what the attacker has already done
  2. Maintain state across commands (cd changes cwd, downloads create files)
  3. Detect attack patterns and intent
  4. Generate context-aware, consistent responses

This solves the "command-by-command with no memory" problem.
The model now sees the relationship between commands.
"""

import time
import re
import json
import os
from collections import defaultdict


HISTORY_PERSIST_FILE = "/workspace/honeypot-training/session_histories.json"
MAX_HISTORY_IN_PROMPT = 15   # how many recent commands to show the model


# ============================================================
# SESSION HISTORY OBJECT
# ============================================================

class SessionHistory:
    """
    Tracks everything an attacker does in one session.
    """

    def __init__(self, session_id, profile_name, profile):
        self.session_id    = session_id
        self.profile_name  = profile_name
        self.profile       = profile
        self.created_at    = time.time()
        self.last_active   = time.time()

        # Command log: list of {command, output_source, timestamp, cwd}
        self.commands      = []

        # Derived state — changes as attacker acts
        self.current_cwd   = profile.get("webroot", "/")
        self.current_user  = "root"

        # Files the attacker created/downloaded during the session
        self.created_files = {}      # path -> content/marker

        # Files the attacker has viewed
        self.viewed_files  = set()

        # Commands that failed or returned errors
        self.errors        = []

        # Detected intent phases
        self.intent_phases = []

        # Tools/binaries the attacker downloaded
        self.downloads     = []

        # Environment variables the attacker has export'd or assigned this
        # session (e.g. "export SECRET=abc123", "TOKEN=xyz") — without this,
        # a later "echo $SECRET" has nothing consistent to read back.
        self.exported_vars = {}

    # --------------------------------------------------------
    # RECORD A COMMAND
    # --------------------------------------------------------

    def record(self, command, output, source):
        """Record a command and update derived state."""
        self.last_active = time.time()

        entry = {
            "command":   command,
            "output":    output,      # kept verbatim so model-generated turns
                                       # can be replayed as real conversation
                                       # history, not just summarized as text
            "source":    source,
            "cwd":       self.current_cwd,
            "timestamp": time.time(),
        }
        self.commands.append(entry)

        # Update state based on the command
        self._update_state(command, output)

        # Update intent classification
        self._classify_intent()

        return entry

    # --------------------------------------------------------
    # STATE TRACKING — the key feature
    # --------------------------------------------------------

    def _update_state(self, command, output):
        c = command.strip()
        cl = c.lower()

        # ── cd changes cwd ──
        if cl.startswith("cd "):
            target = c[3:].strip()
            self.current_cwd = self._resolve_path(target)

        elif cl == "cd":
            self.current_cwd = "/root" if self.current_user == "root" else f"/home/{self.current_user}"

        # ── export VAR=value / bare VAR=value assigns an env var ──
        # Without this, "export SECRET=abc123" followed later by
        # "echo $SECRET" has no session memory to stay consistent with.
        m = re.match(r'^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$', c)
        if m:
            key, val = m.group(1), m.group(2).strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
                val = val[1:-1]
            self.exported_vars[key] = val

        # ── su / sudo changes user ──
        if cl in ["sudo su", "sudo bash", "su", "su root", "su -"]:
            self.current_user = "root"
        elif cl.startswith("su "):
            parts = c.split()
            if len(parts) >= 2 and parts[1] != "-":
                self.current_user = parts[1]

        # ── wget/curl downloads create files ──
        if cl.startswith("wget ") or cl.startswith("curl "):
            self._record_download(c)

        # ── echo > file or tee creates files ──
        if ">" in c and ("echo " in cl or "cat " in cl):
            m = re.search(r">\s*(\S+)", c)
            if m:
                filepath = m.group(1)
                self.created_files[self._resolve_path(filepath)] = "attacker_created"

        # ── chmod marks file executable ──
        if cl.startswith("chmod ") and "+x" in cl:
            parts = c.split()
            if len(parts) >= 3:
                target = self._resolve_path(parts[-1])
                if target in self.created_files:
                    self.created_files[target] = "executable"

        # ── cat marks file viewed ──
        if cl.startswith("cat ") and ">" not in c:
            target = self._resolve_path(c[4:].strip())
            self.viewed_files.add(target)

        # ── touch / mkdir create files/dirs ──
        if cl.startswith("touch "):
            target = self._resolve_path(c[6:].strip())
            self.created_files[target] = "empty"
        if cl.startswith("mkdir "):
            target = self._resolve_path(c.split()[-1])
            self.created_files[target] = "directory"

        # ── rm removes files ──
        if cl.startswith("rm "):
            for part in c.split()[1:]:
                if not part.startswith("-"):
                    target = self._resolve_path(part)
                    self.created_files.pop(target, None)

        # ── error detection ──
        if output and any(x in output.lower() for x in
                          ["no such file", "permission denied", "command not found",
                           "cannot", "connection refused"]):
            self.errors.append({"command": c, "error": output[:100]})

    def _record_download(self, command):
        """Extract download info from wget/curl."""
        url_match = re.search(r"https?://\S+", command)
        url = url_match.group(0) if url_match else ""

        # Determine output filename
        out_match = re.search(r"-O\s+(\S+)", command)
        if out_match:
            filename = out_match.group(1)
        elif url:
            filename = url.rstrip("/").split("/")[-1]
        else:
            filename = "index.html"

        filepath = self._resolve_path(filename)
        self.created_files[filepath] = "downloaded"
        self.downloads.append({
            "url": url,
            "path": filepath,
            "timestamp": time.time(),
        })

    def _resolve_path(self, path):
        """Resolve relative path against current cwd."""
        path = path.strip().strip('"').strip("'")
        if path.startswith("/"):
            return path
        if path.startswith("~"):
            home = "/root" if self.current_user == "root" else f"/home/{self.current_user}"
            return path.replace("~", home, 1)
        if path == ".":
            return self.current_cwd
        if path == "..":
            return "/".join(self.current_cwd.rstrip("/").split("/")[:-1]) or "/"
        # Relative path
        return f"{self.current_cwd.rstrip('/')}/{path}"

    # --------------------------------------------------------
    # INTENT CLASSIFICATION
    # --------------------------------------------------------

    def _classify_intent(self):
        """Classify the current attack phase based on recent commands."""
        recent = [e["command"].lower() for e in self.commands[-10:]]
        recent_str = " ".join(recent)

        phase = "Unknown"

        # Reconnaissance
        recon_cmds = ["whoami", "id", "uname", "hostname", "ps aux", "netstat",
                      "ifconfig", "ip a", "cat /etc/passwd", "ls"]
        recon_count = sum(1 for cmd in recon_cmds if cmd in recent_str)

        # Credential access
        cred_cmds = ["cat .env", "config.php", "db_password", "grep password",
                     "cat /etc/shadow", "id_rsa", "authorized_keys", "mysql", "psql"]
        cred_count = sum(1 for cmd in cred_cmds if cmd in recent_str)

        # Malware download / execution
        malware_cmds = ["wget", "curl", "chmod +x", "/tmp/", "| sh", "| bash"]
        malware_count = sum(1 for cmd in malware_cmds if cmd in recent_str)

        # Persistence
        persist_cmds = ["crontab", "authorized_keys", "useradd", "systemctl",
                        ">> ~/.ssh", "/etc/rc.local", "chpasswd"]
        persist_count = sum(1 for cmd in persist_cmds if cmd in recent_str)

        # Lateral movement
        lateral_cmds = ["ssh ", "scp ", "rsync", "nmap", "ping ", "/dev/tcp"]
        lateral_count = sum(1 for cmd in lateral_cmds if cmd in recent_str)

        # Privilege escalation
        privesc_cmds = ["sudo", "perm -4000", "suid", "pkexec", "su root", "su -"]
        privesc_count = sum(1 for cmd in privesc_cmds if cmd in recent_str)

        scores = {
            "Reconnaissance":      recon_count,
            "Credential Access":   cred_count,
            "Malware Download":    malware_count,
            "Persistence":         persist_count,
            "Lateral Movement":    lateral_count,
            "Privilege Escalation":privesc_count,
        }

        phase = max(scores, key=scores.get)
        if scores[phase] == 0:
            phase = "Reconnaissance"  # default

        # Record phase transition
        if not self.intent_phases or self.intent_phases[-1]["phase"] != phase:
            self.intent_phases.append({
                "phase": phase,
                "at_command": len(self.commands),
                "timestamp": time.time(),
            })

    def get_current_intent(self):
        return self.intent_phases[-1]["phase"] if self.intent_phases else "Reconnaissance"

    # --------------------------------------------------------
    # MODEL CONTEXT — what the model sees
    # --------------------------------------------------------

    def to_model_context(self):
        """
        Generate session history context for the model prompt.
        This is what makes responses context-aware.
        """
        if not self.commands:
            return "SESSION_HISTORY: (no previous commands)\n"

        # Recent commands
        recent = self.commands[-MAX_HISTORY_IN_PROMPT:]
        history_lines = []
        for i, entry in enumerate(recent, 1):
            history_lines.append(f"  {entry['command']}")

        context = "SESSION_HISTORY (most recent commands by this attacker):\n"
        context += "\n".join(history_lines)
        context += "\n\n"

        # Current state
        context += "SESSION_STATE:\n"
        context += f"current_directory={self.current_cwd}\n"
        context += f"current_user={self.current_user}\n"
        context += f"attack_phase={self.get_current_intent()}\n"

        # Files the attacker created — model must remember these exist
        if self.created_files:
            files_str = ", ".join(
                f"{path} ({marker})"
                for path, marker in list(self.created_files.items())[:10]
            )
            context += f"attacker_created_files={files_str}\n"

        # Downloads
        if self.downloads:
            dl_str = ", ".join(d["path"] for d in self.downloads[-5:])
            context += f"downloaded_files={dl_str}\n"

        # Files viewed (so model stays consistent)
        if self.viewed_files:
            viewed_str = ", ".join(list(self.viewed_files)[:8])
            context += f"already_viewed_files={viewed_str}\n"

        # Exported / assigned environment variables — model must echo the
        # SAME value back if the attacker references the variable again.
        if self.exported_vars:
            vars_str = ", ".join(f"{k}={v}" for k, v in list(self.exported_vars.items())[:10])
            context += f"exported_variables={vars_str}\n"

        context += "\n"
        context += (
            "CONTEXT_RULES:\n"
            "- Stay consistent with previous command outputs.\n"
            "- If attacker created/downloaded a file, it exists now.\n"
            "- If attacker cd'd into a directory, you are in that directory.\n"
            "- A file viewed before must return the same content if viewed again.\n"
        )

        return context

    def to_message_turns(self, max_turns=4):
        """
        Return the last `max_turns` MODEL-generated exchanges as real
        (user, assistant) message pairs, so the model sees its own prior
        raw outputs verbatim — not just a text summary of what happened.

        Hard-rule and cache-served commands are deliberately excluded:
        those were already guaranteed correct and consistent by the VMS,
        so replaying them would only spend context budget on commands
        that never needed the model's memory to begin with. This mirrors
        Julien's server.py appending real session history to the message
        list, but scoped to only the turns where model memory actually
        matters.
        """
        model_entries = [
            e for e in self.commands
            if e.get("source", "").startswith("model") and e.get("output")
        ]
        recent = model_entries[-max_turns:]
        turns = []
        for e in recent:
            turns.append({"role": "user", "content": f"COMMAND:\n{e['command']}"})
            turns.append({"role": "assistant", "content": e["output"]})
        return turns

    # --------------------------------------------------------
    # ANALYTICS
    # --------------------------------------------------------

    def get_summary(self):
        """Summary for dashboard/logging."""
        return {
            "session_id":     self.session_id,
            "profile":        self.profile_name,
            "command_count":  len(self.commands),
            "current_cwd":    self.current_cwd,
            "current_user":   self.current_user,
            "current_intent": self.get_current_intent(),
            "intent_phases":  [p["phase"] for p in self.intent_phases],
            "downloads":      len(self.downloads),
            "created_files":  len(self.created_files),
            "errors":         len(self.errors),
            "duration_sec":   round(self.last_active - self.created_at, 1),
        }

    def to_dict(self):
        return {
            "session_id":    self.session_id,
            "profile_name":  self.profile_name,
            "created_at":    self.created_at,
            "last_active":   self.last_active,
            "commands":      self.commands,
            "current_cwd":   self.current_cwd,
            "current_user":  self.current_user,
            "created_files": self.created_files,
            "viewed_files":  list(self.viewed_files),
            "downloads":     self.downloads,
            "errors":        self.errors,
            "intent_phases": self.intent_phases,
        }


# ============================================================
# SESSION HISTORY MANAGER
# ============================================================

SESSION_HISTORIES = {}


def get_or_create_history(session_id, profile_name, profile):
    if session_id not in SESSION_HISTORIES:
        SESSION_HISTORIES[session_id] = SessionHistory(session_id, profile_name, profile)
        print(f"[History] New session: {session_id}")
    return SESSION_HISTORIES[session_id]


def get_history(session_id):
    return SESSION_HISTORIES.get(session_id)


def record_command(session_id, profile_name, profile, command, output, source):
    """Convenience: get history and record in one call."""
    hist = get_or_create_history(session_id, profile_name, profile)
    return hist.record(command, output, source)


def save_all_histories():
    """Persist all session histories to disk."""
    try:
        os.makedirs(os.path.dirname(HISTORY_PERSIST_FILE), exist_ok=True)
        data = {sid: h.to_dict() for sid, h in SESSION_HISTORIES.items()}
        with open(HISTORY_PERSIST_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[History] Save error: {e}")


def load_all_histories(profiles=None):
    """Load session histories from disk on startup (survives restarts)."""
    if not os.path.exists(HISTORY_PERSIST_FILE):
        return
    try:
        with open(HISTORY_PERSIST_FILE) as f:
            data = json.load(f)
        for sid, d in data.items():
            prof = {}
            if profiles and d.get("profile_name") in profiles:
                prof = profiles[d["profile_name"]]
            h = SessionHistory(sid, d.get("profile_name", ""), prof)
            h.created_at    = d.get("created_at", h.created_at)
            h.last_active   = d.get("last_active", h.last_active)
            h.commands      = d.get("commands", [])
            h.current_cwd   = d.get("current_cwd", h.current_cwd)
            h.current_user  = d.get("current_user", h.current_user)
            h.created_files  = d.get("created_files", {})
            h.viewed_files   = set(d.get("viewed_files", []))
            h.downloads      = d.get("downloads", [])
            h.errors         = d.get("errors", [])
            h.intent_phases  = d.get("intent_phases", [])
            SESSION_HISTORIES[sid] = h
        print(f"[History] Loaded {len(SESSION_HISTORIES)} session(s) from disk")
    except Exception as e:
        print(f"[History] Load error: {e}")


def get_all_summaries():
    """Get summaries of all active sessions for dashboard."""
    return [h.get_summary() for h in SESSION_HISTORIES.values()]


# ============================================================
# CWD RESOLUTION HELPER (used by serve to track cd)
# ============================================================

def resolve_current_cwd(session_id, default_cwd):
    """Get the attacker's current cwd based on their cd history."""
    hist = SESSION_HISTORIES.get(session_id)
    return hist.current_cwd if hist else default_cwd


def resolve_current_user(session_id, default_user):
    """Get the attacker's current user based on su/sudo history."""
    hist = SESSION_HISTORIES.get(session_id)
    return hist.current_user if hist else default_user