# Setup Guide

Complete, step-by-step setup for the AI-Augmented Honeypot System, from a clean
environment to a working end-to-end pipeline with live Kibana dashboards.

If you just want the condensed version, see the
[README](../README.md#setup). This guide is the detailed walkthrough.

---

## 0. Overview — what runs where

The system spans up to four roles. They can be four machines, or fewer (e.g. ES +
Kibana on your laptop, everything else on one server) — but keep the honeypot
isolated from anything you care about.

| Role | Machine | What it runs | Talks to |
|------|---------|--------------|----------|
| **Backend** | Linux GPU server (cloud VM / workstation / bare metal) | `serve_final.py` + the 3 engine modules, DeepSeek + LoRA | receives HTTP from Cowrie; writes `serve_outputs.jsonl` |
| **Honeypot** | Ubuntu host | Cowrie SSH honeypot | forwards commands to Backend |
| **Attacker** | Kali Linux | your test SSH client | connects to Cowrie on port 2222 |
| **Monitoring** | Windows / any host | Elasticsearch + Kibana + `ship_to_elastic.py` | ingests the log |

**Data flow:** `Kali ──SSH──▶ Cowrie ──HTTP──▶ Backend ──log──▶ Elasticsearch ──▶ Kibana`

> ⚠️ **Isolate the honeypot.** It is designed to attract attackers. Never place it on a
> network with production or personal systems, and only test against systems you own.

---

## 1. Backend — GPU inference server

The backend is the only component that needs a GPU (for the model tier). The
hard-rule / VMS / session-history layers are pure Python and run anywhere, so you can
even smoke-test most of the system CPU-only.

### 1.1 Provision the machine

Any Linux host (Ubuntu/Debian recommended) with:
- A CUDA GPU, **~16–24 GB VRAM** (DeepSeek-Coder-V2-Lite-Instruct, 4-bit).
- Python **3.10+**, `git`, and the NVIDIA driver + CUDA runtime installed (`nvidia-smi` works).
- Network access so the Cowrie host can reach the backend on port **8000** — open it in
  the firewall / cloud security group.

This is provider-agnostic: it works on a cloud GPU VM (AWS, GCP, Azure, Lambda, RunPod,
Vast, …), an on-prem workstation, or bare metal. If your provider gives you a web
terminal or SSH, use whatever you have to upload the code and reach port 8000. Tested on
a Blackwell GPU (RTX PRO 4500, compute capability `sm_120`).

### 1.2 Clone and create a virtual environment

```bash
git clone https://github.com/<your-username>/ai-augmented-honeypot.git
cd ai-augmented-honeypot

python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
```

### 1.3 Install PyTorch for your GPU, then the rest

**Standard GPUs:**
```bash
pip install torch
pip install -r requirements.txt
```

**Blackwell / newer GPUs (`sm_120`) — pin a CUDA 12.8 build first:**
```bash
pip install torch --index-url https://download.pytorch.org/whl/cu128
pip install -r requirements.txt
```

Notes:
- If `bitsandbytes` can't load its CUDA kernel, the server automatically falls back to
  **fp16** (needs more VRAM). Force it with `USE_4BIT=0`.
- If `flash-attn` won't build, ignore it — the server uses the **eager** attention path.

### 1.4 Get the model + LoRA adapter

The base model downloads automatically from Hugging Face on first run. Pull the LoRA
adapter to the path configured as `ADAPTER_PATH` in `serve_final.py`:

```bash
pip install -U "huggingface_hub[cli]"
huggingface-cli download Patrick123345/deepseek-targeted-v2 \
  --local-dir ./deepseek-targeted-v2
```

Check `serve_final.py`:
```python
BASE_MODEL   = "deepseek-ai/DeepSeek-Coder-V2-Lite-Instruct"
ADAPTER_PATH = "./deepseek-targeted-v2"
PORT         = 8000
```

### 1.5 Run and verify

```bash
python3 serve_final.py
```

In another shell:
```bash
# health check
curl http://localhost:8000/health

# single command (bypasses Cowrie)
curl -s http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"COMMAND:\nwhoami"}]}'
```

You should get `root` (or the profile user). First model-backed command is slow
(model load / first generation); subsequent ones are cached.

> **No GPU handy?** You can still exercise ~81% of the system. The hard-rule engine,
> VMS, and session history import with only the standard library — write a small driver
> that calls `hard_rule_response(...)` and `session_history` to replay a command list.

---

## 2. Honeypot — Cowrie

Cowrie is the SSH front-end attackers actually connect to. It captures sessions and
forwards commands to the backend.

### 2.1 Install (on a separate Ubuntu host)

```bash
sudo apt-get update
sudo apt-get install -y git python3-venv python3-dev libssl-dev libffi-dev build-essential

sudo adduser --disabled-password cowrie
sudo su - cowrie

git clone https://github.com/cowrie/cowrie.git
cd cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 2.2 Configure

```bash
cp etc/cowrie.cfg.dist etc/cowrie.cfg
```

Key settings in `etc/cowrie.cfg`:
- Keep the SSH listener on **port 2222** (default).
- Point Cowrie's command handling at your backend URL, e.g. `http://<backend-host>:8000`.
  This is the custom integration hook you added so that commands Cowrie doesn't answer
  natively are POSTed to `/v1/chat/completions` and the raw response is returned to the
  attacker. Set the backend host/port there.

### 2.3 Start / stop / logs

```bash
bin/cowrie start      # or: python3 -m cowrie.scripts.cowrie start
bin/cowrie status
tail -f var/log/cowrie/cowrie.json     # structured event log
```

> **Permissions gotcha:** if Cowrie can't write its logs, fix ownership of
> `var/log/cowrie` (must be writable by the `cowrie` user). This was a real setup issue
> in development (Errno 13).

---

## 3. Attacker — Kali Linux

Nothing to install — just an SSH client. From Kali:

```bash
ssh root@<cowrie-host> -p 2222
# password: anything (Cowrie accepts weak creds by design)
```

Then run a session — see the ready-made list in the
[README](../README.md#testing-an-attack-session).

---

## 4. Monitoring — Elasticsearch + Kibana

You need Elasticsearch and Kibana **9.x** running and reachable from wherever you run
the shipper.

### 4.1 Start Elasticsearch + Kibana

Install both (same major version) and start them. On first start, ES 9.x **enables
security by default** and prints an `elastic` password and an enrollment token — save
these. Verify:

```bash
# with security on (default): https + auth
curl -k -u elastic:<password> https://localhost:9200
# with security off: plain http
curl http://localhost:9200
```

Kibana runs on `http://localhost:5601`.

### 4.2 Ship the serve log into Elasticsearch

`serve_final.py` writes one JSON record per command to `serve_outputs.jsonl`. The
included `ship_to_elastic.py` reads that file, enriches each record
(`command_name`, `category`, `handler`, `cached`, `intent`, `output_len`), and
bulk-indexes into the `honeypot-commands` index.

**If ES and the serve log are on the same machine:**
```bash
export ES_URL=http://localhost:9200
export SERVE_LOG=/path/to/serve_outputs.jsonl
python3 ship_to_elastic.py            # one-shot
python3 ship_to_elastic.py --watch    # continuous, every 10s
python3 ship_to_elastic.py --reset    # re-ship everything
```

**If ES is on a different host from the serve log** (e.g. ES on your laptop, the backend
on a remote GPU server) — copy the log over, then ship locally:
```powershell
# PowerShell example (Windows) — copy from the backend host over SSH
scp -P <ssh_port> <user>@<backend-host>:/path/to/serve_outputs.jsonl C:\honeypot\serve_outputs.jsonl

$env:ES_URL   = "http://localhost:9200"
$env:SERVE_LOG = "C:\honeypot\serve_outputs.jsonl"
python ship_to_elastic.py
```
(On Linux/macOS use `scp` the same way and export the vars with `export`.)

> **ES 9 security:** `ship_to_elastic.py` as written sends no auth and assumes `http://`.
> If your ES has security on (default), it will fail. Add an `Authorization: Basic`
> header + `https://` + disable cert verification for a self-signed cert — see
> [Troubleshooting](#7-troubleshooting). Or, for a local test only, start ES with
> security disabled.

> **Filters:** `CLEAN_ONLY=1` (default) drops failed/leaky outputs for a polished demo
> dashboard; run once with `CLEAN_ONLY=0` to see the honest failure rate. `MIN_TS`
> skips records older than a timestamp — set `MIN_TS=0` to ship everything.

### 4.3 Build the dashboards in Kibana

1. **Stack Management → Data Views → Create data view**
   - Name/index pattern: `honeypot-commands*`
   - Time field: `@timestamp`
2. **Dashboard → Create**, then add panels:
   - **Handler split** — pie, slice by `handler` (`hard_rule` vs `model`).
   - **Top commands** — bar/table, terms on `command_name`.
   - **Attacker intent** — pie, slice by `intent`.
   - **By category** — bar, terms on `category`.
   - **Activity over time** — date histogram on `@timestamp`, split series by `handler`.

---

## 5. Putting it together (end-to-end test)

1. Backend running (`curl /health` OK).
2. Cowrie running and pointed at the backend.
3. From Kali: `ssh root@<cowrie-host> -p 2222`, run a few commands
   (`whoami`, `cat .env`, `nmap -sV ...`).
4. On the backend, confirm lines are appended:
   `tail -f serve_outputs.jsonl`
5. Run `ship_to_elastic.py`, refresh the Kibana dashboard — the commands appear, split
   by handler and intent.

---

## 6. Configuration reference

**`serve_final.py`** (top of file): `BASE_MODEL`, `ADAPTER_PATH`, `PORT`,
`SERVE_OUTPUT_LOG`, `STATIC_CACHE_TTL_SECONDS`, `DYNAMIC_CACHE_TTL_SECONDS`,
and `FAKE_PROFILES` (the fake host definitions; default `ubuntu_web`).

**`ship_to_elastic.py`** (env vars): `ES_URL`, `SERVE_LOG`, `MIN_TS`, `CLEAN_ONLY`.

Environment defaults live in [`.env.example`](../.env.example) — copy to `.env`.

---

## 7. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `bitsandbytes` / CUDA kernel error on load | GPU arch vs. package mismatch (e.g. Blackwell `sm_120`) | Pin `torch` cu128; server falls back to fp16, or set `USE_4BIT=0` |
| `flash-attn` build fails | No compatible wheel | Ignore — server uses the eager attention path |
| Model output cut off mid-line (`nginx.conf`, `nmap`, big SQL tables) | Per-command token budget too low | Raise the value in `choose_max_tokens`, or serve that file as a hard rule/cache |
| First command very slow (~seconds), then fast | Model load + first generation; later served from cache | Expected; pre-warm by sending one command after startup |
| Cowrie won't start / no logs | `var/log/cowrie` not writable (Errno 13) | Fix ownership so the `cowrie` user can write |
| Backend unreachable from Cowrie | Firewall / wrong host / port not exposed | Open port 8000; verify with `curl http://<backend-host>:8000/health` |
| `ship_to_elastic.py` prints connection `error` | ES 9 security on (https + auth) but script sends none | Add auth/https (below), or disable ES security for local testing |
| Duplicate documents in Kibana after re-runs | Position file unwritable, or bulk uses auto-generated IDs | Ensure the position file path is writable; give docs a deterministic `_id` |
| Intent pie doesn't match the report | `ship_to_elastic.py` uses its own keyword heuristic, not the session-history classifier | Log the real `intent` in `serve_final.py` and have the shipper prefer it |

### Adding ES 9 auth to the shipper

If security is on, edit `es_request()` in `ship_to_elastic.py` to send basic auth over
HTTPS (self-signed cert → skip verification):

```python
import base64, ssl

ES_USER = os.environ.get("ES_USERNAME", "elastic")
ES_PASS = os.environ.get("ES_PASSWORD", "")
_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE   # self-signed cert (local/dev)

# in es_request(), when building the request:
if ES_PASS:
    token = base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()
    headers["Authorization"] = f"Basic {token}"

# and pass the SSL context to urlopen for https URLs:
with urllib.request.urlopen(req, timeout=30, context=_ctx) as resp:
    ...
```

Then set `ES_URL=https://localhost:9200` and export `ES_USERNAME` / `ES_PASSWORD`.

---

## 8. Security & ethics

- For **authorized defensive research and education only**.
- Contains **no malware** — attacker-style outputs are fabricated decoys.
- All hosts, IPs, credentials, and secrets in the profiles are **fake**.
- Isolate the honeypot from production/personal networks; deploy only where you're
  authorized.
