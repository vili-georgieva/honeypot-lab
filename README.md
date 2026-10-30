# honeypot-lab

Configs and scripts from a honeypot project we ran during Innovation Lab 2 at FH Technikum Wien (2026). We had several sensors running on Azure VMs (Cowrie, Endlessh, Heralding and an NGINX web honeypot), collected the logs in Azure Blob Storage and analysed them afterwards.

This repo contains two parts of that setup:

- `nginx/` - a low-interaction web honeypot based on NGINX, plus a Python script that looks for php2shell / LFI-to-RCE attempts in the logs
- `cowrie/` - shell scripts that turn the raw Cowrie SSH logs into a normalized format and load them into OpenSearch

Logs, keys and the real Azure settings are not part of this repo.

## NGINX honeypot

The first version of the web honeypot answered almost everything with a 404. In the logs we could see scanners like `php2s-scan/1.0` hitting the server, but there was never a payload in the log. Two reasons:

1. Scanners stop as soon as the target doesn't look like PHP. A plain 404 on `/` is enough for that.
2. NGINX does not read the request body when a location just does `return ...`, so `$request_body` was always empty.

The fix was to put everything behind an internal server on `127.0.0.1:8088` and `proxy_pass` to it. Because of the proxy, NGINX has to read the full body, and the public server logs it. The internal server then pretends to be an Ubuntu box with Apache, PHP 8.1.2 and WordPress:

- `X-Powered-By` and `PHPSESSID` cookie on every response
- a fake landing page and `/index.php` that prints a real looking PHP `include()` warning when someone tries `?file=/tmp/sess_...`, `php://filter` or `../`
- a fake `phpinfo()` with `session.upload_progress.enabled: On`
- WordPress decoys (`wp-login.php` with a slow tarpit, `xmlrpc.php`, `wp-json`), phpMyAdmin
- canary files like `/.env`, `/.git/config` and `/database_dump.sql` with fake credentials

Every request is written as one JSON line with 21 fields (IP, port, method, URI, headers, cookies, content type, transfer encoding and the full body up to 1 MB).

A few seconds after we deployed the new config, a bot (Androxgh0st) sent a full multipart payload, which was the first one we ever captured on that sensor.

### Running it

```bash
cd nginx
mkdir -p logs ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout ssl/key.pem -out ssl/cert.pem -subj "/CN=localhost"
docker compose up -d
```

Quick test from another terminal:

```bash
curl -i "http://localhost/index.php?file=/tmp/sess_test"
tail -n 1 logs/honeypot.log
```

Do not run this on a machine that has anything else on it. It is meant for a throwaway VM.

### detect_php2shell.py

Reads the JSON logs (plain or `.gz`) and checks every request against a set of rules, for example:

- POST multipart to `/` or `/index.php` (where nobody uploads files normally)
- `PHP_SESSION_UPLOAD_PROGRESS` in the body, which is the main indicator for php2shell
- chunked multipart, many empty file parts
- known scanner user agents and multipart boundaries (`php2s`, assetnote, the React2Shell PoC)
- LFI patterns in the URI (`/tmp/sess_*`, `php://`, `../`, `/etc/passwd`)

Hits are sorted into tiers: T0 recon, T1 probe, T2 armed. For T2 the script also pulls the payload out of the multipart body.

```bash
python3 detect_php2shell.py --file logs/honeypot.log
python3 detect_php2shell.py --dir logs/archive
python3 detect_php2shell.py --live --path logs/honeypot.log
```

On one week of logs from our sensor (about 15,000 requests) it flagged 139 events, mostly LFI probes for `/etc/passwd`.

The output and comments in the script are in German.

### Log rotation and upload

`scripts/rotate_logs.sh` runs once a day via cron, moves the log to an archive folder, tells NGINX to reopen the file and gzips the old one. `scripts/upload_to_blob.sh` uploads the archived files to Azure Blob Storage with a SAS token (`raw/nginx/<sensor>/<yyyy>/<mm>/<dd>/...`). The settings go into `honeypot-nginx.env`, see the `.example` file.

## Cowrie pipeline

Cowrie writes one JSON file per day. `process_cowrie_day.sh YYYY-MM-DD` does the following with `jq`:

1. counts the raw event ids
2. maps every event to a smaller set of types (`auth_fail`, `auth_success`, `session_start`, `command`, `file_transfer`, ...), the schema is in `schema.md`
3. groups the events per session and classifies it (scanner, connect only, brute force only, login without activity, interactive)
4. extracts the commands from interactive sessions
5. writes a few count reports and archives the raw file

`ingest_sessions_metrics.sh` and `ingest_interactive_commands.sh` then load the results into daily OpenSearch indices. `docker-compose.yml` starts OpenSearch and Postgres, both only on localhost.

Needs `bash`, `jq`, `curl` and `gzip`.

## Tech

NGINX, Docker, Python 3 (standard library only), Bash, jq, OpenSearch, Azure VMs and Blob Storage
