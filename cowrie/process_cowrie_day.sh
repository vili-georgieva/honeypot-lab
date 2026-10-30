#!/usr/bin/env bash
set -euo pipefail

DAY="${1:?Usage: $0 YYYY-MM-DD}"
export DAY

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# =========================
# Config (adjust if needed)
# =========================
COWRIE_LOG_DIR="${HOME}/cowrie-docker/logs"
WORK_DIR="${HOME}/cowrie-work"

RAW_RETENTION_DAYS=14        # delete archived raw older than this
DERIVED_RETENTION_DAYS=30    # keep derived longer (debugging)
REPORT_RETENTION_DAYS=60     # keep reports longer

# =========================
# Helpers
# =========================
die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[INFO] $*"; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Missing command: $1"; }

DATE_ARG="${1:-}"
if [[ -z "$DATE_ARG" ]]; then
  die "Usage: $0 YYYY-MM-DD"
fi

# Basic date validation (GNU date)
if ! date -d "$DATE_ARG" "+%F" >/dev/null 2>&1; then
  die "Invalid date: $DATE_ARG (expected YYYY-MM-DD)"
fi

need_cmd jq
need_cmd gzip
need_cmd find
need_cmd wc
need_cmd sort
need_cmd uniq
need_cmd head

# Directories
RAW_DIR="${WORK_DIR}/raw"
DERIVED_DIR="${WORK_DIR}/derived"
REPORTS_DIR="${WORK_DIR}/reports"
ARCHIVE_RAW_DIR="${WORK_DIR}/archive/raw"

mkdir -p "${RAW_DIR}" "${DERIVED_DIR}" "${REPORTS_DIR}" "${ARCHIVE_RAW_DIR}"

INPUT_FILE="${COWRIE_LOG_DIR}/cowrie.json.${DATE_ARG}"
[[ -f "$INPUT_FILE" ]] || die "Input file not found: ${INPUT_FILE}"

# Outputs
NORM_FILE="${DERIVED_DIR}/cowrie_norm_v1_1_${DATE_ARG}.jsonl"
SESS_FILE="${DERIVED_DIR}/cowrie_sessions_metrics_${DATE_ARG}.jsonl"

INTERACTIVE_IDS_TXT="${DERIVED_DIR}/interactive_session_ids_${DATE_ARG}.txt"
INTERACTIVE_IDS_JSON="${DERIVED_DIR}/interactive_session_ids_${DATE_ARG}.json"
INTERACTIVE_CMDS="${DERIVED_DIR}/interactive_commands_${DATE_ARG}.jsonl"

EVENTID_REPORT="${REPORTS_DIR}/eventid_counts_${DATE_ARG}.txt"
EVENTTYPE_REPORT="${REPORTS_DIR}/eventtype_counts_${DATE_ARG}.txt"
SESSIONCLASS_REPORT="${REPORTS_DIR}/sessionclass_counts_${DATE_ARG}.txt"

ARCHIVE_FILE="${ARCHIVE_RAW_DIR}/cowrie.json.${DATE_ARG}.gz"

# Idempotency: avoid redoing work unless you delete outputs
if [[ -f "$SESS_FILE" ]]; then
  info "Session metrics already exist: $SESS_FILE"
  info "Nothing to do. (Delete output files if you want to re-run.)"
  exit 0
fi

# =========================
# Step A: eventid inventory report (from raw)
# =========================

info "Processing day: $DAY"
info "Generating eventid inventory report..."
jq -r '.eventid' "$INPUT_FILE" | sort | uniq -c | sort -nr > "$EVENTID_REPORT"

# =========================
# Step B: Normalize (raw -> normalized events)
# =========================
info "Normalizing raw events -> $NORM_FILE"

jq -c '
def map_type(e):
  if e == "cowrie.login.failed" then "auth_fail"
  elif e == "cowrie.login.success" then "auth_success"
  elif e == "cowrie.session.connect" then "session_start"
  elif e == "cowrie.session.closed" then "session_end"
  elif e == "cowrie.command.input" or e == "cowrie.command.failed" then "command"
  elif e == "cowrie.client.version"
    or e == "cowrie.client.kex"
    or e == "cowrie.client.fingerprint"
    or e == "cowrie.client.size" then "client_fingerprint"
  elif e == "cowrie.session.file_upload"
    or e == "cowrie.session.file_download" then "file_transfer"
  elif e | startswith("cowrie.direct-tcpip") then "tunnel_attempt"
  else "other"
  end;

{
  ts: .timestamp,
  sensor: "cowrie",
  event_type: map_type(.eventid),
  event_id_raw: .eventid,
  session_id: (.session // null),
  src_ip: (.src_ip // null),
  src_port: (.src_port // null),
  dst_ip: (.dst_ip // null),
  dst_port: (.dst_port // null),
  username: (.username // null),
  password: (.password // null),
  success: (.success // null),
  command: (.input // .command // null)
}
' "$INPUT_FILE" > "$NORM_FILE"

# Event type counts report
info "Generating event_type counts report..."
jq -r '.event_type' "$NORM_FILE" | sort | uniq -c | sort -nr > "$EVENTTYPE_REPORT"

# =========================
# Step C: Session metrics (normalized -> sessions)
# =========================
info "Building session metrics -> $SESS_FILE"

jq -c -s '
def has(x): index(x) != null;

def norm_ts(ts):
  ts | sub("\\.[0-9]+Z$"; "Z");

def classify(events):
  if (events | has("command")) then "interactive"
  elif (events | has("auth_success")) then "successful_login_no_activity"
  elif (events | has("auth_fail")) and (events | has("auth_success") | not) and (events | has("command") | not) then "bruteforce_only"
  elif (events | has("session_start")) and (events | has("session_end")) and (events | length == 2) then "connect_only"
  elif (events | has("client_fingerprint")) and (events | has("command") | not)
       and (events | has("auth_fail") | not) and (events | has("auth_success") | not) then "scanner"
  else "unknown"
  end;

group_by(.session_id)
| map(
    . as $rows
    | (
        ($rows | map(.event_type) | unique) as $ev
        | {
            session_id: ($rows[0].session_id),
            src_ip: ($rows | map(.src_ip) | map(select(.!=null)) | .[0] // null),
            start_ts: ($rows | map(.ts) | min),
            end_ts: ($rows | map(.ts) | max),
            duration_sec: (
              ( norm_ts($rows | map(.ts) | max) | fromdateiso8601 )
              -
              ( norm_ts($rows | map(.ts) | min) | fromdateiso8601 )
            ),
            auth_fail_count: ($rows | map(select(.event_type=="auth_fail")) | length),
            auth_success_count: ($rows | map(select(.event_type=="auth_success")) | length),
            command_count: ($rows | map(select(.event_type=="command")) | length),
            file_transfer_count: ($rows | map(select(.event_type=="file_transfer")) | length),
            tunnel_attempt_count: ($rows | map(select(.event_type=="tunnel_attempt")) | length),
            event_types: $ev,
            session_class: classify($ev)
          }
      )
  )
| .[]
' "$NORM_FILE" > "$SESS_FILE"

# Session class counts report
info "Generating session_class counts report..."
jq -r '.session_class' "$SESS_FILE" | sort | uniq -c | sort -nr > "$SESSIONCLASS_REPORT"

# =========================
# Step D: Interactive commands dataset
# =========================
info "Extracting interactive session IDs..."
jq -r 'select(.session_class=="interactive") | .session_id' "$SESS_FILE" \
  | sort -u > "$INTERACTIVE_IDS_TXT"

# Convert plaintext IDs -> JSON array for jq --slurpfile
jq -R -s 'split("\n") | map(select(length>0))' "$INTERACTIVE_IDS_TXT" > "$INTERACTIVE_IDS_JSON"

info "Extracting interactive command events..."
jq -c --slurpfile ids "$INTERACTIVE_IDS_JSON" '
  # make a set: {"id1":true,"id2":true,...}
  ($ids[0] | map({(.): true}) | add) as $set
  | select(type=="object")
  | select(.session_id != null and ($set[.session_id] == true))
  | select(.event_type=="command" and .command!=null)
' "$NORM_FILE" > "$INTERACTIVE_CMDS"

# =========================
# Step E: Sanity checks
# =========================
RAW_LINES=$(wc -l < "$INPUT_FILE" || echo 0)
NORM_LINES=$(wc -l < "$NORM_FILE" || echo 0)
SESS_LINES=$(wc -l < "$SESS_FILE" || echo 0)
CMD_LINES=$(wc -l < "$INTERACTIVE_CMDS" || echo 0)

info "Sanity checks:"
info "  raw_lines=$RAW_LINES"
info "  norm_lines=$NORM_LINES"
info "  sessions=$SESS_LINES"
info "  interactive_command_events=$CMD_LINES"

# raw and norm should have same number of lines (one output event per input line)
if [[ "$RAW_LINES" -ne "$NORM_LINES" ]]; then
  die "Sanity check failed: raw_lines ($RAW_LINES) != norm_lines ($NORM_LINES)"
fi

# sessions should be > 0
if [[ "$SESS_LINES" -le 0 ]]; then
  die "Sanity check failed: sessions file empty"
fi

# =========================
# Step F: Archive raw (gzip) and retention
# =========================
if [[ ! -f "$ARCHIVE_FILE" ]]; then
  info "Archiving raw log to $ARCHIVE_FILE"
  gzip -c "$INPUT_FILE" > "$ARCHIVE_FILE"
else
  info "Archive already exists: $ARCHIVE_FILE"
fi

info "Retention cleanup..."
# Archived raw retention
find "$ARCHIVE_RAW_DIR" -type f -name "cowrie.json.*.gz" -mtime +"$RAW_RETENTION_DAYS" -print -delete || true
# Derived retention (keep longer)
find "$DERIVED_DIR" -type f -name "*.jsonl" -mtime +"$DERIVED_RETENTION_DAYS" -print -delete || true
find "$DERIVED_DIR" -type f -name "*.txt" -mtime +"$DERIVED_RETENTION_DAYS" -print -delete || true
find "$DERIVED_DIR" -type f -name "*.json"  -mtime +"$DERIVED_RETENTION_DAYS" -print -delete || true
# Reports retention
find "$REPORTS_DIR" -type f -name "*.txt" -mtime +"$REPORT_RETENTION_DAYS" -print -delete || true

info "Done for date $DATE_ARG"
info "Outputs:"
info "  $NORM_FILE"
info "  $SESS_FILE"
info "  $INTERACTIVE_CMDS"
info "Reports:"
info "  $EVENTID_REPORT"
info "  $EVENTTYPE_REPORT"
info "  $SESSIONCLASS_REPORT"

# ---- Ingest (only if files have content) ----
# Use the same date argument we processed
DAY="${DATE_ARG:-${1:-}}"

if [[ -z "$DAY" ]]; then
  info "Skipping ingest: no DAY/DATE_ARG available"
  exit 0
fi

if [[ "${SESS_LINES:-0}" -gt 0 ]]; then
  ./ingest_sessions_metrics.sh "$DAY"
else
  info "Skipping session metrics ingest (no sessions)"
fi

if [[ "${CMD_LINES:-0}" -gt 0 ]]; then
  ./ingest_interactive_commands.sh "$DAY"
else
  info "Skipping commands ingest (no interactive commands)"
fi