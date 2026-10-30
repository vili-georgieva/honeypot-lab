#!/usr/bin/env bash
set -euo pipefail

DAY="${1:-}"
if [[ -z "$DAY" ]]; then
  echo "Usage: $0 YYYY-MM-DD" >&2
  exit 1
fi

OS="${OS:-http://127.0.0.1:9200}"
IDX="cowrie-commands-${DAY//-/\.}"
SRC="${HOME}/cowrie-work/derived/interactive_commands_${DAY}.jsonl"

if [[ ! -s "$SRC" ]]; then
  echo "[INFO] No source file (or empty): $SRC"
  exit 0
fi

TOTAL=$(wc -l < "$SRC" | tr -d ' ')
INPUT=$(jq -c 'select(.event_id_raw=="cowrie.command.input")' "$SRC" | wc -l | tr -d ' ')
FAILED=$(jq -c 'select(.event_id_raw=="cowrie.command.failed")' "$SRC" | wc -l | tr -d ' ')

echo "[INFO] Ingest commands (interactive + noise) into ONE index"
echo "       Date:        $DAY"
echo "       Source:      $SRC"
echo "       Total docs:  $TOTAL"
echo "       Input docs:  $INPUT"
echo "       Failed docs: $FAILED"
echo "       Index:       $IDX"
echo

if [[ "$INPUT" == "0" && "$FAILED" == "0" ]]; then
  echo "[INFO] No cowrie.command.input/failed found for $DAY. Nothing to ingest."
  exit 0
fi

# Create index (idempotent: ignore if exists)
curl -sS -o /dev/null -X PUT "$OS/$IDX" \
  -H "Content-Type: application/json" \
  -d '{
    "settings": { "number_of_shards": 1, "number_of_replicas": 0 },
    "mappings": {
      "properties": {
        "ts":            { "type": "date" },
        "session_id":    { "type": "keyword" },
        "src_ip":        { "type": "ip" },
        "src_port":      { "type": "integer" },
        "dst_ip":        { "type": "ip" },
        "dst_port":      { "type": "integer" },
        "username":      { "type": "keyword" },
        "password":      { "type": "keyword" },
        "success":       { "type": "boolean" },

        "event_type":    { "type": "keyword" },
        "event_id_raw":  { "type": "keyword" },
        "eventid":       { "type": "keyword" },
        "sensor":        { "type": "keyword" },

        "command_class": { "type": "keyword" },
        "command_family":{ "type": "keyword" },

        "command": {
          "type": "text",
          "fields": { "keyword": { "type": "keyword", "ignore_above": 2048 } }
        }
      }
    }
  }' >/dev/null || true

TMP_BULK="$(mktemp)"
TMP_RESP="$(mktemp)"

# Build NDJSON bulk payload (validate non-empty + correct NDJSON pairs)
jq -c '
  select(.event_id_raw=="cowrie.command.input" or .event_id_raw=="cowrie.command.failed")

  | .command_class = (if .event_id_raw=="cowrie.command.failed" then "noise" else "interactive" end)

  | .command_family = (
      if (.command? | type) == "string" and (.command | length) > 0 then
        ( .command
          | capture("^(?<cmd>[A-Za-z0-9_./-]+)")?
          | (.cmd // "unknown")
          | ascii_downcase
        )
      else
        "unknown"
      end
    )

  | ._doc_id = (
      if (.eventid? | type) == "string" and (.eventid | length) > 0 then
        .eventid
      else
        (
          (
            (.event_id_raw // "noevent")
            + "|" + (.session_id // "nosess")
            + "|" + ((.ts // "nots")|tostring)
            + "|" + ((.command // "")|tostring)
          )
          | @base64
          | .[0:256]
        )
      end
    )

  | { index: { _index: "'"$IDX"'", _id: ._doc_id } },
    (del(._doc_id))
' "$SRC" > "$TMP_BULK"


LINES=$(wc -l < "$TMP_BULK" | tr -d ' ')
if [[ "$LINES" -eq 0 ]]; then
  echo "[ERROR] Bulk payload is EMPTY. jq produced no output."
  echo "        Check field names in $SRC (event_id_raw etc.)"
  rm -f "$TMP_BULK" "$TMP_RESP"
  exit 1
fi

if (( LINES % 2 != 0 )); then
  echo "[ERROR] Bulk payload line count is odd ($LINES). NDJSON is broken."
  echo "        First 5 lines:"
  head -n 5 "$TMP_BULK"
  rm -f "$TMP_BULK" "$TMP_RESP"
  exit 1
fi

echo "[INFO] Bulk payload lines: $LINES (docs: $((LINES/2)))"

HTTP_CODE=$(curl -sS -o "$TMP_RESP" -w "%{http_code}" \
  -H "Content-Type: application/x-ndjson" \
  -X POST "$OS/_bulk" \
  --data-binary @"$TMP_BULK"
)

echo "[INFO] Bulk HTTP code: $HTTP_CODE"
echo "[INFO] Bulk summary:"
cat "$TMP_RESP" | jq '{took, errors, items: (.items | length)}'

# Wenn errors=true: zeig die ersten 20 Fehler-Items
if cat "$TMP_RESP" | jq -e '.errors == true' >/dev/null; then
  echo "[ERROR] Bulk had errors. Showing first failing items:"
  cat "$TMP_RESP" | jq -c '.items[] | select((.index.status // 0) >= 400 or (.create.status // 0) >= 400 or (.update.status // 0) >= 400) | .[keys[0]]' | head -n 20
  rm -f "$TMP_BULK" "$TMP_RESP"
  exit 1
fi


if [[ "$HTTP_CODE" != "200" ]]; then
  echo "[ERROR] Bulk request failed (HTTP $HTTP_CODE)."
  rm -f "$TMP_BULK" "$TMP_RESP"
  exit 1
fi

# Refresh index
curl -sS -X POST "$OS/$IDX/_refresh" >/dev/null

echo "[INFO] Count total now:"
curl -sS "$OS/$IDX/_count" | jq .

echo "[INFO] Count interactive now:"
curl -sS "$OS/$IDX/_count" -H "Content-Type: application/json" \
  -d '{"query":{"term":{"command_class":"interactive"}}}' | jq .

echo "[INFO] Count noise now:"
curl -sS "$OS/$IDX/_count" -H "Content-Type: application/json" \
  -d '{"query":{"term":{"command_class":"noise"}}}' | jq .

rm -f "$TMP_BULK" "$TMP_RESP"
