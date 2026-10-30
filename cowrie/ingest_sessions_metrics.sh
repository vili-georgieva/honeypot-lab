#!/usr/bin/env bash
set -euo pipefail

DAY="${1:?Usage: $0 YYYY-MM-DD}"

OS="http://127.0.0.1:9200"
DERIVED_DIR="${HOME}/cowrie-work/derived"
INPUT="${DERIVED_DIR}/cowrie_sessions_metrics_${DAY}.jsonl"
INDEX="cowrie-sessions-${DAY//-/\.}"

[[ -s "$INPUT" ]] || { echo "[INFO] No sessions metrics file: $INPUT"; exit 0; }

echo "[INFO] Ingest sessions metrics: $INPUT -> $OS/$INDEX"

# Create index if not exists (ignore error if exists)
curl -s -o /dev/null -w "%{http_code}\n" -XPUT "$OS/$INDEX" -H 'Content-Type: application/json' -d '{
  "settings": { "number_of_shards": 1, "number_of_replicas": 0 },
  "mappings": {
    "properties": {
      "session_id": { "type": "keyword" },
      "src_ip": { "type": "ip" },
      "start_ts": { "type": "date" },
      "end_ts": { "type": "date" },
      "duration_sec": { "type": "integer" },
      "auth_fail_count": { "type": "integer" },
      "auth_success_count": { "type": "integer" },
      "command_count": { "type": "integer" },
      "file_transfer_count": { "type": "integer" },
      "tunnel_attempt_count": { "type": "integer" },
      "session_class": { "type": "keyword" },
      "event_types": { "type": "keyword" }
    }
  }
}' >/dev/null || true

# Bulk
jq -c '{ index: { _index: "'"$INDEX"'", _id: .session_id } }, .' "$INPUT" \
| curl -s -H "Content-Type: application/x-ndjson" -XPOST "$OS/_bulk" --data-binary @- \
| jq '{errors, took}'

echo "[INFO] Count now:"
curl -s "$OS/$INDEX/_count" | jq .
