# Cowrie Normalized Event Schema v1

Required
- ts (string, ISO-8601 UTC)
- sensor (string) = "cowrie"
- event_type (string enum) e.g. auth_fail, auth_success, session_start, session_end, command, file_upload, file_download, other
- event_id_raw (string) original cowrie eventid
- session_id (string|null)
- src_ip (string|null)
- src_port (int|null)
- dst_ip (string|null)
- dst_port (int|null)

Optional (by event_type)
- username (string|null)
- password (string|null)  (later: truncate/hash)
- success (bool|null)
- command (string|null)

File-related
- file_name (string|null)
- file_path (string|null)
- file_size (int|null)
- file_sha256 (string|null)

Enrichment (later)
- geo_country, geo_city, asn, asn_org (nullable)
- tags (array<string>)