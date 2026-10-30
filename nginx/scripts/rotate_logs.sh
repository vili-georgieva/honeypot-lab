#!/bin/bash

# Pfade und Namen
LOG_DIR="/home/honeypot/nginx-docker/logs"
ARCHIVE_DIR="$LOG_DIR/archive"
CONTAINER_NAME="nginx-honeypot"
YESTERDAY=$(date -d "yesterday" +"%Y-%m-%d")

echo "--- Starte Log-Rotation für $YESTERDAY ---"

# Prüfen, ob das Log existiert und nicht leer ist
if [ -s "$LOG_DIR/honeypot.log" ]; then
    # 1. Log in den Archiv-Ordner verschieben und Datum anhängen
    mv "$LOG_DIR/honeypot.log" "$ARCHIVE_DIR/honeypot_$YESTERDAY.log"

    # 2. NGINX im Docker-Container zwingen, sofort eine neue Log-Datei zu erstellen
    /usr/bin/docker exec $CONTAINER_NAME nginx -s reopen

    # 3. Das verschobene Log komprimieren (spart ca. 90% Speicherplatz)
    gzip "$ARCHIVE_DIR/honeypot_$YESTERDAY.log"
    
    echo "Erfolg: honeypot_$YESTERDAY.log.gz wurde erstellt."
else
    echo "Abbruch: honeypot.log ist leer oder existiert nicht."
fi
