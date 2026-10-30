#!/bin/bash

# Variablen aus der .env-Datei laden
source /home/honeypot/nginx-docker/honeypot-nginx.env

ARCHIVE_DIR="/home/honeypot/nginx-docker/logs/archive"
UPLOADED_DIR="$ARCHIVE_DIR/uploaded"

echo "--- Starte Azure Blob Upload ---"

# Suche alle komprimierten (.gz) Dateien direkt im Archiv-Ordner
for filepath in $ARCHIVE_DIR/*.gz; do
    # Falls der Ordner leer ist, brich ab
    [ -e "$filepath" ] || continue

    filename=$(basename "$filepath")
    
    # Datum aus dem Dateinamen extrahieren
    FILE_DATE=$(echo "$filename" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}')
    
    if [ -n "$FILE_DATE" ]; then
        YEAR=$(echo "$FILE_DATE" | cut -d'-' -f1)
        MONTH=$(echo "$FILE_DATE" | cut -d'-' -f2)
        DAY=$(echo "$FILE_DATE" | cut -d'-' -f3)
    else
        YEAR=$(date +"%Y"); MONTH=$(date +"%m"); DAY=$(date +"%d")
    fi
    
    # Der exakte Pfad in Azure
    BLOB_NAME="raw/nginx/${SENSOR_ID}/${YEAR}/${MONTH}/${DAY}/${filename}"
    UPLOAD_URL="https://${AZURE_ACCOUNT_NAME}.blob.core.windows.net/${AZURE_CONTAINER_NAME}/${BLOB_NAME}${AZURE_SAS_TOKEN}"

    echo "Lade hoch: $filename ..."

    # Upload durchführen
    HTTP_STATUS=$(curl -s -w "%{http_code}" -o /dev/null -X PUT -T "$filepath" -H "x-ms-blob-type: BlockBlob" "$UPLOAD_URL")

    if [ "$HTTP_STATUS" == "201" ]; then
        echo "Erfolg! Datei ist in Azure. Verschiebe in lokalen Langzeit-Speicher..."
        mv "$filepath" "$UPLOADED_DIR/"
    else
        echo "FEHLER beim Upload von $filename! HTTP Status Code: $HTTP_STATUS"
    fi
done
