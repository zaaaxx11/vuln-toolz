#!/bin/bash
# Phase 3: JS Collection + Secret Extraction

set -euo pipefail

LIVE_FILE="${1:-live.txt}"
OUTPUT_DIR="recon-$(date +%Y%m%d-%H%M)"
mkdir -p "$OUTPUT_DIR"

echo "[*] Phase 3: JS Hunting → $OUTPUT_DIR"

# Extract JS URLs from live URLs
cat "$LIVE_FILE" | grep "\.js$" | httpx -mc 200 -silent 2>/dev/null > "$OUTPUT_DIR/js-urls.txt"

# Download JS files
mkdir -p "$OUTPUT_DIR/js"
while IFS= read -r js_url; do
    [[ -z "$js_url" ]] && continue
    wget -q -P "$OUTPUT_DIR/js" -nd -r -l1 -A.js "$js_url" 2>/dev/null || true
done < "$OUTPUT_DIR/js-urls.txt"

# Find all downloaded JS
find "$OUTPUT_DIR/js" -name "*.js" 2>/dev/null > "$OUTPUT_DIR/all-js.txt"

# Secret extraction
jscracker -f "$OUTPUT_DIR/all-js.txt" -o "$OUTPUT_DIR/js-secrets.txt" 2>/dev/null || true

# Pattern-based extraction
grep -rE "(api[_-]?key|secret|token|password|aws[_-]?key|slack|discord|stripe|sendgrid|twilio|jwt|bearer|access[_-]?key|client[_-]?secret)" "$OUTPUT_DIR/js" 2>/dev/null | anew "$OUTPUT_DIR/js-secrets.txt"

# Endpoint extraction from JS
grep -rEo "(https?://|/api/|/v[0-9]/)[^\"'<> ]+" "$OUTPUT_DIR/js" 2>/dev/null | sort -u > "$OUTPUT_DIR/js-endpoints.txt"
grep -rEo "\"(/(api|v[0-9])/[^\"']+)\"" "$OUTPUT_DIR/js" 2>/dev/null | sed 's/"//g' | sort -u >> "$OUTPUT_DIR/js-endpoints.txt"

# Nuclei on JS
nuclei -l "$OUTPUT_DIR/js-urls.txt" -t exposures/ -t fuzzing/ -silent -o "$OUTPUT_DIR/nuclei-js.txt" 2>/dev/null || true

echo "[*] JS files: $(wc -l < "$OUTPUT_DIR/all-js.txt" 2>/dev/null || echo 0)"
echo "[*] Secrets: $(wc -l < "$OUTPUT_DIR/js-secrets.txt" 2>/dev/null || echo 0)"
echo "[*] Endpoints: $(wc -l < "$OUTPUT_DIR/js-endpoints.txt" 2>/dev/null || echo 0)"