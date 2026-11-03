#!/bin/bash
# Phase 2: URL & Parameter Harvest + JS Extraction

set -euo pipefail

LIVE_FILE="${1:-live.txt}"
OUTPUT_DIR="recon-$(date +%Y%m%d-%H%M)"
mkdir -p "$OUTPUT_DIR"

echo "[*] Phase 2: URL/Param Harvest → $OUTPUT_DIR"

cat "$LIVE_FILE" | while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    domain=$(echo "$url" | sed -E 's|https?://||' | cut -d'/' -f1)
    
    echo "[+] Harvesting: $domain"
    
    # Wayback + gau + katana
    waymore -i "$domain" -mode U -oU "$OUTPUT_DIR/urls-$domain.txt" 2>/dev/null || true
    gau "$domain" 2>/dev/null | anew "$OUTPUT_DIR/urls-$domain.txt" || true
    katana -u "$url" -jc -kf all -silent 2>/dev/null | anew "$OUTPUT_DIR/urls-$domain.txt" || true
done

# Merge & dedup
cat "$OUTPUT_DIR"/urls-*.txt 2>/dev/null | uro | anew "$OUTPUT_DIR/urls-all.txt"
cat "$OUTPUT_DIR/urls-all.txt" | httpx -silent -mc 200 -o "$OUTPUT_DIR/live-urls.txt" 2>/dev/null

# Extract params
cat "$OUTPUT_DIR/live-urls.txt" | grep "=" | qsreplace "FUZZ" | anew "$OUTPUT_DIR/params.txt"

# Extract JS files
cat "$OUTPUT_DIR/urls-all.txt" | grep "\.js$" | httpx -mc 200 -silent 2>/dev/null | anew "$OUTPUT_DIR/js-files.txt"

echo "[*] URLs: $(wc -l < "$OUTPUT_DIR/urls-all.txt" 2>/dev/null || echo 0)"
echo "[*] Live URLs: $(wc -l < "$OUTPUT_DIR/live-urls.txt" 2>/dev/null || echo 0)"
echo "[*] Params: $(wc -l < "$OUTPUT_DIR/params.txt" 2>/dev/null || echo 0)"
echo "[*] JS files: $(wc -l < "$OUTPUT_DIR/js-files.txt" 2>/dev/null || echo 0)"