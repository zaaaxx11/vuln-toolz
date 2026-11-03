#!/bin/bash
# Phase 5: Infrastructure Recon

set -euo pipefail

LIVE_FILE="${1:-live.txt}"
OUTPUT_DIR="recon-$(date +%Y%m%d-%H%M)"
mkdir -p "$OUTPUT_DIR"

echo "[*] Phase 5: Infra Recon → $OUTPUT_DIR"

# Resolve IPs
cat "$LIVE_FILE" | httpx -silent -mc 200,301,302,403,401 -title -tech-detect -ip -o "$OUTPUT_DIR/live-with-ip.txt" 2>/dev/null
cut -d' ' -f2 "$OUTPUT_DIR/live-with-ip.txt" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u > "$OUTPUT_DIR/ips.txt"

# Port scan
naabu -rate 10000 -l "$OUTPUT_DIR/ips.txt" -top-ports 1000 -silent -o "$OUTPUT_DIR/ports.txt" 2>/dev/null || true

# Cloud metadata
for ip in $(cat "$OUTPUT_DIR/ips.txt"); do
    for ep in "http://169.254.169.254/latest/meta-data/" "http://metadata.google.internal/computeMetadata/v1/"; do
        curl -s -m 2 -H "Metadata-Flavor: Google" "$ep" 2>/dev/null && echo "$ip: $ep" >> "$OUTPUT_DIR/cloud-metadata.txt" || true
    done
done

# K8s/Docker ports
for port in 10250 10255 2375 2376 6443 8443; do
    for ip in $(cat "$OUTPUT_DIR/ips.txt"); do
        timeout 2 bash -c "cat < /dev/null > /dev/tcp/$ip/$port" 2>/dev/null && echo "$ip:$port (k8s/docker)" >> "$OUTPUT_DIR/container-ports.txt" || true
    done
done

# SSL check
cat "$OUTPUT_DIR/live-with-ip.txt" | cut -d' ' -f1 | while read url; do
    echo | openssl s_client -connect "$(echo $url | sed 's|https://||' | cut -d'/' -f1)":443 -servername "$(echo $url | sed 's|https://||' | cut -d'/' -f1)" 2>/dev/null | openssl x509 -noout -dates 2>/dev/null >> "$OUTPUT_DIR/ssl.txt" || true
done

# VHOSTs
ffuf -u "https://FUZZ.$(cat $LIVE_FILE | head -1 | sed 's|https://||' | cut -d'/' -f1)" -w ~/wordlists/vhosts.txt -mc 200,301,302,403,401 -silent -o "$OUTPUT_DIR/vhosts.json" 2>/dev/null || true

echo "[*] IPs: $(wc -l < "$OUTPUT_DIR/ips.txt" 2>/dev/null || echo 0)"
echo "[*] Open ports: $(wc -l < "$OUTPUT_DIR/ports.txt" 2>/dev/null || echo 0)"
echo "[*] Cloud metadata hits: $(wc -l < "$OUTPUT_DIR/cloud-metadata.txt" 2>/dev/null || echo 0)"