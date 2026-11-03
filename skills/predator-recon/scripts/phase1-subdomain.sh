#!/bin/bash
# Phase 1: Subdomain Enumeration (Passive → Active → Resolve → Live)
# Usage: ./phase1-subdomain.sh targets.yaml

set -euo pipefail

TARGETS_FILE="${1:-targets.yaml}"
OUTPUT_DIR="recon-$(date +%Y%m%d-%H%M)"
mkdir -p "$OUTPUT_DIR"

echo "[*] Phase 1: Subdomain Enum → $OUTPUT_DIR"

# Parse targets.yaml (simplified - assumes YAML with domain: entries)
# For now, read domains from file (one per line or YAML)
if [[ "$TARGETS_FILE" == *.yaml ]]; then
    # Extract domains from YAML
    grep -E "^\s*-?\s*domain:" "$TARGETS_FILE" | sed 's/.*domain:\s*//' | sed 's/["'"'"']//g' > "$OUTPUT_DIR/domains.txt"
else
    cp "$TARGETS_FILE" "$OUTPUT_DIR/domains.txt"
fi

while IFS= read -r domain; do
    [[ -z "$domain" ]] && continue
    echo "[+] Enumerating: $domain"
    
    # Passive enumeration
    subfinder -d "$domain" -all -silent | anew "$OUTPUT_DIR/subs-passive.txt"
    assetfinder --subs-only "$domain" | anew "$OUTPUT_DIR/subs-passive.txt"
    amass enum -passive -d "$domain" -norecursive -noalts -o "$OUTPUT_DIR/amass.txt" 2>/dev/null
    cat "$OUTPUT_DIR/amass.txt" 2>/dev/null | anew "$OUTPUT_DIR/subs-passive.txt"
    
    # CRT.sh
    curl -s "https://crt.sh/?q=%.${domain}&output=json" | jq -r '.[].name_value' 2>/dev/null | anew "$OUTPUT_DIR/subs-passive.txt"
    
    # GitHub subdomains (if token available)
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        github-subdomains -t "$GITHUB_TOKEN" -d "$domain" | anew "$OUTPUT_DIR/subs-passive.txt"
    fi
    
    # Active bruteforce (optional - controlled by calculus)
    if [[ "${RUN_ACTIVE:-false}" == "true" ]]; then
        puredns bruteforce ~/wordlists/best-dns-wordlist.txt "$domain" -r ~/resolvers.txt 2>/dev/null | anew "$OUTPUT_DIR/subs-active.txt"
    fi
    
    # Merge all
    cat "$OUTPUT_DIR/subs-passive.txt" "$OUTPUT_DIR/subs-active.txt" 2>/dev/null | sort -u > "$OUTPUT_DIR/subs-all.txt"
    
    # Resolve
    puredns resolve "$OUTPUT_DIR/subs-all.txt" -r ~/resolvers.txt -w "$OUTPUT_DIR/subs-resolved.txt" 2>/dev/null
    
    # HTTP probe
    httpx -l "$OUTPUT_DIR/subs-resolved.txt" -silent -mc 200,301,302,403,401 -title -tech-detect -status-code -o "$OUTPUT_DIR/live.txt"
    
    echo "[+] $domain: $(wc -l < "$OUTPUT_DIR/live.txt") live subdomains"
done < "$OUTPUT_DIR/domains.txt"

echo "[*] Phase 1 complete → $OUTPUT_DIR/live.txt"