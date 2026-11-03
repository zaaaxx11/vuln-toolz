# RECON CHEATSHEET — One Page

## PHASE COMMANDS
```bash
# Phase 1: Subdomain Enum
./scripts/phase1-subdomain.sh targets.yaml
# → live.txt

# Phase 2: URLs + Params
./scripts/phase2-urls.sh recon-*/live.txt
# → live-urls.txt, params.txt, js-files.txt

# Phase 3: JS Hunting
./scripts/phase3-js.sh recon-*/live.txt
# → js-secrets.txt, js-endpoints.txt

# Phase 4: Vuln Scan
./scripts/phase4-vuln.sh recon-*/params.txt recon-*/live-urls.txt recon-*/js-files.txt
# → vulns.txt

# Phase 5: Infra
./scripts/phase5-infra.sh recon-*/live.txt
# → infra.txt

# Phase 6: On-Chain
./scripts/phase6-onchain.sh targets.yaml
# → onchain.txt

# Auto Deep/Trojan
./scripts/auto-deep.sh vulns.txt
./scripts/auto-trojan.sh vulns.txt targets.yaml
```

## QUICK ONE-LINERS

### Subdomain Enum
```bash
# Passive
subfinder -d target.com -all -o subs.txt
assetfinder --subs-only target.com | anew subs.txt
amass enum -passive -d target.com -o amass.txt

# Resolve + Live
cat subs.txt | puredns resolve -r ~/resolvers.txt -w resolved.txt
cat resolved.txt | httpx -silent -mc 200,301,302,403,401 -title -tech-detect -o live.txt
```

### URL Harvest
```bash
waymore -i target.com -mode U -oU urls.txt
gau target.com --subs | anew urls.txt
katana -u https://target.com -jc -kf all -silent | anew urls.txt
cat urls.txt | uro | anew urls-dedup.txt
cat urls-dedup.txt | httpx -silent -mc 200 -o live-urls.txt
cat live-urls.txt | grep "=" | anew params.txt
```

### JS Secrets
```bash
cat js-files.txt | jscracker -o secrets.txt
grep -rE "(api[_-]?key|secret|token|password)" js/ | anew secrets.txt
```

### Vuln Scan
```bash
# XSS
cat params.txt | Gxss -c 100 -p XssReflected | dalfox pipe -b https://xss.bug -w 100
cat params.txt | dalfox pipe -b https://xss.bug -blind -w 50

# SQLi
sqlmap -m params.txt --batch --random-agent --level 1 --tamper=space2comment --dbs

# Nuclei
nuclei -l live-urls.txt -t vulnerabilities/ -t cves/ -t exposures/ -t misconfiguration/ -t fuzzing-templates/ -t ssl/ -t dns/ -t takeovers/ -severity critical,high,medium -rate-limit 100 -silent

# CORS
cat live-urls.txt | CORS-Scanner

# Takeover
nuclei -l live.txt -t takeovers/ -silent
subzy run --targets live.txt
```

### Infra
```bash
naabu -rate 10000 -l live.txt -top-ports 1000 -silent -o ports.txt
for ip in $(cat live-ips.txt); do
  curl -s -m 2 -H "Metadata-Flavor: Google" http://169.254.169.254/latest/meta-data/ && echo "$ip: AWS"
  curl -s -m 2 http://metadata.google.internal/computeMetadata/v1/ -H "Metadata-Flavor: Google" && echo "$ip: GCP"
done
```

### On-Chain
```bash
cast code $CONTRACT --rpc-url $RPC
for i in {0..49}; do cast storage $CONTRACT $i --rpc-url $RPC; done
cast call $CONTRACT "totalSupply()(uint256)" --rpc-url $RPC
cast call $CONTRACT "balanceOf(address)(uint256)" 0x000... --rpc-url $RPC
```

## CALCULUS CHECK (Before EVERY tool)
```
Value > Cost + Risk + Irreversibility?
Value: $bounty × confidence
Cost: minutes
Risk: 1-10 detection prob
Irrev: 1-10 cleanup difficulty
```

## BLIND SPOT CHECK (After EVERY phase)
```bash
# What did I miss?
comm -23 <(cat all-possible.txt | sort) <(cat checked.txt | sort)

# What would devs hide?
grep -r "internal\|admin\|debug\|test\|staging" checked.txt

# If wrong, where?
echo "Failed assumption: " >> assumptions.log
```

## TRIGGER WORDS → AUTO-ACTIVATE
```
recon, subdomain, bug bounty, hunt, target, scope,
exploit, steal, drain, attack, compromise, pwn, hack,
vuln, weakness, flaw, bug, 0day, poc, payload,
xss, sqli, ssrf, ssti, idor, cors, redirect, takeover,
bypass, waf bypass, auth bypass, priv esc,
calculus, deep mode, trojan mode, gatekeeper,
onchain, smart contract, defi exploit, bridge exploit,
flashloan, reentrancy, oracle manipulation, governance attack
```

## OUTPUT FORMAT
```
[OUTPUT]
→ deliverable file

[NEXT STEP]
→ immediate action

[🔧 UPGRADE]
→ one meaningful improvement
```