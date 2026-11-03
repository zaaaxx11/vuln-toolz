# WORDLISTS — Sources + Priorities

## Tier 1: Best (Use First)

### Assetnote (Industry Standard)
```
https://wordlists.assetnote.io/
```
- `best-dns-wordlist.txt` — 5M+ subdomains
- `subdomains-top1mil.txt` — 1M common
- `directories-top1mil.txt` — paths
- `parameters-top1mil.txt` — param names
- Updated weekly

### SecLists (danielmiessler)
```
https://github.com/danielmiessler/SecLists
```
- `Discovery/DNS/` — subdomain lists
- `Discovery/Web-Content/` — directories, files
- `Fuzzing/` — params, payloads
- `Payloads/` — XSS, SQLi, etc.

---

## Tier 2: Specialized

### Subdomain Brute
```
~/wordlists/best-dns-wordlist.txt          # Assetnote (PRIMARY)
~/wordlists/subdomains-top1mil.txt         # Assetnote
~/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
~/wordlists/SecLists/Discovery/DNS/deepmagic.com-prefixes-top50000.txt
```

### Directory/File
```
~/wordlists/directories-top1mil.txt        # Assetnote
~/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt
~/wordlists/SecLists/Discovery/Web-Content/raft-large-files.txt
~/wordlists/SecLists/Discovery/Web-Content/common.txt
```

### Parameters
```
~/wordlists/parameters-top1mil.txt         # Assetnote
~/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt
~/wordlists/SecLists/Fuzzing/params.txt
```

### VHOST
```
~/wordlists/vhosts.txt                     # Custom: common + cloud
# cloud: s3.amazonaws.com, cloudfront.net, azurewebsites.net, etc.
```

---

## Tier 3: Generators

### Permutation (puredns)
```bash
# Generate from known subs
puredns generate ~/wordlists/permutations.txt target.com | puredns resolve -r ~/resolvers.txt
```

### AlterX
```bash
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
alterx -l live.txt -o permuted.txt
```

---

## Resolvers (Critical for puredns)
```
~/resolvers.txt  # 50+ trusted resolvers
# Source: https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt
# Test: puredns resolve -r ~/resolvers.txt test.txt
```

---

## Priority Order (Calculus-Driven)

| Phase | Wordlist | Why |
|-------|----------|-----|
| 1 Passive | Assetnote best-dns | Highest signal, lowest noise |
| 1 Active | SecLists 5000 | Fast, good coverage |
| 2 Dirs | Assetnote directories | Modern paths |
| 2 Files | Assetnote files + raft | Extensions matter |
| 3 Params | Assetnote params | Real param names |
| 4 Fuzzing | SecLists Fuzzing | Payload-specific |

---

## Download Script
```bash
#!/bin/bash
mkdir -p ~/wordlists ~/resolvers

# Assetnote (best)
wget -q https://wordlists.assetnote.io/data/manual/best-dns-wordlist.txt -O ~/wordlists/best-dns-wordlist.txt
wget -q https://wordlists.assetnote.io/data/manual/subdomains-top1mil.txt -O ~/wordlists/subdomains-top1mil.txt
wget -q https://wordlists.assetnote.io/data/manual/directories-top1mil.txt -O ~/wordlists/directories-top1mil.txt
wget -q https://wordlists.assetnote.io/data/manual/parameters-top1mil.txt -O ~/wordlists/parameters-top1mil.txt

# Resolvers
wget -q https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -O ~/resolvers.txt

# SecLists (clone once)
git clone --depth 1 https://github.com/danielmiessler/SecLists.git ~/wordlists/SecLists 2>/dev/null || cd ~/wordlists/SecLists && git pull

echo "Done. Verify:"
wc -l ~/wordlists/*.txt ~/resolvers.txt
```