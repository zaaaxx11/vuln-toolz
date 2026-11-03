#!/bin/bash
# Install all 25+ tools for Predator Recon

set -euo pipefail

echo "[*] Installing Predator Recon tools..."

# Go tools
echo "[*] Go tools..."
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
go install github.com/tomnomnom/ffuf@latest
go install github.com/projectdiscovery/pdtm/go/cmd/pdtm@latest

# Python tools
echo "[*] Python tools..."
pip install waymore
pip install sqlmap
pip install uro
pip install paramspider
pip install arjun
pip install tplmap

# Wordlists
echo "[*] Wordlists..."
mkdir -p ~/wordlists ~/resolvers
if [[ ! -f ~/wordlists/best-dns-wordlist.txt ]]; then
    curl -s https://wordlists.assetnote.io/data/manual/best-dns-wordlist.txt -o ~/wordlists/best-dns-wordlist.txt
fi
if [[ ! -f ~/wordlists/vhosts.txt ]]; then
    curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt -o ~/wordlists/vhosts.txt
fi
if [[ ! -f ~/resolvers.txt ]]; then
    curl -s https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -o ~/resolvers.txt
fi

# Nuclei templates
echo "[*] Nuclei templates..."
nuclei -update-templates

echo "[*] Install complete!"
echo "    Verify: subfinder -version && httpx -version && nuclei -version"