#!/bin/bash
# Phase 5: On-Chain / DeFi Analysis

set -euo pipefail

TARGETS_YAML="${1:-targets.yaml}"
OUTPUT_DIR="$(dirname "$TARGETS_YAML")/phase5-$(date +%Y%m%d-%H%M)"
mkdir -p "$OUTPUT_DIR"

# Load RPC URLs
ETH_RPC="${ETH_RPC_URL:-https://eth.llamarpc.com}"
ARB_RPC="${ARB_RPC_URL:-https://arb1.arbitrum.io/rpc}"
BSC_RPC="${BSC_RPC_URL:-https://bsc-dataseed.binance.org}"

echo "[*] Phase 5: On-Chain Analysis"

# Parse targets.yaml for contracts
if [[ -f "$TARGETS_YAML" ]]; then
    # Extract contracts (simplified - use yq in production)
    grep -A 5 "contracts:" "$TARGETS_YAML" | grep "0x" | sed 's/.*0x/0x/' | sed 's/[" ,]//g' > "$OUTPUT_DIR/contracts.txt" || true
    
    while IFS= read -r contract; do
        [[ -z "$contract" ]] && continue
        echo "[*] Analyzing $contract..."
        
        # Bytecode
        cast code "$contract" --rpc-url "$ETH_RPC" > "$OUTPUT_DIR/${contract}-bytecode.txt" 2>/dev/null || true
        
        # Storage slots (first 50)
        for i in {0..49}; do
            cast storage "$contract" "$i" --rpc-url "$ETH_RPC" >> "$OUTPUT_DIR/${contract}-storage.txt" 2>/dev/null || true
        done
        
        # Function selectors
        cast 4byte-decode "$(cast sig 'transfer(address,uint256)')" 2>/dev/null || true
        
        # Simulate common calls
        cast call "$contract" "totalSupply()(uint256)" --rpc-url "$ETH_RPC" >> "$OUTPUT_DIR/${contract}-calls.txt" 2>/dev/null || true
        cast call "$contract" "balanceOf(address)(uint256)" "0x0000000000000000000000000000000000000000" --rpc-url "$ETH_RPC" >> "$OUTPUT_DIR/${contract}-calls.txt" 2>/dev/null || true
        
    done < "$OUTPUT_DIR/contracts.txt"
fi

# Also check for proxy patterns
echo "[*] Checking proxy patterns..."
grep -r "delegatecall\|implementation\|admin" "$OUTPUT_DIR" 2>/dev/null | anew "$OUTPUT_DIR/proxy-candidates.txt" || true

echo "[*] Phase 5 complete → $OUTPUT_DIR/"