#!/bin/bash
# Auto Deep Mode: Triggered when core loop stalls

set -euo pipefail

VULNS_FILE="${1:-vulns.txt}"
TARGETS_FILE="${2:-targets.yaml}"
OUTPUT_DIR="recon-$(date +%Y%m%d-%H%M)/deep-$(date +%H%M)"
mkdir -p "$OUTPUT_DIR"

echo "[*] Auto Deep Mode triggered"

# Count failed vectors
ATTEMPTS=$(grep -c "attempt" "$VULNS_FILE" 2>/dev/null || echo 3)
if [[ $ATTEMPTS -lt 3 ]]; then
    echo "[!] Not enough attempts for Deep Mode (need 3, have $ATTEMPTS)"
    exit 0
fi

echo "[*] Running 3-Scenario Simulation..."

# Scenario 1: Best Case
cat > "$OUTPUT_DIR/scenario-best.yaml" << 'EOF'
scenario: best
assumptions:
  - All Calculus thresholds met
  - Tools run without rate limits
  - Target has high-value vulns
  - Clean exit path exists
path:
  - Focus: High-value params only
  - Tools: Nuclei + Dalfox + SQLMap (targeted)
  - Time: 15 min
proof: Verified POC + tx hash
overextension_risk: Chase low-value findings
EOF

# Scenario 2: Worst Credible
cat > "$OUTPUT_DIR/scenario-worst.yaml" << 'EOF'
scenario: worst_credible
assumptions:
  - Critical assumption fails (e.g., WAF blocks all)
  - Multiple complications converge
  - Gas spikes / rate limits hit
  - Clean exit compromised
max_damage: Full time invested, no findings
earliest_warning: 0 findings after 2 phases
protect_first: Time investment, reputation
abort_threshold: 0 verified findings after 30 min
EOF

# Scenario 3: Adversarial
cat > "$OUTPUT_DIR/scenario-adversarial.yaml" << 'EOF'
scenario: adversarial
assumptions:
  - Target detects pattern
  - WAF rules deployed mid-scan
  - Honeytokens triggered
  - Legal threat received
counter_move: Target monitors automated scans
predictable_parts: Standard Nuclei templates, common wordlists
plan_b_independent: Manual review + custom payloads
EOF

# Pre-commit decisions
cat > "$OUTPUT_DIR/deep-plan.yaml" << EOF
trigger: Auto Deep Mode
owner: SUPERAGENT
evidence: $(wc -l < "$VULNS_FILE") findings after $ATTEMPTS attempts
max_loss: 30 min
fallback: Trojan Mode
abort_if: Gas > 2x normal OR 0 verified after 3 phases
verification: Independent POC + explorer tx hash
EOF

echo "[*] Deep Mode complete → $OUTPUT_DIR/deep-plan.yaml"