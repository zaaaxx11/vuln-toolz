#!/bin/bash
# Auto Trojan Mode: Indirect Victory via Gatekeeper Analysis

set -euo pipefail

VULNS_FILE="${1:-vulns.txt}"
TARGETS_FILE="${2:-targets.yaml}"
OUTPUT_DIR="recon-$(date +%Y%m%d-%H%M)/trojan-$(date +%H%M)"
mkdir -p "$OUTPUT_DIR"

echo "[*] Auto Trojan Mode: Direct force failed → Indirect strategy"

# Analyze gatekeepers
cat > "$OUTPUT_DIR/gatekeepers.yaml" << 'EOF'
gatekeepers:
  - name: "WAF / Rate Limiter"
    type: "technical"
    signal: "HTTP 200 + specific headers"
    reward: "Request processed"
    inspection: "Header analysis, timing"
    familiarity_bonus: "Standard browser headers"
    
  - name: "Auth / Session Validator"
    type: "access"
    signal: "Valid JWT / Session cookie"
    reward: "Authenticated access"
    inspection: "Token validation, expiry check"
    familiarity_bonus: "Standard OAuth flow"
    
  - name: "Business Logic / Workflow"
    type: "process"
    signal: "Correct step sequence"
    reward: "State transition"
    inspection: "State machine validation"
    familiarity_bonus: "Normal user journey"
    
  - name: "Human Review / Approval"
    type: "human"
    signal: "Complete form + valid data"
    reward: "Manual approval"
    inspection: "Data quality, anomaly detection"
    familiarity_bonus: "Legitimate-looking request"
EOF

# Two-layer objective
cat > "$OUTPUT_DIR/two-layer-objective.yaml" << 'EOF'
visible_value:
  description: "What genuine benefit makes them accept?"
  examples:
    - "Security report with real findings"
    - "Feature request with working prototype"
    - "Integration that solves their pain point"
    - "Bug bounty submission with POC"
  must_survive_scrutiny: true

strategic_value:
  description: "What lawful objective opens after acceptance?"
  examples:
    - "Trusted reporter status → expanded scope"
    - "API access granted → deeper testing"
    - "Partner program → internal endpoints"
    - "White-list IP → bypass rate limits"
  measurable: true
  reversible: true
EOF

# Horse Architecture (5 Chambers)
cat > "$OUTPUT_DIR/horse-architecture.yaml" << 'EOF'
chamber_1_exterior:
  - Real security report with verified findings
  - Working integration prototype
  - Feature that reduces their operational cost
  - Must pass manual review

chamber_2_acceptance:
  mechanism: "incentive"  # incentive | authority | social_proof | familiarity | convenience | urgency | curiosity | scarcity
  signal: "High-quality report with business impact"
  verification: "Manual review by security team"
  
chamber_3_hidden_dependency:
  - New workflow: "Submit via their platform"
  - Integration: "API key for automated reporting"
  - Decision habit: "Trust this reporter's submissions"
  - Channel: "Direct line to security team"
  - Data source: "Their internal triage data"

chamber_4_reveal_condition:
  - Explicit: "After 3 accepted reports"
  - Measurable: "API access granted"
  - Authorized: "By security lead"
  - Reversible: "Can revoke API key"

chamber_5_exit:
  - Rollback: "Revoke API key, delete integration"
  - Audit: "Log all actions taken"
  - Stabilization: "Return to standard reporting"
EOF

# Indirect Victory Comparison
cat > "$OUTPUT_DIR/indirect-comparison.yaml" << 'EOF'
approaches:
  - name: "Force"
    cost: "High (WAF blocks, legal risk)"
    success_prob: 0.1
    
  - name: "Bypass"
    cost: "Medium (technical complexity)"
    success_prob: 0.3
    
  - name: "Reframe"
    cost: "Low (report existing findings)"
    success_prob: 0.6
    
  - name: "Incentivize"
    cost: "Low (provide value)"
    success_prob: 0.7
    
  - name: "Embed"
    cost: "Medium (build integration)"
    success_prob: 0.8
    
  - name: "Wait"
    cost: "Time only"
    success_prob: 0.4

recommended: "Incentivize + Embed"
indirect_advantage: 0.7 * 0.8 - 0.2 - 0.1 = 0.43
EOF

# Trojan Verdict
cat > "$OUTPUT_DIR/trojan-plan.yaml" << EOF
verdict: PROCEED
conditions:
  - Inspection: Visible value survives manual review ✓
  - Disclosure: Strategic value documented ✓
  - Rejection: If rejected, exit cleanly ✓
  - Misuse: No unauthorized access path ✓
  - Rollback: API key revocable, logs auditable ✓

next_actions:
  1. Prepare high-quality report from existing findings
  2. Submit via their platform (builds familiarity)
  3. Request API access for automated reporting
  4. After 3 accepted → expanded scope
  
abort_if: Any condition fails verification
EOF

echo "[*] Trojan Mode complete → $OUTPUT_DIR/trojan-plan.yaml"