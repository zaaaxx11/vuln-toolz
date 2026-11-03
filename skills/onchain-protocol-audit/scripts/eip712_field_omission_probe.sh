#!/usr/bin/env bash
# EIP-712 field-omission probe + deployment gate.
#
# Finds signing structs that accept a parameter but never put it in the digest — the
# "authorization binds less than the effect uses" bug family (see references/
# evm-foundry-and-offchain-api-audit.md §15). Then checks whether the contract is even
# deployed, because a proven bug in an undeployed contract is not a bounty finding.
#
# Usage:
#   ./eip712_field_omission_probe.sh <repo-root>            # scan source
#   ./eip712_field_omission_probe.sh <repo-root> <ADDR> <RPC>  # scan + deployment gate
#
# Read-only. Emits candidates for human review; it does NOT prove exploitability.

set -uo pipefail
ROOT="${1:?usage: $0 <repo-root> [contract-address] [rpc-url]}"
ADDR="${2:-}"
RPC="${3:-}"

echo "=============================================================="
echo " 1. EIP-712 TYPEHASH declarations (what the signature CLAIMS to bind)"
echo "=============================================================="
grep -rn --include='*.sol' -E 'TYPEHASH\s*=' -A1 "$ROOT" \
  | grep -E 'keccak256|TYPEHASH' | head -60

echo
echo "=============================================================="
echo " 2. structHash builders (what the digest ACTUALLY encodes)"
echo "=============================================================="
grep -rn --include='*.sol' -E '_hash[A-Za-z]*\(|structHash\s*=' -A12 "$ROOT" \
  | grep -E 'structHash|abi\.encode|TYPEHASH|authorization\.|request\.|params\.' | head -80

echo
echo "=============================================================="
echo " 3. CANDIDATES — verify functions whose params may be absent from the digest"
echo "=============================================================="
echo "   Look for a parameter in the _require*/_validate* signature that appears in"
echo "   NEITHER the TYPEHASH string NOR the structHash abi.encode(...) list."
echo "   Known shape (RelayFundingPool): _requireDrawAuthorization(account, token,"
echo "   orderAddress, auth) with TYPEHASH 'DrawAuthorization(address account,address"
echo "   orderAddress)' -> token is discarded."
echo
grep -rn --include='*.sol' -E 'function _require[A-Za-z]*\(|function _validate[A-Za-z]*\(' -A8 "$ROOT" \
  | head -60

echo
echo "=============================================================="
echo " 4. ECONOMIC BOUNDS — is the missing field load-bearing?"
echo "=============================================================="
echo "   If limits are per-(account,TOKEN) but the signature is token-agnostic,"
echo "   one signature covers every token. Grep for the nested mapping:"
grep -rn --include='*.sol' -E 'mapping\(address => mapping\(address =>' "$ROOT" | head -20

if [ -n "$ADDR" ] && [ -n "$RPC" ]; then
  echo
  echo "=============================================================="
  echo " 5. DEPLOYMENT GATE (a proven bug in an undeployed contract = zero)"
  echo "=============================================================="
  echo -n "codesize $ADDR on $RPC = "
  cast codesize --rpc-url "$RPC" "$ADDR" 2>&1 | head -1
  echo "  0  -> NOT DEPLOYED. Report as latent / next-release, NOT critical."
  echo "  >0 -> live. Proceed to forge PoC."
fi

echo
echo "=============================================================="
echo " deployment manifests (check prod/stag/test, not just dev)"
echo "=============================================================="
for f in $(find "$ROOT" -path '*deployments*' -name '*.json' 2>/dev/null | head -8); do
  echo -n "$(basename "$f"): "
  grep -ci 'pool\|funding\|vault' "$f" 2>/dev/null || echo 0
done
echo "  A contract present only in dev.json is NOT live. Confirm with cast codesize."
