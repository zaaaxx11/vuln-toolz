#!/usr/bin/env bash
# wpapi_jina.sh - paced GET-only WP-API prober through the Jina Reader read-proxy
# Use when the target rate-limits your egress IP (persistent 429) and proxy fallback is authorized.
# Usage: ./wpapi_jina.sh <base-url> <routes-file> [evidence-out]
#   routes-file: one path per line (e.g. /wp-json/code-snippets/v1/snippets)
# Pacing: 1.2s between requests (honour stricter operator rates by editing SLEEP).
# Output: one classification line per route + full captures to evidence file.
set -euo pipefail

BASE="${1:?usage: wpapi_jina.sh <base-url> <routes-file> [evidence-out]}"
ROUTES="${2:?routes file required}"
EVID="${3:-wpapi_jina_evidence_$(date +%Y%m%d_%H%M%S).txt}"
SLEEP=1.2
HDRS=(-H "X-Bug-Bounty: zaaaxx" -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

: > "$EVID"

while IFS= read -r path; do
  [ -z "$path" ] && continue
  url="${BASE}${path}"
  # Jina Reader read-proxy: fetches from Jina's infra, bypasses our IP's rate-limit
  resp=$(curl -s --max-time 40 --http1.1 "${HDRS[@]}" "https://r.jina.ai/${url}" || true)
  # strip Jina markdown wrapper - body is everything after 'Markdown Content:\n'
  body="${resp#*Markdown Content:}"
  [ "$body" = "$resp" ] && body="$resp"   # no wrapper found

  # classify
  if printf '%s' "$body" | grep -q 'rest_forbidden'; then
    verdict="LOCKED-401 (permission callback rejects anonymous)"
  elif printf '%s' "$body" | grep -q 'rest_no_route'; then
    verdict="METHOD-GATED (route exists, not for GET)"
  elif printf '%s' "$body" | grep -q 'Checking your browser'; then
    verdict="ANTI-BOT (fingerprint-gated, read-proxy also challenged)"
  elif printf '%s' "$body" | grep -q 'Too Many Requests'; then
    verdict="PROXY-429 (back off 5s)"
    SLEEP=6
  else
    verdict="OPEN (public read surface)"
  fi

  printf '%s\n  [%s] %s\n' "$path" "$verdict" "$(printf '%s' "$body" | head -c 220 | tr '\n' ' ')"
  {
    printf '### %s\n%s\n\n' "$path" "$resp"
  } >> "$EVID"

  sleep "$SLEEP"
done < "$ROUTES"

echo "evidence -> $EVID"
