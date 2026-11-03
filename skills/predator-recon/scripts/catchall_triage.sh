#!/bin/bash
# catchall_triage.sh — decide live / dead / hiding for a batch of dev+staging hosts.
#
# Implements the disciplines from references/cdn-edge-disposition-triage.md and
# references/ssrf-differential-refutation.md:
#   * the 40-SECOND RULE  — a CF-fronted host that returns 0 bytes under a short timeout is not a
#     mystery; re-probe at 45s and Cloudflare will emit 522/524 itself.
#   * CATCH-ALL PROOF BY BYTE-IDENTITY — a random-path control plus md5 of the body. Every attack
#     path byte-identical to the control => proven catch-all => no differential => host is closed.
#   * SHAPE-DEPENDENT CATCH-ALL — ONE random-path control is NOT enough. Stacks gate the catch-all on
#     path SHAPE, not existence: SPA routers answer /robots.txt and /sitemap.xml with the app shell
#     while a bare random path 404s; PHP front controllers answer dot-paths with the homepage while a
#     bare random path 404s. So probe THREE control shapes — bare, extension-bearing, dot-prefixed —
#     and count a path as a true differential only when it differs from ALL of them.
#
# usage:
#   ./catchall_triage.sh host1 [host2 ...]                  # default 45s timeout
#   TIMEOUT=15 ./catchall_triage.sh api.example.com         # short sweep
#   OUT=/tmp/recon ./catchall_triage.sh dev.example.com ...
#
# Env: TIMEOUT (per-request seconds, default 45)
#      OUT     (evidence dir, default ./triage-evidence)
#      OPERATOR_HEADER="X-Bug-Bounty: handle"  (stamped on every request)
#      UA      (default: a current Chrome string)
#
# Exit: 0 always (triage tool, not a gate). Prints one verdict line per host.
set -uo pipefail

TIMEOUT="${TIMEOUT:-45}"
OUT="${OUT:-./triage-evidence}"
OPERATOR_HEADER="${OPERATOR_HEADER:-X-Zoya-Recon: batch-a}"
UA="${UA:-Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36}"

# random paths that cannot exist — the controls. Regenerate per run so a cached CDN 404 can't fake it.
# Three SHAPES, because the catch-all may be shape-gated rather than universal (see header).
SEED="$(date +%s | tail -c 6)"
CONTROL_BARE="/zx9-nonexistent-${SEED}"
CONTROL_EXT="/zx9-nonexistent-${SEED}.xml"
CONTROL_DOT="/.zx9-nonexistent-${SEED}"

# attack paths: config/env/debug/API docs. Kept small on purpose — the controls do the work.
PATHS=(
  "/"
  "$CONTROL_BARE"
  "$CONTROL_EXT"
  "$CONTROL_DOT"
  "/.env"
  "/actuator"
  "/config.js"
  "/robots.txt"
  "/api/health"
  "/openapi.json"
)

mkdir -p "$OUT"
[ $# -ge 1 ] || { echo "usage: $0 host1 [host2 ...]"; exit 1; }

slug() { echo "$1" | tr -c 'a-zA-Z0-9.' '_' | sed 's/_*$//'; }

for HOST in "$@"; do
  H="$HOST"; [[ "$H" == http* ]] && H="${H#*://}" && H="${H%%/*}"
  S="$(slug "$H")"
  echo "=========================================================="
  echo "HOST    : $H"
  echo "CONTROLS: $CONTROL_BARE"
  echo "          $CONTROL_EXT"
  echo "          $CONTROL_DOT"
  echo "TIMEOUT : ${TIMEOUT}s"
  echo "----------------------------------------------------------"
  echo "  path                          status        bytes   body-md5"

  declare -A MD5S=()
  CTRL_STATUS=""
  for P in "${PATHS[@]}"; do
    F="$OUT/${S}__$(echo "$P" | tr -c 'a-zA-Z0-9.' '_' | sed 's/_*$//').txt"
    BODY="$(mktemp)"
    {
      echo "### REQUEST"
      echo "GET https://${H}${P}"
      echo "headers: ${OPERATOR_HEADER} | UA: ${UA}"
      echo "time: $(date -u +%Y-%m-%dT%H:%M:%SZ)  timeout: ${TIMEOUT}s"
      echo
      echo "### RESPONSE (verbatim)"
    } > "$F"
    curl -sS -m "$TIMEOUT" -D - -o "$BODY" \
      -H "$OPERATOR_HEADER" -H "User-Agent: $UA" -H "Accept: */*" \
      "https://${H}${P}" >> "$F" 2>&1
    RC=$?
    STATUS="$(grep -m1 -oE '^HTTP/[0-9.]+ [0-9]{3}' "$F" | head -1)"
    [ -z "$STATUS" ] && STATUS="NO-RESPONSE(curl=$RC)"
    BYTES="$(wc -c < "$BODY" 2>/dev/null || echo 0)"
    MD5="$(md5sum "$BODY" 2>/dev/null | cut -c1-12)"
    {
      echo
      echo "### CURL_EXIT: $RC   BODY_BYTES: $BYTES   BODY_MD5: $MD5"
      echo "### BODY (first 3000 bytes)"
      head -c 3000 "$BODY"
      echo
    } >> "$F"
    rm -f "$BODY"

    [ "$P" = "$CONTROL_BARE" ] && CTRL_STATUS="$STATUS"
    MD5S["$P"]="$MD5"
    printf "  %-28s %-13s %-7s %s\n" "$P" "$STATUS" "$BYTES" "$MD5"
    sleep 1.1   # 1 req/s pacing, honoured literally
  done

  # ---- verdict ----
  # "/" is the host baseline, never a finding. The three control shapes define the catch-all
  # envelope: a path matching ANY of them is proven catch-all, not a differential.
  declare -A CTRL=()
  for P in "$CONTROL_BARE" "$CONTROL_EXT" "$CONTROL_DOT"; do
    M="${MD5S[$P]:-}"
    [ -n "$M" ] && CTRL["$M"]=1
  done
  DIFF=0
  for P in "${PATHS[@]}"; do
    case "$P" in
      "/"|"$CONTROL_BARE"|"$CONTROL_EXT"|"$CONTROL_DOT") continue ;;
    esac
    M="${MD5S[$P]:-}"
    if [ -n "${CTRL[$M]:-}" ]; then
      echo "  ~~ catch-all: $P ($M) matches a control shape — no differential"
    else
      DIFF=1
      echo "  !! DIFFERENTIAL: $P ($M) differs from ALL control shapes — chase this"
    fi
  done

  case "$CTRL_STATUS" in
    *522*|*524*|*521*)
      echo "  VERDICT: ERROR — origin dead/unreachable at the edge ($CTRL_STATUS). Cert may still be live; re-check later." ;;
    *530*|*1016*)
      echo "  VERDICT: ERROR — dangling origin (CF 1016/530: origin name does not resolve). Takeover CANDIDATE only; CNAME is unobservable behind the proxy." ;;
    NO-RESPONSE*)
      echo "  VERDICT: UNRESOLVED — no bytes at ${TIMEOUT}s. Re-run with TIMEOUT=60 before writing this off." ;;
    *)
      if [ "$DIFF" -eq 0 ]; then
        echo "  VERDICT: NOTHING — proven catch-all ($CTRL_STATUS). Every attack path matches a control shape."
        echo "           No differential exists: path name does not influence the response. Host is closed."
      else
        echo "  VERDICT: FOUND DIFFERENTIAL — at least one path differs from all control shapes. Chase those paths."
      fi ;;
  esac
  echo "  evidence: $OUT/${S}__*.txt"
  echo
done
