#!/bin/bash
# rt.sh — paced, verbatim evidence capture for a red-team hypothesis round.
#
# usage: rt.sh <testname> <curl-args...>     (curl args include the URL)
#   e.g. rt.sh openredir_param "https://url.example.com/?url=https://example.com"
#        rt.sh stage_options "https://stage.example.com/" -X OPTIONS -H "Origin: https://evil.example"
#
# Behavior:
#   * sleeps 1s BEFORE the request so 1 req/sec pacing survives any call site
#   * stamps an operator header (X-Bug-Bounty) on every request
#   * writes verbatim request + response to <DIR>/<testname>.txt
#   * echoes the first 1500 bytes to stdout for quick triage
#
# Set RT_DIR to change the evidence directory (default ./redteam next to this script).
NAME="$1"; shift
DIR="${RT_DIR:-$(dirname "$0")}"
sleep 1
{
  echo "### REQUEST"
  echo "curl -sS -i --max-time 15 -H 'X-Bug-Bounty: zaaaxx' $*"
  echo
  echo "### RESPONSE (verbatim)"
  curl -sS -i --max-time 15 -H "X-Bug-Bounty: zaaaxx" "$@" 2>&1
  echo
  echo "### END $NAME"
} > "$DIR/${NAME}.txt" 2>&1
echo "=== saved $NAME.txt ==="
head -c 1500 "$DIR/${NAME}.txt"
