#!/usr/bin/env bash
#===============================================================================
# vuln-toolz — One-Command Install Script
#===============================================================================
# Installs all skill packs and tool scripts into the user's Hermes agent
# environment. Safe to run repeatedly — every run is idempotent and will
# refresh all files to the latest version.
#
# Usage:
#   curl -fsSL https://.../install.sh | bash
#   # or locally:
#   bash install.sh
#
# What it does:
#   • Copies ./skills/* → ~/.hermes/skills/
#   • Copies ./scripts/* → ~/.hermes/scripts/
#   • Preserves subdirectory structure (references/, scripts/, etc.)
#   • Prints a color summary of every skill installed
#===============================================================================

set -euo pipefail

# ── Colour palette ───────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  C_RESET='\033[0m'
  C_BOLD='\033[1m'
  C_DIM='\033[2m'
  C_GREEN='\033[32m'
  C_YELLOW='\033[33m'
  C_CYAN='\033[36m'
  C_MAGENTA='\033[35m'
  C_RED='\033[31m'
else
  C_RESET='' C_BOLD='' C_DIM='' C_GREEN='' C_YELLOW='' C_CYAN='' C_MAGENTA='' C_RED=''
fi

# ── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILLS_SRC="${SCRIPT_DIR}/skills"
SCRIPTS_SRC="${SCRIPT_DIR}/scripts"
HERMES_HOME="${HOME}/.hermes"
SKILLS_DST="${HERMES_HOME}/skills"
SCRIPTS_DST="${HERMES_HOME}/scripts"

# ── Counters ─────────────────────────────────────────────────────────────────
INSTALLED=0
SKIPPED=0
FAILED=0
declare -a INSTALLED_NAMES=()

# ── Helpers ──────────────────────────────────────────────────────────────────

banner() {
  echo -e "${C_MAGENTA}${C_BOLD}"
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║              vuln-toolz — Installer                         ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo -e "${C_RESET}"
}

section() {
  echo -e "\n${C_BOLD}${C_CYAN}▸ ${1}${C_RESET}"
}

ok() {
  echo -e "  ${C_GREEN}✓${C_RESET} ${1}"
}

warn() {
  echo -e "  ${C_YELLOW}⚠${C_RESET}  ${1}" >&2
}

err() {
  echo -e "  ${C_RED}✗${C_RESET} ${1}" >&2
}

# ── Preflight ────────────────────────────────────────────────────────────────

banner

section "Preflight checks"

# Ensure Hermes skills directory exists
if [[ ! -d "${HERMES_HOME}" ]]; then
  warn "~/.hermes/ not found — creating…"
  mkdir -p "${HERMES_HOME}"
  ok "Created ${HERMES_HOME}"
fi

if [[ ! -d "${SKILLS_DST}" ]]; then
  warn "~/.hermes/skills/ not found — creating…"
  mkdir -p "${SKILLS_DST}"
  ok "Created ${SKILLS_DST}"
else
  ok "~/.hermes/skills/ exists"
fi

if [[ ! -d "${SCRIPTS_DST}" ]]; then
  warn "~/.hermes/scripts/ not found — creating…"
  mkdir -p "${SCRIPTS_DST}"
  ok "Created ${SCRIPTS_DST}"
else
  ok "~/.hermes/scripts/ exists"
fi

# Check source directory
if [[ ! -d "${SKILLS_SRC}" ]]; then
  err "Source skills directory not found: ${SKILLS_SRC}"
  echo "  Make sure you are running this script from the vuln-toolz repository root."
  exit 1
fi
ok "Source skills directory found"

# ── Install skills ───────────────────────────────────────────────────────────

section "Installing skills"

TOTAL=$(find "${SKILLS_SRC}" -mindepth 1 -maxdepth 1 -type d | wc -l)

for skill_dir in "${SKILLS_SRC}"/*/; do
  [[ -d "${skill_dir}" ]] || continue

  skill_name="$(basename "${skill_dir}")"
  dst_dir="${SKILLS_DST}/${skill_name}"

  # ---------- handle existing install ----------------------------------------
  if [[ -d "${dst_dir}" ]]; then
    action="updated"
  else
    action="installed"
  fi

  # ---------- copy -----------------------------------------------------------
  if rm -rf "${dst_dir}" 2>/dev/null; then true; fi
  if cp -r "${skill_dir}" "${dst_dir}"; then
    ((INSTALLED++)) || true
    INSTALLED_NAMES+=("${skill_name}")
    ok "${action}  ${skill_name}"
  else
    ((FAILED++)) || true
    err "failed: ${skill_name}"
  fi
done

# ── Install scripts ──────────────────────────────────────────────────────────

section "Installing scripts"

if [[ -d "${SCRIPTS_SRC}" ]]; then
  SCRIPT_COUNT=0
  for f in "${SCRIPTS_SRC}"/*; do
    if [[ -f "${f}" ]]; then
      script_name="$(basename "${f}")"
      cp -f "${f}" "${SCRIPTS_DST}/${script_name}"
      ok "copied   ${script_name}"
      ((SCRIPT_COUNT++)) || true
    fi
  done

  if [[ ${SCRIPT_COUNT} -eq 0 ]]; then
    warn "No scripts found in ./scripts/"
  fi
else
  warn "No ./scripts/ directory — skipping"
fi

# ── Summary ──────────────────────────────────────────────────────────────────

section "Installation summary"

echo ""
echo -e "  ${C_BOLD}Skills installed:${C_RESET}  ${C_GREEN}${INSTALLED}${C_RESET}"
echo -e "  ${C_BOLD}Scripts copied:${C_RESET}   ${C_GREEN}${SCRIPT_COUNT:-0}${C_RESET}"

if [[ ${FAILED} -gt 0 ]]; then
  echo -e "  ${C_BOLD}Failures:${C_RESET}        ${C_RED}${FAILED}${C_RESET}"
fi

echo ""
echo -e "  ${C_BOLD}Target:${C_RESET}  ${SKILLS_DST}"
echo ""

# ── List installed skills (compact grid) ────────────────────────────────────

if [[ ${INSTALLED} -gt 0 ]]; then
  echo -e "${C_DIM}  ┌─ Installed skills ─────────────────────────────────────────────┐${C_RESET}"
  COL=0
  for name in "${INSTALLED_NAMES[@]}"; do
    printf "${C_DIM}  │${C_RESET} %-42s" "${name}"
    ((COL++)) || true
    if [[ $((COL % 2)) -eq 0 ]]; then
      printf "${C_DIM}│${C_RESET}\n"
    fi
  done
  # Finish partial row (pad the empty right-hand cell)
  if [[ $((COL % 2)) -ne 0 ]]; then
    printf ' %.0s' $(seq 1 44)
    printf "${C_DIM}│${C_RESET}\n"
  fi
  echo -e "${C_DIM}  └──────────────────────────────────────────────────────────────────┘${C_RESET}"
fi

# ── Done ─────────────────────────────────────────────────────────────────────

echo ""
echo -e "  ${C_GREEN}${C_BOLD}vuln-toolz is ready.${C_RESET}"
echo -e "  ${C_DIM}Run 'hermes skill view black-swan-engine' to verify.${C_RESET}"
echo ""

# Exit with failure if any skill failed to install
if [[ ${FAILED} -gt 0 ]]; then
  exit 1
fi