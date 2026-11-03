#!/usr/bin/env bash
#===============================================================================
# vuln-toolz — One-Command Install Script
#===============================================================================
# Installs all skill packs and tool scripts into the detected agent harness.
# Agnostic: auto-detects Hermes, Claude Code, OpenClaw, Devora, Roo, Codex,
# Cursor, Continue, and generic ~/.claude/~/skills dirs. Fallback copies to
# ~/.vuln-toolz/skills for manual wiring.
#
# Safe to run repeatedly — every run is idempotent and refreshes all files.
#
# Usage:
#   bash install.sh
#   # custom target:
#   SKILLS_DST=/path/to/skills bash install.sh
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

# ── Agent harness auto-detection ─────────────────────────────────────────────
# Order matters: more specific/popular first. Each probe: "name|dest_dir".
detect_harness() {
  local name="generic"
  local dst=""

  if [[ -d "${HOME}/.hermes/skills" ]]; then
    name="hermes"; dst="${HOME}/.hermes/skills"
  elif [[ -d "${HOME}/.claude/skills" ]]; then
    name="claude"; dst="${HOME}/.claude/skills"
  elif [[ -d "${HOME}/.config/claude-code/skills" ]]; then
    name="claude-code"; dst="${HOME}/.config/claude-code/skills"
  elif [[ -d "${HOME}/.openclaw/skills" ]]; then
    name="openclaw"; dst="${HOME}/.openclaw/skills"
  elif [[ -d "${HOME}/.devora/skills" ]]; then
    name="devora"; dst="${HOME}/.devora/skills"
  elif [[ -d "${HOME}/.roo/skills" ]]; then
    name="roo"; dst="${HOME}/.roo/skills"
  elif [[ -d "${HOME}/.codex/skills" ]]; then
    name="codex"; dst="${HOME}/.codex/skills"
  elif [[ -d "${HOME}/.cursor/skills" ]]; then
    name="cursor"; dst="${HOME}/.cursor/skills"
  elif [[ -d "${HOME}/.continue/skills" ]]; then
    name="continue"; dst="${HOME}/.continue/skills"
  elif [[ -n "${AGENT_SKILLS_DIR:-}" && -d "${AGENT_SKILLS_DIR}" ]]; then
    name="env"; dst="${AGENT_SKILLS_DIR}"
  else
    # Fallback — local neutral dir, user wires it manually
    name="generic"; dst="${HOME}/.vuln-toolz/skills"
  fi

  echo "${name}|${dst}"
}

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

ok()   { echo -e "  ${C_GREEN}✓${C_RESET} ${1}"; }
warn() { echo -e "  ${C_YELLOW}⚠${C_RESET}  ${1}" >&2; }
err()  { echo -e "  ${C_RED}✗${C_RESET} ${1}" >&2; }

# ── Detect target ────────────────────────────────────────────────────────────

banner
section "Harness detection"

# Honor explicit override
if [[ -n "${SKILLS_DST:-}" ]]; then
  harness_name="manual"
  harness_dst="${SKILLS_DST}"
  warn "SKILLS_DST override: ${harness_dst}"
else
  detect_out="$(detect_harness)"
  harness_name="${detect_out%%|*}"
  harness_dst="${detect_out##*|}"
fi

# Scripts go beside skills (sibling dir)
harness_root="$(dirname "${harness_dst}")"
SCRIPTS_DST="${harness_root}/scripts"

ok "Harness: ${harness_name}"
ok "Skills:  ${harness_dst}"
ok "Scripts: ${SCRIPTS_DST}"

# ── Preflight ────────────────────────────────────────────────────────────────

section "Preflight checks"

if [[ ! -d "${harness_dst}" ]]; then
  warn "Skills dir not found — creating…"
  mkdir -p "${harness_dst}"
  ok "Created ${harness_dst}"
else
  ok "Skills dir exists"
fi

if [[ ! -d "${SCRIPTS_DST}" ]]; then
  mkdir -p "${SCRIPTS_DST}" 2>/dev/null || true
fi

if [[ ! -d "${SKILLS_SRC}" ]]; then
  err "Source skills directory not found: ${SKILLS_SRC}"
  echo "  Make sure you are running this script from the vuln-toolz repository root."
  exit 1
fi
ok "Source skills directory found"

# ── Install skills ───────────────────────────────────────────────────────────

section "Installing skills"

TOTAL=$(find "${SKILLS_SRC}" -mindepth 1 -maxdepth 1 -type d | wc -l)
ok "${TOTAL} skill packs found"

for skill_dir in "${SKILLS_SRC}"/*/; do
  [[ -d "${skill_dir}" ]] || continue

  skill_name="$(basename "${skill_dir}")"
  dst_dir="${harness_dst}/${skill_name}"

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

# ── Install scripts ────────────���─────────────────────────────────────────────

section "Installing scripts"

if [[ -d "${SCRIPTS_SRC}" ]]; then
  SCRIPT_COUNT=0
  for f in "${SCRIPTS_SRC}"/*; do
    if [[ -f "${f}" ]]; then
      script_name="$(basename "${f}")"
      cp -f "${f}" "${SCRIPTS_DST}/${script_name}"
      chmod +x "${SCRIPTS_DST}/${script_name}" 2>/dev/null || true
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
echo -e "  ${C_BOLD}Target harness:${C_RESET}   ${harness_name} → ${harness_dst}"

if [[ ${FAILED} -gt 0 ]]; then
  echo -e "  ${C_BOLD}Failures:${C_RESET}        ${C_RED}${FAILED}${C_RESET}"
fi

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
  if [[ $((COL % 2)) -ne 0 ]]; then
    printf ' %.0s' $(seq 1 44)
    printf "${C_DIM}│${C_RESET}\n"
  fi
  echo -e "${C_DIM}  └──────────────────────────────────────────────────────────────────┘${C_RESET}"
fi

# ── Done ─────────────────────────────────────────────────────────────────────

echo ""
echo -e "  ${C_GREEN}${C_BOLD}vuln-toolz is ready.${C_RESET}"
echo -e "  ${C_DIM}Target: ${harness_name} (${harness_dst})${C_RESET}"
echo -e "  ${C_DIM}Restart the agent to pick up the skills.${C_RESET}"
echo ""

# Exit with failure if any skill failed to install
if [[ ${FAILED} -gt 0 ]]; then
  exit 1
fi