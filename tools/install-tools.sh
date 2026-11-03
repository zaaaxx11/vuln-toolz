#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# install-tools.sh — Comprehensive Security Tool Installer
# ---------------------------------------------------------------------------
# Installs ~27 offensive-security tools across WEB/API, BLOCKCHAIN, and
# CREDENTIALS categories.  Idempotent: skips anything already on $PATH.
#
# Usage:
#   chmod +x install-tools.sh && ./install-tools.sh
#
# Supported package managers: apt (Debian/Ubuntu), brew (macOS), go, cargo,
# pip, curl.
# ---------------------------------------------------------------------------
set -euo pipefail

# ── colour helpers ──────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  C_RESET='\033[0m'  C_BOLD='\033[1m'  C_RED='\033[31m'  C_GREEN='\033[32m'
  C_YELLOW='\033[33m' C_CYAN='\033[36m'   C_MAGENTA='\033[35m'
else
  C_RESET='' C_BOLD='' C_RED='' C_GREEN='' C_YELLOW='' C_CYAN='' C_MAGENTA=''
fi

# ── global state ────────────────────────────────────────────────────────
declare -a INSTALLED=() FAILED=() SKIPPED=()
GOBIN="${GOBIN:-${HOME}/go/bin}"
export GOFLAGS='-buildvcs=false'
export PATH="${GOBIN}:${HOME}/.local/bin:${HOME}/.cargo/bin:/usr/local/bin:${PATH}"
START_TIME=$(date +%s)

# ── helpers ─────────────────────────────────────────────────────────────
banner() {
  echo -e "${C_MAGENTA}${C_BOLD}"
  echo '╔══════════════════════════════════════════════════════════════╗'
  echo '║        ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗               ║'
  echo '║        ██║   ██║██║   ██║██║     ████╗  ██║               ║'
  echo '║        ██║   ██║██║   ██║██║     ██╔██╗ ██║               ║'
  echo '║        ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║               ║'
  echo '║         ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║               ║'
  echo '║          ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝               ║'
  echo '╠══════════════════════════════════════════════════════════════╣'
  echo '║            COMPREHENSIVE SECURITY TOOL INSTALLER            ║'
  echo '╚══════════════════════════════════════════════════════════════╝'
  echo -e "${C_RESET}"
}

log_info()  { echo -e "${C_CYAN}[INFO]${C_RESET}  $*"; }
log_ok()    { echo -e "${C_GREEN}[OK]${C_RESET}    $*"; }
log_skip()  { echo -e "${C_YELLOW}[SKIP]${C_RESET}  $*"; }
log_fail()  { echo -e "${C_RED}[FAIL]${C_RESET}  $*"; }
log_step()  { echo -e "${C_BOLD}${C_MAGENTA}──▶${C_RESET} ${C_BOLD}$*${C_RESET}"; }

tool_exists() {
  command -v "$1" &>/dev/null
}

record() {
  local status="$1" tool="$2" detail="${3:-}"
  case "$status" in
    installed) INSTALLED+=("$tool"); log_ok "$tool $detail";;
    skipped)   SKIPPED+=("$tool");   log_skip "$tool $detail";;
    failed)    FAILED+=("$tool");    log_fail "$tool $detail";;
  esac
}

# ── package-manager detection ───────────────────────────────���───────────
detect_os() {
  case "$(uname -s)" in
    Linux)
      if command -v apt-get &>/dev/null; then
        PKG_MANAGER="apt"
        PKG_INSTALL="sudo apt-get install -y -qq"
        PKG_UPDATE="sudo apt-get update -qq"
      else
        PKG_MANAGER="unknown"
      fi
      ;;
    Darwin)
      PKG_MANAGER="brew"
      PKG_INSTALL="brew install"
      PKG_UPDATE="brew update"
      ;;
    *)
      PKG_MANAGER="unknown"
      ;;
  esac
  log_info "Detected OS: $(uname -s), package manager: ${PKG_MANAGER:-none}"
}

# ── dependency checks ───────────────────────────────────────────────────
check_deps() {
  local deps=(go python3 cargo curl git)
  log_info "Checking core dependencies..."
  for dep in "${deps[@]}"; do
    if command -v "$dep" &>/dev/null; then
      log_ok "$dep: $(command -v "$dep")"
    else
      log_fail "$dep: NOT FOUND — some tools may fail to install"
    fi
  done
  echo
}

# ── generic installers ──────────────────────────────────────────────────
# All installer functions return 0 even on failure so set -e doesn't
# abort the whole script on the first missing tool. Failures are
# recorded in the FAILED array for the summary.

# go_install takes: tool_name package_path[@version]
go_install() {
  local name="$1" pkg="$2"
  shift 2 || true
  if tool_exists "$name"; then
    record skipped "$name" "(already at $(command -v "$name"))"
    return 0
  fi
  if ! command -v go &>/dev/null; then
    record failed "$name" "(go not installed — needed for ${pkg})"
    return 0
  fi
  log_info "installing $name via go install..."
  if GOFLAGS="${GOFLAGS}" go install -v "${pkg}" "$@" 2>&1; then
    record installed "$name" "(go install ${pkg})"
  else
    record failed "$name" "(go install ${pkg} failed)"
  fi
  return 0
}

apt_install() {
  local name="$1" pkg="${2:-$1}"
  if tool_exists "$name"; then
    record skipped "$name" "(already at $(command -v "$name"))"
    return 0
  fi
  if [[ "$PKG_MANAGER" != "apt" ]]; then
    record failed "$name" "(apt not available)"
    return 0
  fi
  log_info "installing $name via apt..."
  if sudo apt-get install -y -qq "$pkg" 2>&1; then
    record installed "$name" "(apt install $pkg)"
  else
    record failed "$name" "(apt install $pkg failed)"
  fi
  return 0
}

brew_install() {
  local name="$1" formula="${2:-$1}"
  if tool_exists "$name"; then
    record skipped "$name" "(already at $(command -v "$name"))"
    return 0
  fi
  if [[ "$PKG_MANAGER" != "brew" ]]; then
    record failed "$name" "(brew not available)"
    return 0
  fi
  log_info "installing $name via brew..."
  if brew install "$formula" 2>&1; then
    record installed "$name" "(brew install $formula)"
  else
    record failed "$name" "(brew install $formula failed)"
  fi
  return 0
}

pip_install() {
  local name="$1" pkg="${2:-$1}"
  if tool_exists "$name"; then
    record skipped "$name" "(already at $(command -v "$name"))"
    return 0
  fi
  log_info "installing $name via pip..."

  # Detect virtualenv — if inside one, --user won't work
  local pip_args=(--quiet)
  if [[ -n "${VIRTUAL_ENV:-}" ]] || [[ -n "${CONDA_PREFIX:-}" ]]; then
    pip_args+=()
  else
    pip_args+=(--user)
  fi

  if python3 -m pip install "${pip_args[@]}" "$pkg" 2>&1; then
    record installed "$name" "(pip install $pkg)"
  else
    # Fallback: try without --user
    log_info "first pip attempt failed, retrying without user flag..."
    if python3 -m pip install --quiet "$pkg" 2>&1; then
      record installed "$name" "(pip install $pkg)"
    else
      record failed "$name" "(pip install $pkg failed)"
    fi
  fi
  return 0
}

cargo_install() {
  local name="$1" crate="${2:-$1}"
  if tool_exists "$name"; then
    record skipped "$name" "(already at $(command -v "$name"))"
    return 0
  fi
  if ! command -v cargo &>/dev/null; then
    record failed "$name" "(cargo not available)"
    return 0
  fi
  log_info "installing $name via cargo..."
  if cargo install "$crate" 2>&1; then
    record installed "$name" "(cargo install $crate)"
  else
    record failed "$name" "(cargo install $crate failed)"
  fi
  return 0
}

# ── categories ──────────────────────────────────────────────────────────

install_web_api() {
  log_step '── WEB / API tools ──────────────────────────────────────────'

  # --- Go-based tools ---
  go_install nuclei    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  go_install subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  go_install httpx     github.com/projectdiscovery/httpx/cmd/httpx@latest
  go_install naabu     github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
  go_install katana    github.com/projectdiscovery/katana/cmd/katana@latest
  go_install ffuf      github.com/ffuf/ffuf/v2@latest
  go_install gobuster  github.com/OJ/gobuster/v3@latest
  go_install amass     github.com/owasp-amass/amass/v4/...@latest
  go_install dnsx      github.com/projectdiscovery/dnsx/cmd/dnsx@latest
  go_install shuffledns github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
  go_install gau       github.com/lc/gau/v2/cmd/gau@latest
  go_install waybackurls github.com/tomnomnom/waybackurls@latest

  # gf is a bit special — install binary + clone patterns
  if tool_exists gf; then
    record skipped gf "(already at $(command -v gf))"
  elif ! command -v go &>/dev/null; then
    record failed gf "(go not installed — needed for gf)"
  else
    log_info "installing gf via go install..."
    if GOFLAGS="${GOFLAGS}" go install -v github.com/tomnomnom/gf@latest 2>&1; then
      record installed gf "(go install)"
      # clone gf patterns if not present
      GFDIR="${HOME}/.gf"
      if [[ ! -d "$GFDIR" ]]; then
        log_info "cloning gf patterns to ${GFDIR}..."
        if git clone --depth 1 https://github.com/tomnomnom/gf.git "${GFDIR}/_tmp" 2>&1; then
          mkdir -p "${GFDIR}"
          cp -r "${GFDIR}/_tmp/examples/"*.json "${GFDIR}/" 2>/dev/null || true
          rm -rf "${GFDIR}/_tmp"
          log_ok "gf patterns installed to ${GFDIR}"
        else
          log_info "could not clone gf patterns (non-fatal)"
        fi
      else
        log_ok "gf patterns already at ${GFDIR}"
      fi
    else
      record failed gf "(go install failed)"
    fi
  fi

  go_install anew      github.com/tomnomnom/anew@latest
  go_install unfurl    github.com/tomnomnom/unfurl@latest

  # --- APT (Debian/Ubuntu) / Brew (macOS) tools ---
  if [[ "$PKG_MANAGER" == "apt" ]]; then
    apt_install nmap    nmap
    apt_install masscan masscan
    apt_install sqlmap  sqlmap
  elif [[ "$PKG_MANAGER" == "brew" ]]; then
    brew_install nmap    nmap
    brew_install masscan masscan
    brew_install sqlmap  sqlmap
  else
    # No apt/brew — sqlmap falls back to git clone
    if tool_exists sqlmap; then
      record skipped sqlmap "(already at $(command -v sqlmap))"
    else
      SQLMAP_DIR="${HOME}/tools/sqlmap"
      if [[ -d "$SQLMAP_DIR" ]]; then
        log_info "sqlmap git clone already exists at ${SQLMAP_DIR}, updating..."
        (cd "$SQLMAP_DIR" && git pull --ff-only 2>&1) || true
        record installed sqlmap "(git clone at ${SQLMAP_DIR})"
      else
        log_info "cloning sqlmap to ${SQLMAP_DIR}..."
        if git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git "$SQLMAP_DIR" 2>&1; then
          ln -sf "${SQLMAP_DIR}/sqlmap.py" "${HOME}/.local/bin/sqlmap" 2>/dev/null || true
          record installed sqlmap "(git clone at ${SQLMAP_DIR})"
        else
          record failed sqlmap "(git clone failed)"
        fi
      fi
    fi
    # nmap / masscan have no universal fallback — report as failed
    for t in nmap masscan; do
      if tool_exists "$t"; then
        record skipped "$t" "(already at $(command -v "$t"))"
      else
        record failed "$t" "(no supported package manager)"
      fi
    done
  fi

  echo
}

install_blockchain() {
  log_step '── BLOCKCHAIN tools ───────────────────────────────────────'

  # --- Foundry (foundryup, provides cast + anvil) ---
  if tool_exists foundryup; then
    record skipped foundryup "(already at $(command -v foundryup))"
  else
    log_info "installing Foundry (cast + anvil + forge + chisel)..."
    if curl -sSfL https://foundry.paradigm.xyz | bash 2>&1; then
      record installed foundryup "(curl installer)"
      # Run foundryup to install the actual binaries
      log_info "running foundryup..."
      if "${HOME}/.foundry/bin/foundryup" 2>&1; then
        log_ok "Foundry binaries installed"
      else
        record failed foundry-binaries "(foundryup failed)"
      fi
    else
      record failed foundryup "(curl installer failed)"
    fi
  fi

  # Verify cast + anvil (provided by foundry)
  for cmd in cast anvil; do
    if tool_exists "$cmd"; then
      record skipped "$cmd" "(part of foundry, at $(command -v "$cmd"))"
    else
      # May need path update
      if [[ -x "${HOME}/.foundry/bin/${cmd}" ]]; then
        export PATH="${HOME}/.foundry/bin:${PATH}"
        record installed "$cmd" "(foundry, at ${HOME}/.foundry/bin/${cmd})"
      else
        record failed "$cmd" "(not found after foundry install)"
      fi
    fi
  done

  # --- Slither ---
  pip_install slither slither-analyzer

  # --- solc-select ---
  pip_install solc-select solc-select

  # --- crytic-compile ---
  pip_install crytic-compile crytic-compile

  # --- Echidna (try cargo, fallback to pre-built) ---
  if tool_exists echidna; then
    record skipped echidna "(already at $(command -v echidna))"
  else
    if command -v cargo &>/dev/null; then
      log_info "installing echidna via cargo..."
      if cargo install echidna 2>&1; then
        record installed echidna "(cargo install)"
      else
        log_info "cargo install failed, trying pre-built binary..."
        ECHIDNA_VER="2.2.5"
        ECHIDNA_URL="https://github.com/crytic/echidna/releases/download/v${ECHIDNA_VER}/echidna-${ECHIDNA_VER}-x86_64-linux.tar.gz"
        ECHIDNA_TMP="$(mktemp -d)"
        if curl -sSfL "$ECHIDNA_URL" -o "${ECHIDNA_TMP}/echidna.tar.gz" 2>&1; then
          tar -xzf "${ECHIDNA_TMP}/echidna.tar.gz" -C "$ECHIDNA_TMP"
          mkdir -p "${HOME}/.local/bin"
          cp "${ECHIDNA_TMP}/echidna" "${HOME}/.local/bin/echidna" 2>/dev/null || \
            find "$ECHIDNA_TMP" -name echidna -type f -exec cp {} "${HOME}/.local/bin/echidna" \;
          chmod +x "${HOME}/.local/bin/echidna" 2>/dev/null || true
          rm -rf "$ECHIDNA_TMP"
          if tool_exists echidna; then
            record installed echidna "(pre-built v${ECHIDNA_VER})"
          else
            record failed echidna "(pre-built install failed)"
          fi
        else
          record failed echidna "(download failed)"
          rm -rf "$ECHIDNA_TMP"
        fi
      fi
    else
      record failed echidna "(cargo not available)"
    fi
  fi

  # --- Medusa (fuzzer) ---
  go_install medusa github.com/crytic/medusa/cmd/medusa@latest

  # --- 4byte (Ethereum signature database) ---
  go_install 4byte github.com/dethcrypto/4byte/cmd/4byte@latest

  echo
}

install_credentials() {
  log_step '── CREDENTIALS tools ──────────────────────────────────────'

  go_install trufflehog github.com/trufflesecurity/trufflehog/v3@latest
  go_install gitleaks  github.com/gitleaks/gitleaks/v8@latest

  echo
}

# ── summary ─────────────────────────────────────────────────────────────
print_summary() {
  local elapsed=$(($(date +%s) - START_TIME))
  local mins=$((elapsed / 60))
  local secs=$((elapsed % 60))

  echo
  echo -e "${C_MAGENTA}${C_BOLD}╔══════════════════════════════════════════════════════════════╗${C_RESET}"
  echo -e "${C_MAGENTA}${C_BOLD}║                    INSTALLATION SUMMARY                      ║${C_RESET}"
  echo -e "${C_MAGENTA}${C_BOLD}╚══════════════════════════════════════════════════════════════╝${C_RESET}"
  echo -e "  Time elapsed: ${C_BOLD}${mins}m ${secs}s${C_RESET}"
  echo

  echo -e "  ${C_GREEN}Installed (${#INSTALLED[@]})${C_RESET}:"
  for t in "${INSTALLED[@]}"; do
    echo -e "    ${C_GREEN}✔${C_RESET} $t"
  done
  echo

  echo -e "  ${C_YELLOW}Skipped (${#SKIPPED[@]})${C_RESET}:"
  for t in "${SKIPPED[@]}"; do
    echo -e "    ${C_YELLOW}─${C_RESET} $t"
  done
  echo

  if [[ ${#FAILED[@]} -gt 0 ]]; then
    echo -e "  ${C_RED}Failed (${#FAILED[@]})${C_RESET}:"
    for t in "${FAILED[@]}"; do
      echo -e "    ${C_RED}✘${C_RESET} $t"
    done
    echo
  fi

  local total=$(( ${#INSTALLED[@]} + ${#SKIPPED[@]} + ${#FAILED[@]} ))
  echo -e "  Total tools processed: ${C_BOLD}${total}${C_RESET}"
  echo -e "  ${C_GREEN}Installed: ${#INSTALLED[@]}${C_RESET}  ${C_YELLOW}Skipped: ${#SKIPPED[@]}${C_RESET}  ${C_RED}Failed: ${#FAILED[@]}${C_RESET}"
  echo

  if [[ ${#FAILED[@]} -eq 0 ]]; then
    echo -e "  ${C_GREEN}${C_BOLD}✓ All tools installed successfully!${C_RESET}"
    echo
    return 0
  else
    echo -e "  ${C_RED}${C_BOLD}⚠ Some tools failed to install.${C_RESET}"
    echo "  Check the output above for details."
    echo
    return ${#FAILED[@]}
  fi
}

# ── main ───────────────────────────────────────────────���────────────────
main() {
  banner

  detect_os

  # Update package lists if using apt
  if [[ "$PKG_MANAGER" == "apt" ]]; then
    log_info "updating apt package lists..."
    sudo apt-get update -qq 2>&1 || log_info "apt update failed (continuing anyway)"
  elif [[ "$PKG_MANAGER" == "brew" ]]; then
    brew update 2>&1 || log_info "brew update failed (continuing anyway)"
  fi

  check_deps

  # Ensure ~/.local/bin exists
  mkdir -p "${HOME}/.local/bin" "${GOBIN}"

  # Install tools by category
  install_web_api
  install_blockchain
  install_credentials

  local final_exit=${#FAILED[@]}
  print_summary
  return $(( final_exit ))
}

main "$@"