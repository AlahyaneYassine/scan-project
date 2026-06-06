#!/usr/bin/env bash

set -euo pipefail

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

TARGET=""
OUTPUT_DIR="pentest_reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
PORTS=""

DO_FAST=0
DO_FULL=0
DO_VULN=0
DO_WEB=0
FAILED=0
NMAP_FAST_TIMEOUT="120s"
NMAP_VULN_TIMEOUT="600s"
NMAP_WEB_TIMEOUT="600s"
NMAP_FULL_TIMEOUT="600s"

print_banner() {
  cat << 'EOF'
=============================================================
Advanced Pentest Scanner (Modular)
=============================================================
EOF
}

usage() {
  echo "Usage: $0 <target_ip> [--fast] [--full] [--vuln] [--web] [--ports 80,443] [--output-dir path]" >&2
}

validate_ip() {
  local ip="$1"
  if ! [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "[!] IP invalide: $ip" >&2
    exit 1
  fi

  IFS='.' read -r -a octets <<< "$ip"
  for octet in "${octets[@]}"; do
    if (( octet < 0 || octet > 255 )); then
      echo "[!] IP invalide: $ip" >&2
      exit 1
    fi
  done
}

validate_ports() {
  local ports="$1"
  if [[ -z "$ports" ]]; then
    return 0
  fi

  if ! [[ "$ports" =~ ^[0-9]{1,5}(,[0-9]{1,5})*$ ]]; then
    echo "[!] Format de ports invalide: $ports" >&2
    exit 1
  fi

  IFS=',' read -r -a list <<< "$ports"
  for port in "${list[@]}"; do
    if (( port < 1 || port > 65535 )); then
      echo "[!] Port hors plage: $port" >&2
      exit 1
    fi
  done
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[!] Outil manquant: $cmd" >&2
    return 1
  fi
  return 0
}

check_dependencies() {
  local status=0
  require_cmd "nmap" || status=1

  if (( status != 0 )); then
    echo "[!] Dependances manquantes. Installez les outils requis avant execution." >&2
    exit 1
  fi
}

init_output() {
  REPORT_BASE="${OUTPUT_DIR}/${TARGET}_${TIMESTAMP}"
  mkdir -p "${REPORT_BASE}/nmap" "${REPORT_BASE}/web" "${REPORT_BASE}/exploits"
}

run_logged_command() {
  local label="$1"
  shift
  local output_file="$1"
  shift

  echo -e "${YELLOW}[*] ${label}...${NC}"
  set +e
  "$@" 2>&1 | tee -a "$output_file"
  local command_status=${PIPESTATUS[0]}
  set -e

  if [[ "$command_status" -eq 124 ]]; then
    echo -e "${YELLOW}[WARN] ${label} depasse le delai de 60s${NC}" | tee -a "$output_file"
    FAILED=1
    return 0
  fi

  if [[ "$command_status" -ne 0 ]]; then
    echo -e "${YELLOW}[WARN] ${label} a echoue avec le code ${command_status}${NC}" | tee -a "$output_file"
    FAILED=1
    return 0
  fi

  return 0
}

detect_web_ports() {
  local target="$1"
  local ports_output
  ports_output=$(timeout 45s nmap -Pn -n -sV --open --max-retries 1 --host-timeout 20s -p 80,443,8080,8000,8443 "$target" 2>/dev/null || true)

  if [[ -z "$ports_output" ]]; then
    return 0
  fi

  printf '%s\n' "$ports_output" | awk '/^[0-9]+\/(tcp|udp)[[:space:]]+open[[:space:]]+/ {
    split($1, parts, "/");
    port = parts[1];
    if ($2 == "open" && $1 ~ /\/tcp$/) {
      if (port == 80 || port == 443 || port == 8080 || port == 8000 || port == 8443) {
        print port;
      }
    }
  }' | sort -n | uniq
}

scan_fast() {
  local nmap_target="$1"
  local nmap_ports="$2"

  if [[ -n "$nmap_ports" ]]; then
    run_logged_command "Module FAST" "${REPORT_BASE}/nmap/fast.txt" timeout "$NMAP_FAST_TIMEOUT" nmap -F -T4 -p "$nmap_ports" "$nmap_target"
  else
    run_logged_command "Module FAST" "${REPORT_BASE}/nmap/fast.txt" timeout "$NMAP_FAST_TIMEOUT" nmap -F -T4 "$nmap_target"
  fi
}

scan_vuln() {
  local nmap_target="$1"

  echo -e "${BLUE}[*] Module VULN...${NC}"
  run_logged_command "Module VULN" "${REPORT_BASE}/nmap/vuln.txt" timeout "$NMAP_VULN_TIMEOUT" nmap -sV --script vuln --script-timeout 120s "$nmap_target"
}

scan_web() {
  local target="$1"
  local detected_ports
  detected_ports=$(detect_web_ports "$target")

  if [[ -z "$detected_ports" ]]; then
    echo "No HTTP service detected on common web ports." | tee -a "${REPORT_BASE}/web/whatweb.txt"
    return 0
  fi

  local ports_array=()
  while IFS= read -r port; do
    if [[ -n "$port" ]]; then
      ports_array+=("$port")
    fi
  done <<< "$detected_ports"

  for port in "${ports_array[@]}"; do
    if [[ -z "$port" ]]; then
      continue
    fi

    local scheme="http"
    if [[ "$port" == "443" || "$port" == "8443" ]]; then
      scheme="https"
    fi
    local base_url="${scheme}://${target}:${port}"
    run_logged_command "Module WEB / whatweb:${port}" "${REPORT_BASE}/web/whatweb.txt" timeout "$NMAP_WEB_TIMEOUT" whatweb "$base_url"
    run_logged_command "Module WEB / nuclei:${port}" "${REPORT_BASE}/web/nuclei_${port}.txt" timeout "$NMAP_WEB_TIMEOUT" nuclei -u "$base_url" -severity critical,high,medium -o "${REPORT_BASE}/web/nuclei_${port}.txt"
  done
}

scan_full() {
  local nmap_target="$1"
  local nmap_ports="$2"

  echo -e "${BLUE}[*] Module FULL...${NC}"
  scan_fast "$nmap_target" "$nmap_ports"
  scan_vuln "$nmap_target" "$nmap_ports"
  scan_web "$nmap_target" "$nmap_ports"
}

main() {
  if [[ $# -lt 1 ]]; then
    usage
    exit 1
  fi

  TARGET="$1"
  shift

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --fast)
        DO_FAST=1
        shift
        ;;
      --full)
        DO_FULL=1
        shift
        ;;
      --vuln)
        DO_VULN=1
        shift
        ;;
      --web)
        DO_WEB=1
        shift
        ;;
      --ports)
        if [[ -z "${2:-}" ]]; then
          echo "[!] --ports requiert une valeur" >&2
          exit 1
        fi
        PORTS="$2"
        shift 2
        ;;
      --output-dir)
        if [[ -z "${2:-}" ]]; then
          echo "[!] --output-dir requiert une valeur" >&2
          exit 1
        fi
        OUTPUT_DIR="$2"
        shift 2
        ;;
      *)
        echo "[!] Option inconnue: $1" >&2
        usage
        exit 1
        ;;
    esac
  done

  if (( DO_FAST == 0 )) && (( DO_FULL == 0 )) && (( DO_VULN == 0 )) && (( DO_WEB == 0 )); then
    DO_FAST=1
  fi

  validate_ip "$TARGET"
  validate_ports "$PORTS"

  print_banner
  check_dependencies
  init_output

  echo -e "${GREEN}[*] Target: ${TARGET}${NC}"
  if [[ -n "$PORTS" ]]; then
    echo -e "${GREEN}[*] Ports: ${PORTS}${NC}"
  fi

  if (( DO_FAST == 1 )); then
    scan_fast "$TARGET" "$PORTS"
  fi

  if (( DO_VULN == 1 )); then
    scan_vuln "$TARGET" "$PORTS"
  fi

  if (( DO_WEB == 1 )); then
    scan_web "$TARGET" "$PORTS"
  fi

  if (( DO_FULL == 1 )); then
    scan_full "$TARGET" "$PORTS"
  fi

  grep -r -i "exploit\|cve\|rce\|root\|shell\|vuln" "${REPORT_BASE}/" 2>/dev/null | head -50 > "${REPORT_BASE}/exploits/summary.txt" || true

  echo
  if (( FAILED == 1 )); then
    echo "[DONE] SCAN COMPLETE WITH WARNINGS"
  else
    echo "[DONE] SCAN COMPLETE"
  fi
  echo "Reports: ${REPORT_BASE}"
  echo "Exploit summary: ${REPORT_BASE}/exploits/summary.txt"

  if (( FAILED == 1 )); then
    exit 1
  fi
}

main "$@"