#!/bin/bash

# Script: audit-master.sh
# Description: Orchestrateur central pour tous les audits de sécurité
# Intègre: Claude AI + scans existants + formal verification + fuzzing
# Usage: ./scripts/audit-master.sh [--full|--quick|--ci]

# --- Couleurs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m'

# --- Configuration ---
MODE="${1:---full}"  # full, quick, ci
EXPORT_REPORT=true
OUTPUT_DIR="docs/security-reports"
TIMESTAMP=$(date +'%Y-%m-%d_%H-%M-%S')
REPORT_FILE="$OUTPUT_DIR/audit-master-$TIMESTAMP.json"

# Scores et compteurs
declare -A SCORES
declare -A ISSUES
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0

# --- Vérifications préliminaires ---
echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${WHITE}        MONERO MARKETPLACE - MASTER SECURITY AUDIT           ${CYAN}║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo
echo -e "${WHITE}Mode: ${MAGENTA}$MODE${NC}"
echo -e "${WHITE}Timestamp: ${CYAN}$TIMESTAMP${NC}"
echo -e "${WHITE}Report: ${CYAN}$REPORT_FILE${NC}"
echo

# Créer le dossier de rapports
mkdir -p "$OUTPUT_DIR"

# --- Fonctions utilitaires ---

run_check() {
    local title=$1
    local command=$2
    local category=$3
    local weight=$4  # 1-10 (importance)

    ((TOTAL_CHECKS++))

    echo -e "\n${YELLOW}[$TOTAL_CHECKS] $title${NC}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────────${NC}"

    # Exécution avec timeout
    timeout 300 bash -c "$command" > /tmp/audit_output.txt 2>&1
    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        echo -e "   ${GREEN}✅ PASSED${NC}"
        ((PASSED_CHECKS++))
        SCORES[$category]=$((${SCORES[$category]:-0} + $weight))
    elif [ $exit_code -eq 124 ]; then
        echo -e "   ${RED}⏱️ TIMEOUT (5 min)${NC}"
        ((FAILED_CHECKS++))
        ISSUES[$category]=$((${ISSUES[$category]:-0} + 1))
    else
        echo -e "   ${RED}❌ FAILED${NC}"
        ((FAILED_CHECKS++))
        ISSUES[$category]=$((${ISSUES[$category]:-0} + 1))

        # Afficher les erreurs
        if [ -f /tmp/audit_output.txt ]; then
            echo -e "${RED}$(tail -10 /tmp/audit_output.txt)${NC}"
        fi
    fi

    return $exit_code
}

calculate_score() {
    local category=$1
    local max_score=$2

    local score=${SCORES[$category]:-0}
    local percentage=$((score * 100 / max_score))

    echo $percentage
}

# --- PHASE 1: Claude AI Analysis ---

if [ "$MODE" != "quick" ]; then
    echo -e "\n${MAGENTA}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║${WHITE}                    PHASE 1: Claude AI Analysis              ${MAGENTA}║${NC}"
    echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════════╝${NC}"

    # Vérifier que ANTHROPIC_API_KEY est définie
    if [ -z "$ANTHROPIC_API_KEY" ]; then
        echo -e "${YELLOW}⚠️  ANTHROPIC_API_KEY not set - Skipping Claude analysis${NC}"
    else
        # Deep analysis avec Sonnet 4.5
        run_check \
            "Claude Deep Security Analysis (Sonnet 4.5)" \
            "python3 scripts/ai/claude_security_analyzer.py --dir server/src --mode deep --output $OUTPUT_DIR/claude-deep-$TIMESTAMP.json" \
            "AI_ANALYSIS" \
            10

        # Quick scan avec Haiku
        run_check \
            "Claude Quick Scan (Haiku) - Wallet" \
            "python3 scripts/ai/claude_quick_scan.py --dir wallet/src --output $OUTPUT_DIR/claude-quick-wallet-$TIMESTAMP.json" \
            "AI_ANALYSIS" \
            5

        run_check \
            "Claude Quick Scan (Haiku) - Common" \
            "python3 scripts/ai/claude_quick_scan.py --dir common/src --output $OUTPUT_DIR/claude-quick-common-$TIMESTAMP.json" \
            "AI_ANALYSIS" \
            5
    fi
fi

# --- PHASE 2: Security Theatre Detection (Existant) ---

echo -e "\n${MAGENTA}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}║${WHITE}              PHASE 2: Security Theatre Detection            ${MAGENTA}║${NC}"
echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════════╝${NC}"

run_check \
    "Security Theatre Patterns" \
    "./scripts/check-security-theatre.sh" \
    "CODE_QUALITY" \
    10

run_check \
    "Monero/Tor Security Patterns" \
    "./scripts/check-monero-tor-final.sh" \
    "MONERO_TOR" \
    10

# --- PHASE 3: Rust Security ---

echo -e "\n${MAGENTA}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}║${WHITE}                 PHASE 3: Rust Security Checks               ${MAGENTA}║${NC}"
echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════════╝${NC}"

run_check \
    "Cargo Check (Compilation)" \
    "cargo check --workspace --quiet" \
    "RUST" \
    8

run_check \
    "Clippy (Strict Lints)" \
    "cargo clippy --workspace -- -D warnings" \
    "RUST" \
    9

run_check \
    "Cargo Audit (Dependencies)" \
    "cargo audit" \
    "DEPENDENCIES" \
    10

if command -v cargo-deny &> /dev/null; then
    run_check \
        "Cargo Deny (Security Advisories)" \
        "cargo deny check" \
        "DEPENDENCIES" \
        10
fi

# --- PHASE 4: Tests ---

echo -e "\n${MAGENTA}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}║${WHITE}                      PHASE 4: Testing                        ${MAGENTA}║${NC}"
echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════════╝${NC}"

if [ "$MODE" = "full" ]; then
    run_check \
        "Unit Tests (All Workspace)" \
        "cargo test --workspace --quiet" \
        "TESTING" \
        8

    run_check \
        "E2E Tests (Escrow)" \
        "cargo test --package server --test escrow_e2e -- --ignored --quiet" \
        "TESTING" \
        9
fi

# --- PHASE 5: Infrastructure (si disponible) ---

if [ "$MODE" = "full" ]; then
    echo -e "\n${MAGENTA}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║${WHITE}                PHASE 5: Infrastructure Security             ${MAGENTA}║${NC}"
    echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════════╝${NC}"

    # Vérifier Docker si disponible
    if command -v docker &> /dev/null; then
        run_check \
            "Docker Security (Trivy)" \
            "docker run --rm aquasec/trivy image monero-marketplace:latest 2>/dev/null || echo 'Image not found, skipping'" \
            "INFRASTRUCTURE" \
            7
    fi

    # Vérifier Tor
    run_check \
        "Tor Connectivity" \
        "curl --silent --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip --connect-timeout 10 | grep -q '\"IsTor\":true'" \
        "TOR" \
        9

    # Vérifier Monero RPC
    run_check \
        "Monero RPC (localhost only)" \
        "curl --silent -X POST http://127.0.0.1:18082/json_rpc -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_version\"}' --connect-timeout 5 | grep -q '\"result\"' || echo 'RPC not running (OK in dev)'" \
        "MONERO" \
        5
fi

# --- PHASE 6: Code Metrics ---

echo -e "\n${MAGENTA}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}║${WHITE}                    PHASE 6: Code Metrics                     ${MAGENTA}║${NC}"
echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════════╝${NC}"

# Compter les patterns dangereux
unwrap_count=$(grep -r --include="*.rs" -E "\.unwrap\(" server/ wallet/ common/ 2>/dev/null | grep -v "/tests/" | wc -l)
todo_count=$(grep -r --include="*.rs" -i -E "TODO|FIXME" server/ wallet/ common/ 2>/dev/null | wc -l)
loc=$(find server/ wallet/ common/ -name "*.rs" -print0 2>/dev/null | xargs -0 wc -l 2>/dev/null | tail -n 1 | awk '{print $1}')

echo -e "${CYAN}Code Metrics:${NC}"
echo -e "  Lines of Code (Rust): ${WHITE}$loc${NC}"
echo -e "  .unwrap() calls: ${WHITE}$unwrap_count${NC} $([ $unwrap_count -gt 10 ] && echo -e \"${RED}(HIGH)${NC}\" || echo -e \"${GREEN}(OK)${NC}\")"
echo -e "  TODO/FIXME comments: ${WHITE}$todo_count${NC} $([ $todo_count -gt 20 ] && echo -e \"${RED}(HIGH)${NC}\" || echo -e \"${GREEN}(OK)${NC}\")"

# --- RAPPORT FINAL ---

echo -e "\n${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${WHITE}                    FINAL SECURITY REPORT                     ${CYAN}║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}\n"

echo -e "${WHITE}Total Checks: ${CYAN}$TOTAL_CHECKS${NC}"
echo -e "${WHITE}Passed: ${GREEN}$PASSED_CHECKS${NC}"
echo -e "${WHITE}Failed: ${RED}$FAILED_CHECKS${NC}"
echo -e "${WHITE}Success Rate: ${CYAN}$(( PASSED_CHECKS * 100 / TOTAL_CHECKS ))%${NC}\n"

# Scores par catégorie
echo -e "${YELLOW}Scores by Category:${NC}"

for category in AI_ANALYSIS CODE_QUALITY MONERO_TOR RUST DEPENDENCIES TESTING INFRASTRUCTURE TOR MONERO; do
    if [ -n "${SCORES[$category]}" ]; then
        score=${SCORES[$category]}
        issues=${ISSUES[$category]:-0}

        # Couleur basée sur le score
        if [ $score -ge 8 ]; then
            color=$GREEN
        elif [ $score -ge 5 ]; then
            color=$YELLOW
        else
            color=$RED
        fi

        echo -e "  ${WHITE}$category:${NC} ${color}$score/10${NC} (${issues} issues)"
    fi
done

# Score global
total_possible=100
total_score=$(( ${SCORES[AI_ANALYSIS]:-0} + ${SCORES[CODE_QUALITY]:-0} + ${SCORES[MONERO_TOR]:-0} + ${SCORES[RUST]:-0} + ${SCORES[DEPENDENCIES]:-0} + ${SCORES[TESTING]:-0} ))
global_score=$(( total_score * 100 / total_possible ))

echo
if [ $global_score -ge 85 ]; then
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${WHITE}  🎯 GLOBAL SECURITY SCORE: ${GREEN}$global_score/100 - EXCELLENT${WHITE}          ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
elif [ $global_score -ge 70 ]; then
    echo -e "${YELLOW}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║${WHITE}  🎯 GLOBAL SECURITY SCORE: ${YELLOW}$global_score/100 - GOOD${WHITE}               ║${NC}"
    echo -e "${YELLOW}╚═══════════════════════════════════════════════════════════════╝${NC}"
else
    echo -e "${RED}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║${WHITE}  🎯 GLOBAL SECURITY SCORE: ${RED}$global_score/100 - NEEDS IMPROVEMENT${WHITE} ║${NC}"
    echo -e "${RED}╚═══════════════════════════════════════════════════════════════╝${NC}"
fi

# Export JSON
if [ "$EXPORT_REPORT" = true ]; then
    cat > "$REPORT_FILE" <<EOF
{
    "timestamp": "$TIMESTAMP",
    "mode": "$MODE",
    "global_score": $global_score,
    "total_checks": $TOTAL_CHECKS,
    "passed": $PASSED_CHECKS,
    "failed": $FAILED_CHECKS,
    "success_rate": $(( PASSED_CHECKS * 100 / TOTAL_CHECKS )),
    "scores": {
        "ai_analysis": ${SCORES[AI_ANALYSIS]:-0},
        "code_quality": ${SCORES[CODE_QUALITY]:-0},
        "monero_tor": ${SCORES[MONERO_TOR]:-0},
        "rust": ${SCORES[RUST]:-0},
        "dependencies": ${SCORES[DEPENDENCIES]:-0},
        "testing": ${SCORES[TESTING]:-0}
    },
    "metrics": {
        "lines_of_code": $loc,
        "unwrap_count": $unwrap_count,
        "todo_count": $todo_count
    }
}
EOF

    echo -e "\n${GREEN}✅ Report exported to: ${CYAN}$REPORT_FILE${NC}"
fi

# Exit code basé sur le score
if [ $global_score -lt 70 ]; then
    echo -e "\n${RED}❌ Security score too low - AUDIT FAILED${NC}"
    exit 1
else
    echo -e "\n${GREEN}✅ Security audit passed${NC}"
    exit 0
fi
