#!/bin/bash

# Script: security-dashboard.sh
# Description: Affiche un tableau de bord de sécurité complet pour le projet.

# --- Configuration des couleurs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# --- Paramètres par défaut ---
LIVE_MODE=false
REFRESH_INTERVAL=30
EXPORT_REPORT=false
OUTPUT_PATH="docs/security-reports"

# --- Parsing des arguments avec getopts ---
while getopts ":lr:eo:" opt; do
  case $opt in
    l) LIVE_MODE=true ;;
    r) REFRESH_INTERVAL=$OPTARG ;;
    e) EXPORT_REPORT=true ;;
    o) OUTPUT_PATH=$OPTARG ;;
    \?) echo "Usage: $0 [-l] [-r interval] [-e] [-o path]" >&2; exit 1 ;;
  esac
done

# --- Fonctions de collecte et d'affichage ---

# Affiche le header
show_header() {
    clear
    echo -e "${RED}🔒 MONERO MARKETPLACE - SECURITY DASHBOARD${NC}"
    echo -e "${RED}=============================================${NC}"
    echo -e "${WHITE}Timestamp: $(date +'%Y-%m-%d %H:%M:%S')${NC}"
    echo
}

# Affiche les métriques de code
display_code_metrics() {
    echo -e "${CYAN}📊 CODE METRICS${NC}"
    echo -e "${CYAN}===============${NC}"
    loc=$(find src/ -name '*.rs' -print0 | xargs -0 wc -l | tail -n 1 | awk '{print $1}')
    functions=$(grep -r -h --include="*.rs" -E "fn\s+\w+\s*\(" src/ | wc -l)
    tests=$(find tests/ -name '*.rs' 2>/dev/null | wc -l)
    specs=$(find docs/specs -name "*.md" 2>/dev/null | wc -l)
    
    echo -e "  ${WHITE}Lignes de code: $loc${NC}"
    echo -e "  ${WHITE}Fonctions: $functions${NC}"
    echo -e "  ${WHITE}Tests: $tests${NC}"
    echo -e "  ${WHITE}Specs: $specs${NC}"
    echo
}

# Calcule et affiche le score de sécurité
display_security_score() {
    echo -e "${CYAN}🛡️ SECURITY SCORE${NC}"
    echo -e "${CYAN}=================${NC}"
    local score=100
    local issues=()

    local unwraps=$(grep -r --include="*.rs" -E "\.unwrap\s*\(" src/ | wc -l)
    if [ $unwraps -gt 0 ]; then ((score-=20)); issues+=("Unwraps: $unwraps"); fi

    local todos=$(grep -r --include="*.rs" -i -E "TODO|FIXME" src/ | wc -l)
    if [ $todos -gt 5 ]; then ((score-=10)); issues+=("TODOs: $todos"); fi
    
    local functions=$(grep -r -h --include="*.rs" -E "fn\s+\w+\s*\(" src/ | wc -l)
    local specs=$(find docs/specs -name "*.md" 2>/dev/null | wc -l)
    if [ $functions -gt $specs ]; then ((score-=15)); issues+=("Fonctions sans spec: $((functions - specs))"); fi

    if [ $score -lt 0 ]; then score=0; fi

    local level="Critique"
    local color=$RED
    if [ $score -ge 90 ]; then level="Excellent"; color=$GREEN;
elif [ $score -ge 70 ]; then level="Bon"; color=$WHITE;
elif [ $score -ge 50 ]; then level="Moyen"; color=$YELLOW; fi

    echo -e "  ${color}Score: $score/100${NC}"
    echo -e "  ${color}Niveau: $level${NC}"

    if [ ${#issues[@]} -gt 0 ]; then
        echo -e "  ${YELLOW}Problèmes:${NC}"
        for issue in "${issues[@]}"; do
            echo -e "    ${YELLOW}- $issue${NC}"
        done
    else
        echo -e "  ${GREEN}✅ Aucun problème détecté${NC}"
    fi
    echo
}

# Affiche le statut de Tor
display_tor_status() {
    echo -e "${CYAN}🧅 TOR STATUS${NC}"
    echo -e "${CYAN}=============${NC}"
    response=$(curl --silent --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip --connect-timeout 5)
    if [[ $(echo "$response" | jq -r '.IsTor') == "true" ]]; then
        echo -e "  ${GREEN}Statut: Connecté${NC}"
        echo -e "  ${WHITE}IP: $(echo "$response" | jq -r '.IP')${NC}"
    else
        echo -e "  ${RED}Statut: Non connecté ou erreur${NC}"
    fi
    echo
}

# Affiche le statut du RPC Monero
display_monero_rpc_status() {
    echo -e "${CYAN}💰 MONERO RPC STATUS${NC}"
    echo -e "${CYAN}====================${NC}"
    response=$(curl --silent -X POST http://127.0.0.1:18082/json_rpc -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' --connect-timeout 5)
    if [[ $response == *"result"* ]]; then
        echo -e "  ${GREEN}Statut: Connecté${NC}"
        echo -e "  ${WHITE}Version: $(echo $response | jq -r '.result.version')${NC}"
    else
        echo -e "  ${RED}Statut: Non accessible${NC}"
    fi
    echo
}

# --- Fonction principale du tableau de bord ---
show_dashboard() {
    show_header
    display_code_metrics
    display_security_score
    display_tor_status
    display_monero_rpc_status
    # L'exportation et les alertes pourraient être ajoutées ici
    echo -e "${WHITE}=============================================${NC}"
    if [ "$LIVE_MODE" = true ]; then
        echo -e "${WHITE}Mode live actif. Rafraîchissement toutes les ${REFRESH_INTERVAL}s. Pressez Ctrl+C pour quitter.${NC}"
    fi
}

# --- Logique d'exécution ---
if [ "$LIVE_MODE" = true ]; then
    while true; do
        show_dashboard
        sleep $REFRESH_INTERVAL
    done
else
    show_dashboard
fi

# La logique d'exportation pourrait être appelée ici si -e est passé
