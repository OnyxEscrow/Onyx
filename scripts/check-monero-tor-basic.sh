#!/bin/bash

# Script: check-monero-tor-basic.sh
# Description: Détecte des motifs de sécurité Monero/Tor avec analyse de contexte.

# --- Couleurs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
WHITE='\033[1;37m'
NC='\033[0m'

# --- Initialisation ---
echo -e "${CYAN}Monero/Tor Security Check (Basic)${NC}"
echo -e "${CYAN}==================================${NC}"
echo

issues=()

# --- Fonctions de vérification ---

# 1. Vérifier RPC exposé publiquement (hors tests)
check_exposed_rpc() {
    local count=0
    # Grep pour le motif et le fichier/numéro de ligne
    grep -n -r "0\.0\.0\.0.*18082" src/ --include="*.rs" | while IFS= read -r line; do
        local file=$(echo "$line" | cut -d: -f1)
        local line_num=$(echo "$line" | cut -d: -f2)
        
        # Vérifier si on est dans un bloc de test (10 lignes avant)
        local start_line=$((line_num - 10))
        [ $start_line -lt 1 ] && start_line=1
        
        if ! sed -n "${start_line},${line_num}p" "$file" | grep -q -E '#\[.*test.*\]|fn.*test|async fn.*test'; then
            ((count++))
        fi
    done
    if [ $count -gt 0 ]; then
        issues+=("RPC exposed publicly: $count occurrences")
    fi
}

# 2. Vérifier les connexions directes
check_direct_connections() {
    local count=$(grep -r "reqwest::get" src/ --include="*.rs" | wc -l)
    if [ $count -gt 0 ]; then
        issues+=("Direct HTTP connections: $count occurrences")
    fi
}

# 3. Vérifier les adresses .onion loggées
check_onion_logged() {
    local count=$(grep -r "\\.onion" src/ --include="*.rs" | wc -l)
    if [ $count -gt 0 ]; then
        issues+=("Onion addresses logged: $count occurrences")
    fi
}

# 4. Vérifier les IPs loggées (hors constantes et tests)
check_ips_logged() {
    # Exclut les lignes contenant const, test, assert, //, localhost
    local count=$(grep -r -E "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}" src/ --include="*.rs" \
        | grep -v -E 'const|test|assert|//|localhost' | wc -l)
    if [ $count -gt 0 ]; then
        issues+=("IP addresses logged: $count occurrences")
    fi
}

# 5. Vérifier les credentials hardcodés
check_hardcoded_creds() {
    local count=$(grep -r "password.*=" src/ --include="*.rs" | wc -l)
    if [ $count -gt 0 ]; then
        issues+=("Hardcoded credentials: $count occurrences")
    fi
}

# --- Exécution des checks ---
check_exposed_rpc
check_direct_connections
check_onion_logged
check_ips_logged
check_hardcoded_creds

# --- Affichage des résultats ---
if [ ${#issues[@]} -eq 0 ]; then
    echo -e "${GREEN}✅ No Monero/Tor security issues detected${NC}"
    echo
    echo -e "${GREEN}Security check completed${NC}"
    exit 0
else
    echo -e "${RED}❌ Monero/Tor security issues detected:${NC}"
    for issue in "${issues[@]}"; do
        echo -e "  ${RED}- $issue${NC}"
    done
    echo
    echo -e "${YELLOW}Recommendations:${NC}"
    echo -e "  ${WHITE}1. Use localhost-only RPC binding (127.0.0.1)${NC}"
    echo -e "  ${WHITE}2. Use SOCKS5 proxy for external connections${NC}"
    echo -e "  ${WHITE}3. Never log .onion addresses or IPs${NC}"
    echo -e "  ${WHITE}4. Use environment variables for credentials${NC}"
    exit 1
fi
