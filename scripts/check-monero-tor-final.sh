#!/bin/bash

# Script: check-monero-tor-final.sh
# Description: Détecte les motifs de sécurité Monero/Tor (vérification finale simple).

# --- Couleurs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
WHITE='\033[1;37m'
NC='\033[0m'

# --- Initialisation ---
echo -e "${CYAN}Monero/Tor Security Check (Final)${NC}"
echo -e "${CYAN}==================================${NC}"
echo

issues=()

# --- Exécution des checks ---

# 1. Vérifier RPC exposé publiquement (hors tests)
count_rpc=$(grep -r "0\.0\.0\.0" src/ --include="*.rs" | grep -v -E "test|assert" | wc -l)
if [ $count_rpc -gt 0 ]; then
    issues+=("RPC exposed publicly: $count_rpc occurrences")
fi

# 2. Vérifier les connexions directes
count_direct=$(grep -r "reqwest::get" src/ --include="*.rs" | wc -l)
if [ $count_direct -gt 0 ]; then
    issues+=("Direct HTTP connections: $count_direct occurrences")
fi

# 3. Vérifier les adresses .onion loggées
count_onion=$(grep -r "\\.onion" src/ --include="*.rs" | wc -l)
if [ $count_onion -gt 0 ]; then
    issues+=("Onion addresses logged: $count_onion occurrences")
fi

# 4. Vérifier les IPs non-localhost (hors constantes et tests)
count_ips=$(grep -r -E "192\\.168\\.|10\\.|172\." src/ --include="*.rs" | grep -v -E "const|test" | wc -l)
if [ $count_ips -gt 0 ]; then
    issues+=("Non-localhost IPs: $count_ips occurrences")
fi

# 5. Vérifier les credentials hardcodés (hors tests)
count_creds=$(grep -r "password.*=" src/ --include="*.rs" | grep -v "test" | wc -l)
if [ $count_creds -gt 0 ]; then
    issues+=("Hardcoded credentials: $count_creds occurrences")
fi

# --- Affichage des résultats ---
if [ ${#issues[@]} -eq 0 ]; then
    echo -e "${GREEN}✅ No Monero/Tor security issues detected${NC}"
    echo
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
    echo
    echo -e "${RED}❌ COMMIT BLOCKED - Fix Monero/Tor security issues first${NC}"
    exit 1
fi
