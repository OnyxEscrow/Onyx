#!/bin/bash

# Script: metrics-dashboard.sh
# Description: Affiche un tableau de bord complet des métriques du projet.

# --- Couleurs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# --- Fonctions d'aide ---

# Compte les lignes d'un motif dans les fichiers Rust
count_lines() {
    grep -r -h --include="*.rs" -E "$1" src/ | wc -l
}

# --- Début du tableau de bord ---
echo -e "${CYAN}📊 Monero Marketplace - Metrics Dashboard${NC}"
echo -e "${CYAN}========================================${NC}"
echo

# --- 1. Métriques de Code ---
echo -e "${YELLOW}📝 Métriques de Code${NC}"
loc=$(find src/ -name '*.rs' -print0 | xargs -0 wc -l | tail -n 1 | awk '{print $1}')
functions=$(count_lines "pub (async )?fn \w+")
specs=$(find docs/specs -name "*.md" 2>/dev/null | wc -l)
functions_without_spec=$(($functions - $specs))
unwraps=$(count_lines "\.unwrap\(")
todos=$(grep -r -h --include="*.rs" -i -E "TODO|FIXME" src/ | wc -l)

echo -e "  ${WHITE}Lignes de code: $loc${NC}"
echo -e "  ${WHITE}Fonctions: $functions${NC}"
echo -e "  ${WHITE}Specs: $specs${NC}"
echo -e "  ${WHITE}Fonctions sans spec: $functions_without_spec${NC}"
[ $unwraps -eq 0 ] && echo -e "  ${GREEN}Unwraps: $unwraps ✅${NC}" || echo -e "  ${YELLOW}Unwraps: $unwraps ⚠️${NC}"
echo -e "  ${WHITE}TODOs: $todos${NC}"
echo

# --- 2. Métriques Tor ---
echo -e "${YELLOW}🧅 Métriques Tor${NC}"
if pgrep -x "tor" > /dev/null; then
    tor_running=true
    echo -e "  ${GREEN}Démon Tor: ✅ Actif${NC}"
    # Test de connexion
    response=$(curl --silent --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip --connect-timeout 10)
    if [[ $(echo "$response" | jq -r '.IsTor') == "true" ]]; then
        tor_ip=$(echo "$response" | jq -r '.IP')
        echo -e "  ${GREEN}Connexion Tor: ✅ Active (IP de sortie: $tor_ip)${NC}"
    else
        echo -e "  ${RED}Connexion Tor: ❌ Échouée${NC}"
    fi
    tor_rc=$(find docs/reality-checks -name "tor-*.md" 2>/dev/null | wc -l)
    echo -e "  ${WHITE}Reality Checks Tor: $tor_rc${NC}"
else
    tor_running=false
    echo -e "  ${RED}Démon Tor: ❌ Inactif${NC}"
fi
echo

# --- 3. Métriques Monero ---
echo -e "${YELLOW}💰 Métriques Monero${NC}"
if pgrep -x "monerod" > /dev/null; then echo -e "  ${GREEN}Démon Monero: ✅ Actif${NC}"; else echo -e "  ${RED}Démon Monero: ❌ Inactif${NC}"; fi

if pgrep -x "monero-wallet-rpc" > /dev/null; then
    echo -e "  ${GREEN}Wallet RPC: ✅ Actif${NC}"
    rpc_response=$(curl --silent -X POST http://127.0.0.1:18082/json_rpc -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' --connect-timeout 5)
    if [[ $rpc_response == *"result"* ]]; then
        echo -e "  ${GREEN}Accès RPC: ✅${NC}"
    else
        echo -e "  ${RED}Accès RPC: ❌${NC}"
    fi
    # Vérification de l'isolation
    if netstat -an | grep "LISTEN" | grep -q "0\.0\.0\.0:18082"; then
        rpc_exposed=true
        echo -e "  ${RED}Isolation RPC: ⚠️ EXPOSÉ PUBLIQUEMENT!${NC}"
    elif netstat -an | grep "LISTEN" | grep -q "127\.0\.0\.1:18082"; then
        rpc_exposed=false
        echo -e "  ${GREEN}Isolation RPC: ✅ Localhost uniquement${NC}"
    fi
else
    rpc_exposed=false # Ne peut pas être exposé s'il ne tourne pas
    echo -e "  ${RED}Wallet RPC: ❌ Inactif${NC}"
fi
echo

# --- 4. Résultats des Tests ---
echo -e "${YELLOW}🧪 Résultats des Tests${NC}"
test_output=$(cargo test --workspace 2>&1)
if [[ $test_output =~ ([0-9]+) passed ]]; then
    echo -e "  ${GREEN}Tests Passés: ${BASH_REMATCH[1]} ✅${NC}"
else
    echo -e "  ${RED}Tests: ❌ Non exécutés ou échoués${NC}"
fi
echo

# --- 5. Security Score ---
echo -e "${YELLOW}🔒 Statut de Sécurité${NC}"
security_score=100
issues=()

# Pénalités
if [ $unwraps -gt 0 ]; then ((security_score-=20)); issues+=("- $unwraps unwrap() trouvés ⚠️"); fi
if [ "$rpc_exposed" = true ]; then ((security_score-=50)); issues+=("- RPC exposé publiquement 🚨"); fi
if [ "$tor_running" = false ]; then ((security_score-=10)); issues+=("- Tor n'est pas actif ⚠️"); fi
if [ $functions -gt $specs ]; then ((security_score-=10)); issues+=("- $functions_without_spec fonction(s) sans spec ⚠️"); fi

# Affichage du score
color=$RED
if [ $security_score -ge 90 ]; then color=$GREEN;
elif [ $security_score -ge 70 ]; then color=$YELLOW; fi
echo -e "  ${color}Score de Sécurité: $security_score/100${NC}"

if [ $security_score -lt 100 ]; then
    echo -e "\n  ${YELLOW}Problèmes détectés:${NC}"
    for issue in "${issues[@]}"; do
        echo -e "    ${YELLOW}$issue${NC}"
    done
fi
echo

# --- Fin ---
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}Dernière mise à jour: $(date +'%Y-%m-%d %H:%M')${NC}"
