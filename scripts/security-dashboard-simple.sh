#!/bin/bash

# Script: security-dashboard-simple.sh
# Description: Affiche un tableau de bord de sécurité simplifié.

# --- Couleurs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# --- Header ---
clear
echo -e "${RED}🔒 MONERO MARKETPLACE - SECURITY DASHBOARD (Simple)${NC}"
echo -e "${RED}==================================================${NC}"
echo -e "${WHITE}Timestamp: $(date +'%Y-%m-%d %H:%M:%S')${NC}"
echo

# --- 1. Security Theatre Check ---
echo -e "${YELLOW}🎭 SECURITY THEATRE CHECK${NC}"
echo -e "${YELLOW}=========================${NC}"
if [ -f "./scripts/check-security-theatre-simple.sh" ]; then
    ./scripts/check-security-theatre-simple.sh &> /dev/null
    if [ $? -eq 0 ]; then
        echo -e "  ${GREEN}✅ Aucun \"security theatre\" détecté${NC}"
    else
        echo -e "  ${RED}❌ \"Security theatre\" détecté !${NC}"
    fi
else
    echo -e "  ${YELLOW}⚠️ Script de vérification non trouvé${NC}"
fi
echo

# --- 2. Métriques de Code ---
echo -e "${CYAN}📊 CODE METRICS${NC}"
echo -e "${CYAN}===============${NC}"
loc=$(find src/ -name '*.rs' -print0 | xargs -0 wc -l | tail -n 1 | awk '{print $1}')
functions=$(grep -r -h --include="*.rs" -E "fn\s+\w+\s*\(" src/ | wc -l)
tests=$(find tests/ -name '*.rs' 2>/dev/null | wc -l)
specs=$(find docs/specs -name "*.md" 2>/dev/null | wc -l)
reality_checks=$(find docs/reality-checks -name "*.md" 2>/dev/null | wc -l)
echo -e "  ${WHITE}Lignes de code: $loc${NC}"
echo -e "  ${WHITE}Fonctions: $functions${NC}"
echo -e "  ${WHITE}Tests: $tests${NC}"
echo -e "  ${WHITE}Specs: $specs${NC}
echo -e "  ${WHITE}Reality Checks: $reality_checks${NC}"
echo

# --- 3. Security Score ---
echo -e "${YELLOW}🛡️ SECURITY SCORE${NC}"
echo -e "${YELLOW}=================${NC}"
score=100
issues=()
unwraps=$(grep -r --include="*.rs" -E "\.unwrap\s*\(" src/ | wc -l)
if [ $unwraps -gt 0 ]; then ((score-=20)); issues+=("Unwraps: $unwraps"); fi
todos=$(grep -r --include="*.rs" -i -E "TODO|FIXME" src/ | wc -l)
if [ $todos -gt 5 ]; then ((score-=10)); issues+=("TODOs: $todos"); fi
if [ $functions -gt $specs ]; then ((score-=15)); issues+=("Fonctions sans spec: $((functions - specs))"); fi
if [ $tests -lt 3 ]; then ((score-=10)); issues+=("Tests insuffisants: $tests"); fi
if [ $score -lt 0 ]; then score=0; fi

level="Critique"; color=$RED
if [ $score -ge 90 ]; then level="Excellent"; color=$GREEN;
elif [ $score -ge 70 ]; then level="Bon"; color=$YELLOW;
elif [ $score -ge 50 ]; then level="Moyen"; color=$YELLOW; fi
echo -e "  ${color}Score: $score/100 ($level)${NC}"
if [ ${#issues[@]} -gt 0 ]; then
    echo -e "  ${YELLOW}Problèmes:${NC}"
    for issue in "${issues[@]}"; do echo -e "    - $issue"; done
else
    echo -e "  ${GREEN}✅ Aucun problème détecté${NC}"
fi
echo

# --- 4. Tor Status ---
echo -e "${CYAN}🧅 TOR STATUS${NC}"
echo -e "${CYAN}=============${NC}"
response_tor=$(curl --silent --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip --connect-timeout 5)
if [[ $(echo "$response_tor" | jq -r '.IsTor') == "true" ]]; then
    echo -e "  ${GREEN}✅ Connecté via Tor${NC}"
else
    echo -e "  ${RED}❌ Non connecté via Tor${NC}"
fi
echo

# --- 5. Monero RPC Status ---
echo -e "${CYAN}💰 MONERO RPC STATUS${NC}"
echo -e "${CYAN}====================${NC}"
response_rpc=$(curl --silent -X POST http://127.0.0.1:18082/json_rpc -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' --connect-timeout 5)
if [[ $response_rpc == *"result"* ]]; then
    echo -e "  ${GREEN}✅ Monero RPC connecté${NC}"
else
    echo -e "  ${RED}❌ La connexion au RPC Monero a échoué${NC}"
fi
echo

# --- 6. Alerts ---
echo -e "${RED}🚨 ALERTS${NC}"
echo -e "${RED}=========${NC}"
alerts=()
if [ $score -lt 70 ]; then alerts+=("Le score de sécurité est en dessous de 70%"); fi
if [ $unwraps -gt 0 ]; then alerts+=("$unwraps unwrap() trouvé(s) dans le code"); fi
if [ $functions -gt $specs ]; then alerts+=("$((functions - specs)) fonction(s) sans spec"); fi

if [ ${#alerts[@]} -gt 0 ]; then
    for alert in "${alerts[@]}"; do echo -e "  ${RED}⚠️ $alert${NC}"; done
else
    echo -e "  ${GREEN}✅ Aucune alerte${NC}"
fi
echo
