#!/bin/bash

# Script: security-dashboard-basic.sh
# Description: Affiche un tableau de bord de sécurité basique (analyse statique uniquement).

# --- Couleurs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# --- Header ---
clear
echo -e "${RED}🔒 MONERO MARKETPLACE - SECURITY DASHBOARD (Basic)${NC}"
echo -e "${RED}==================================================${NC}"
echo

# --- 1. Security Theatre Check ---
echo -e "${YELLOW}🎭 SECURITY THEATRE CHECK${NC}"
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
loc=$(find src/ -name '*.rs' -print0 | xargs -0 wc -l | tail -n 1 | awk '{print $1}')
functions=$(grep -r -h --include="*.rs" -E "fn\s+\w+\s*\(" src/ | wc -l)
tests=$(find tests/ -name '*.rs' 2>/dev/null | wc -l)
specs=$(find docs/specs -name "*.md" 2>/dev/null | wc -l)
echo -e "  ${WHITE}Lignes de code: $loc${NC}"
echo -e "  ${WHITE}Fonctions: $functions${NC}"
echo -e "  ${WHITE}Tests: $tests${NC}"
echo -e "  ${WHITE}Specs: $specs${NC}"
echo

# --- 3. Security Score ---
echo -e "${YELLOW}🛡️ SECURITY SCORE${NC}"
score=100
issues=()
unwraps=$(grep -r --include="*.rs" -E "\.unwrap\s*\(" src/ | wc -l)
if [ $unwraps -gt 0 ]; then ((score-=20)); issues+=("Unwraps: $unwraps"); fi
todos=$(grep -r --include="*.rs" -i -E "TODO|FIXME" src/ | wc -l)
if [ $todos -gt 5 ]; then ((score-=10)); issues+=("TODOs: $todos"); fi
if [ $functions -gt $specs ]; then ((score-=15)); issues+=("Fonctions sans spec: $((functions - specs))"); fi
if [ $score -lt 0 ]; then score=0; fi

level="Critique"; color=$RED
if [ $score -ge 90 ]; then level="Excellent"; color=$GREEN;
elif [ $score -ge 70 ]; then level="Bon"; color=$YELLOW; fi
echo -e "  ${color}Score: $score/100 ($level)${NC}"
if [ ${#issues[@]} -gt 0 ]; then
    echo -e "  ${YELLOW}Problèmes:${NC}"
    for issue in "${issues[@]}"; do echo -e "    - $issue"; done
else
    echo -e "  ${GREEN}✅ Aucun problème détecté${NC}"
fi
echo

echo -e "${WHITE}Dashboard terminé.${NC}"
