#!/bin/bash

# Script: security-alerts-basic.sh
# Description: Exécute des vérifications de sécurité et affiche les alertes en console.

# --- Couleurs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

# --- Vérifications ---
alerts=()

# 1. Security Theatre Check
if [ -f "./scripts/check-security-theatre-simple.sh" ]; then
    ./scripts/check-security-theatre-simple.sh &> /dev/null
    if [ $? -ne 0 ]; then
        alerts+=("Security theatre détecté dans le code")
    fi
fi

# 2. Vérifier les unwraps
unwraps=$(grep -r --include="*.rs" -E "\\.unwrap\\s*\\(" src/ | wc -l)
if [ $unwraps -gt 0 ]; then
    alerts+=("$unwraps unwrap() trouvé(s) dans le code de production")
fi

# 3. Vérifier les TODOs
todos=$(grep -r --include="*.rs" -i -E "TODO|FIXME" src/ | wc -l)
if [ $todos -gt 10 ]; then
    alerts+=("$todos TODO/FIXME nécessitent une attention")
fi

# 4. Vérifier les fonctions sans specs
functions=$(grep -r -h --include="*.rs" -E "fn\\s+\\w+\\s*\(" src/ | wc -l)
specs=$(find docs/specs -name "*.md" 2>/dev/null | wc -l)
if [ $functions -gt $specs ]; then
    functions_without_spec=$((functions - specs))
    alerts+=("$functions_without_spec fonction(s) sans spec")
fi

# --- Affichage des alertes ---
if [ ${#alerts[@]} -gt 0 ]; then
    echo -e "${RED}ALERTES DE SÉCURITÉ :${NC}"
    for alert in "${alerts[@]}"; do
        echo -e "  ${RED}- $alert${NC}"
    done
    echo -e "${YELLOW}Total des alertes: ${#alerts[@]}${NC}"
else
    echo -e "${GREEN}Aucune alerte de sécurité.${NC}"
fi
