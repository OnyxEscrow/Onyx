#!/bin/bash

# Script: security-alerts.sh
# Description: Exécute des vérifications de sécurité et envoie des alertes.
# Usage: ./scripts/security-alerts.sh [-t] [-w <webhook_url>] [-e <email>]

# --- Couleurs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

# --- Paramètres ---
TEST_MODE=false
WEBHOOK_URL=""
EMAIL=""

while getopts ":tw:e:" opt; do
  case $opt in
    t) TEST_MODE=true ;;
    w) WEBHOOK_URL=$OPTARG ;;
    e) EMAIL=$OPTARG ;;
    \?) echo "Usage: $0 [-t] [-w webhook_url] [-e email]" >&2; exit 1 ;;
  esac
done

# --- Vérifications ---
alerts=()

# 1. Security Theatre Check
if [ -f "./scripts/check-security-theatre-simple.sh" ]; then
    ./scripts/check-security-theatre-simple.sh &> /dev/null
    if [ $? -ne 0 ]; then
        alerts+=("🚨 "Security theatre" détecté dans le code")
    fi
fi

# 2. Vérifier les unwraps
unwraps=$(grep -r --include="*.rs" -E "\\.unwrap\\s*\\(" src/ | wc -l)
if [ $unwraps -gt 0 ]; then
    alerts+=("⚠️ $unwraps unwrap() trouvé(s) dans le code de production")
fi

# 3. Vérifier les TODOs
todos=$(grep -r --include="*.rs" -i -E "TODO|FIXME" src/ | wc -l)
if [ $todos -gt 10 ]; then
    alerts+=("📝 $todos TODO/FIXME nécessitent une attention")
fi

# 4. Vérifier les fonctions sans specs
functions=$(grep -r -h --include="*.rs" -E "fn\\s+\\w+\\s*\(" src/ | wc -l)
specs=$(find docs/specs -name "*.md" 2>/dev/null | wc -l)
if [ $functions -gt $specs ]; then
    functions_without_spec=$((functions - specs))
    alerts+=("📋 $functions_without_spec fonction(s) sans spec")
fi

# --- Envoi des alertes ---
if [ ${#alerts[@]} -gt 0 ]; then
    # Construire le message
    message="🔒 Alertes de Sécurité Monero Marketplace\n\n"
    for alert in "${alerts[@]}"; do
        message+="- $alert\n"
    done

    echo -e "${YELLOW}Envoi de ${#alerts[@]} alerte(s) de sécurité...${NC}"

    if [ "$TEST_MODE" = true ]; then
        echo -e "${RED}--- MODE TEST ---${NC}"
        echo -e "$message"
        echo -e "${RED}-----------------${NC}"
    fi

    if [ -n "$WEBHOOK_URL" ]; then
        echo "Envoi vers Webhook..."
        # Formatter pour JSON, en échappant les nouvelles lignes
        json_message=$(echo -e "$message" | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')
        curl -X POST -H "Content-Type: application/json" -d "{\"text\":\"$json_message\"}" "$WEBHOOK_URL"
    fi

    if [ -n "$EMAIL" ]; then
        echo "Envoi par e-mail..."
        echo -e "$message" | mail -s "Alerte de Sécurité - Monero Marketplace" "$EMAIL"
    fi

else
    echo -e "${GREEN}✅ Aucune alerte de sécurité.${NC}"
fi
