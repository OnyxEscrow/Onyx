#!/bin/bash

# Script: validate-reality-check-tor.sh
# Valide un reality check Tor avant le merge en production.
# Dépendance: jq
# Usage: ./scripts/validate-reality-check-tor.sh <function_name>

# --- Couleurs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Vérification des dépendances ---
if ! command -v jq &> /dev/null; then
    echo -e "${RED}ERREUR: 'jq' n'est pas installé. Veuillez l'installer pour continuer.${NC}"
    exit 1
fi

# --- Vérification des arguments ---
if [ -z "$1" ]; then
    echo -e "${RED}ERREUR: Nom de la fonction manquant.${NC}"
    echo "Usage: $0 <function_name>"
    exit 1
fi

FunctionName=$1

# --- Chemin du fichier ---
date=$(date +"%Y-%m-%d")
check_path="docs/reality-checks/tor-$FunctionName-$date.md"

if [ ! -f "$check_path" ]; then
    echo -e "${RED}Reality check Tor non trouvé: $check_path${NC}"
    exit 1
fi

echo -e "${CYAN}Validation du Reality Check TOR pour: $FunctionName${NC}"
echo

# --- Extraction des métadonnées ---
json_content=$(sed -n '/^```json/,/^```/p' "$check_path" | sed '1d;$d')

if [ -z "$json_content" ]; then
    echo -e "${YELLOW}Metadata JSON non trouvées dans le rapport.${NC}"
    critical_issues=999
    auto_tests_passed="false"
else
    critical_issues=$(echo "$json_content" | jq '.critical_issues')
    auto_tests_passed=$(echo "$json_content" | jq '.auto_tests_passed')
fi

# --- Variables de validation ---
all_valid=true
blockers_count=0

# --- Fonction de vérification ---
# Usage: run_check "Description du check" "is_blocker" "commande_grep"
run_check() {
    local description=$1
    local is_blocker=$2
    local command_result

    # Exécute la commande grep passée en argument
    if eval "$3"; then
        command_result=0 # Success
    else
        command_result=1 # Failure
    fi

    if [ $command_result -eq 0 ]; then
        echo -e "  ${GREEN}OK  ${NC} $description"
    else
        echo -e "  ${RED}FAIL${NC} $description"
        all_valid=false
        if [ "$is_blocker" == "true" ]; then
            ((blockers_count++))
        fi
    fi
}

# --- Exécution des vérifications ---
echo -e "${CYAN}Vérifications obligatoires:${NC}"
run_check "Tests auto passés" "true" "[ \"$auto_tests_passed\" == \"true\" ]"
run_check "Issues critiques = 0" "true" "[ \"$critical_issues\" -eq 0 ]"
run_check "Test DNS leak complété" "false" "grep -q '\\[x\\].*DNS via Tor uniquement' \"$check_path\""
run_check "Test fingerprint complété" "false" "grep -q '\\[x\\].*Fingerprint anonyme' \"$check_path\""
run_check "Décision prise" "true" "grep -q '\\[x\\].*\\*\\*\\(\\APPROUVÉ\\|\\CONDITIONNEL\\|\\REJETÉ\\)\\\*\\*\' \"$check_path\""
run_check "Signature présente" "false" "grep -q 'Testé par:.*\\[[^\\]]+\\]' \"$check_path\" && ! grep -q 'Testé par:.*\\[Nom\\]' \"$check_path\""
run_check "Checklist finale complétée" "false" "grep -q '\\[x\\].*Tous les tests auto passent' \"$check_path\" && grep -q '\\[x\\].*Tests manuels complétés' \"$check_path\""

echo
echo -e "${CYAN}Vérifications de la décision:${NC}"
run_check "Justification présente" "true" "grep -q 'Justification' \"$check_path\" && ! grep -q '\[Expliquer' \"$check_path\""

# Vérification conditionnelle pour les actions requises
if grep -q "CONDITIONNEL\|REJETÉ" "$check_path"; then
    run_check "Actions requises listées" "true" "grep -q 'Actions Requises' \"$check_path\" && grep -q '\[Action' \"$check_path\""
fi

echo

# --- Résultat final ---
if [ $blockers_count -eq 0 ] && [ "$all_valid" == "true" ]; then
    echo -e "${GREEN}VALIDATION RÉUSSIE${NC}"
    echo
    echo -e "${GREEN}Reality Check Tor complet et valide.${NC}"
    echo -e "${GREEN}Issues critiques: $critical_issues OK${NC}"
    echo
    echo -e "${CYAN}Prêt pour merge en production Tor.${NC}"
    
    # Marquer comme valide dans le fichier
    sed -i 's/Status:.*$/Status: [x] Valide pour production/' "$check_path"
    exit 0
elif [ $blockers_count -gt 0 ]; then
    echo -e "${RED}VALIDATION ÉCHOUÉE - $blockers_count BLOCKER(S)${NC}"
    echo
    echo -e "${RED}Issues critiques détectées: $critical_issues${NC}"
    echo
    echo -e "${RED}NE PAS MERGER EN PRODUCTION${NC}"
    echo -e "${YELLOW}Corrigez les issues critiques dans: $check_path${NC}"
    exit 1
else
    echo -e "${YELLOW}VALIDATION PARTIELLE${NC}"
    echo
    echo -e "${YELLOW}Complétez les sections manquantes avant le merge.${NC}"
    echo -e "${CYAN}Fichier: $check_path${NC}"
    exit 2
fi
