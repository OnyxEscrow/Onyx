#!/bin/bash

# Script: validate-github-workflows.sh
# Description: Valide les workflows GitHub Actions du projet.

# --- Couleurs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# --- Initialisation ---
echo -e "${CYAN}GitHub Actions Workflow Validation${NC}"
echo -e "${CYAN}====================================${NC}"
echo

workflows_dir=".github/workflows"
errors=0
warnings=0

if [ ! -d "$workflows_dir" ]; then
    echo -e "${RED}❌ Répertoire $workflows_dir non trouvé.${NC}"
    exit 1
fi

workflow_files=$(find "$workflows_dir" -name "*.yml")
if [ -z "$workflow_files" ]; then
    echo -e "${RED}❌ Aucun fichier de workflow trouvé dans $workflows_dir.${NC}"
    exit 1
fi

echo -e "${YELLOW}Fichiers de workflow trouvés:${NC}"
for file in $workflow_files; do
    echo -e "  - ${WHITE}$(basename "$file")${NC}"
done
echo

# --- Fonction de vérification ---
run_check() {
    local file=$1
    local pattern=$2
    local description=$3
    local is_warning=${4:-false}

    if grep -q -E "$pattern" "$file"; then
        echo -e "  ${GREEN}✅ $description${NC}"
        return 0
    else
        if [ "$is_warning" = true ]; then
            echo -e "  ${YELLOW}⚠️ $description${NC}"
            ((warnings++))
            return 0 # Ne compte pas comme une erreur bloquante
        else
            echo -e "  ${RED}❌ $description${NC}"
            ((errors++))
            return 1
        fi
    fi
}

# --- Validation par fichier ---
for file in $workflow_files; do
    filename=$(basename "$file")
    echo -e "${YELLOW}Validation de $filename...${NC}"

    run_check "$file" "name:" "Possède un champ 'name'"
    run_check "$file" "on:" "Possède un déclencheur 'on'"
    run_check "$file" "jobs:" "Possède une section 'jobs'"
    run_check "$file" "actions/checkout" "Utilise 'actions/checkout'"
    run_check "$file" "rust-toolchain|actions-rs/toolchain" "Utilise le toolchain Rust"

    case $filename in
        "ci.yml")
            run_check "$file" "check-security-theatre" "Possède la vérification 'security theatre'" true
            run_check "$file" "cargo check" "Possède 'cargo check'" true
            run_check "$file" "cargo clippy" "Possède 'cargo clippy'" true
            run_check "$file" "cargo test" "Possède 'cargo test'" true
            ;;
        "security-audit.yml")
            run_check "$file" "cargo audit" "Possède 'cargo audit'" true
            run_check "$file" "semgrep" "Possède 'semgrep'" true
            ;;
        "monero-integration.yml")
            run_check "$file" "monero|Monero" "Possède la configuration Monero" true
            run_check "$file" "testnet" "Possède la configuration testnet" true
            ;;
    esac
    echo
done

# --- Résumé ---
echo -e "${CYAN}Résumé de la validation${NC}"
echo -e "${CYAN}=======================${NC}"
echo

if [ $errors -eq 0 ] && [ $warnings -eq 0 ]; then
    echo -e "${GREEN}✅ Tous les workflows sont valides!${NC}"
    exit 0
elif [ $errors -eq 0 ]; then
    echo -e "${YELLOW}⚠️ Les workflows sont valides mais ont $warnings avertissement(s).${NC}"
    exit 0
else
    echo -e "${RED}❌ Trouvé $errors erreur(s) et $warnings avertissement(s).${NC}"
    echo -e "${RED}Corrigez les erreurs avant de commiter les workflows.${NC}"
    exit 1
fi
