#!/bin/bash

# Script: pre-commit.sh
# Description: Exécute toutes les vérifications de pré-commit.

# --- Couleurs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Initialisation ---
echo -e "${CYAN}PRE-COMMIT CHECKS${NC}"
echo -e "${CYAN}===================${NC}"

# S'assurer que le script est exécuté depuis la racine
if [ ! -f ".cursorrules" ]; then
    echo -e "${RED}ERREUR: Exécutez ce script depuis la racine du projet.${NC}"
    exit 1
fi

errors=0
warnings=0

# --- Fonctions de vérification ---

run_check() {
    local title=$1
    local command=$2
    local on_success=$3
    local on_failure=$4

    echo -e "\n${YELLOW}$title${NC}"
    # Exécute la commande et capture la sortie et le code de sortie
    output=$(eval "$command" 2>&1)
    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        echo -e "   ${GREEN}$on_success${NC}"
    else
        echo -e "   ${RED}$on_failure${NC}"
        # Affiche la sortie seulement en cas d'erreur pour les checks qui le nécessitent
        if [[ "$title" == *"Clippy"* || "$title" == *"compilation"* || "$title" == *"Tests"* ]]; then
            echo "$output"
        fi
        return 1
    fi
    return 0
}

# 1. Vérification de la compilation
run_check "1. Vérification de la compilation..." \
          "cargo check" \
          "Projet compilé correctement" \
          "Erreurs de compilation détectées" || ((errors++))

# 2. Format du code
echo -e "\n${YELLOW}2. Vérification du format...${NC}"
cargo fmt --check
if [ $? -ne 0 ]; then
    echo -e "   ${YELLOW}Code mal formaté, correction automatique...${NC}"
    cargo fmt
    if [ $? -eq 0 ]; then
        echo -e "   ${GREEN}Code reformaté automatiquement.${NC}"
    else
        echo -e "   ${RED}Erreur lors du formatage.${NC}"
        ((errors++))
    fi
else
    echo -e "   ${GREEN}Code bien formaté.${NC}"
fi

# 3. Clippy (linter)
run_check "3. Vérification Clippy..." \
          "cargo clippy -- -D warnings" \
          "Aucun warning Clippy" \
          "Warnings Clippy détectés" || ((warnings++))

# 4. Tests
run_check "4. Exécution des tests..." \
          "cargo test --workspace" \
          "Tous les tests passent" \
          "Échec des tests" || ((errors++))

# 5. Vérification des unwraps (exclude test files as per .security-theatre-ignore)
echo -e "\n${YELLOW}5. Vérification des unwraps...${NC}"
unwrap_count=$(grep -r -E --include="*.rs" --exclude-dir=target --exclude-dir=tests "\.unwrap\(" . | grep -v "/tests/" | wc -l)
if [ $unwrap_count -eq 0 ]; then
    echo -e "   ${GREEN}Aucun unwrap() trouvé.${NC}"
elif [ $unwrap_count -le 5 ]; then
    echo -e "   ${YELLOW}$unwrap_count unwrap() trouvé(s) (seuil: 5).${NC}"
    ((warnings++))
else
    echo -e "   ${RED}$unwrap_count unwrap() trouvé(s) (seuil: 5).${NC}"
    ((errors++))
fi

# 6. Vérification des TODOs
echo -e "\n${YELLOW}6. Vérification des TODOs...${NC}"
todo_count=$(grep -r -i -E --include="*.rs" --exclude-dir=target "TODO|FIXME" . | wc -l)
if [ $todo_count -eq 0 ]; then
    echo -e "   ${GREEN}Aucun TODO trouvé.${NC}"
elif [ $todo_count -le 10 ]; then
    echo -e "   ${YELLOW}$todo_count TODO trouvé(s) (seuil: 10).${NC}"
    ((warnings++))
else
    echo -e "   ${RED}$todo_count TODO trouvé(s) (seuil: 10).${NC}"
    ((errors++))
fi

# 7. Check Security Theatre
run_check "7. Vérification Security Theatre..." \
          "./scripts/check-security-theatre-simple.sh" \
          "Aucun \"security theatre\" détecté" \
          "\"Security theatre\" détecté !" || ((errors++))

# 8. Check Monero/Tor Security
run_check "8. Vérification Monero/Tor Security..." \
          "./scripts/check-monero-tor-final.sh" \
          "Aucun problème de sécurité Monero/Tor détecté" \
          "Problèmes de sécurité Monero/Tor détectés !" || ((errors++))

# 9. Mise à jour des métriques
run_check "9. Mise à jour des métriques..." \
          "./scripts/update-metrics.sh" \
          "Mise à jour des métriques réussie" \
          "Échec de la mise à jour des métriques" || ((warnings++))

# --- Résumé final ---
echo -e "\n${CYAN}RÉSUMÉ PRE-COMMIT${NC}"
echo -e "${CYAN}===================${NC}"

if [ $errors -eq 0 ] && [ $warnings -eq 0 ]; then
    echo -e "${GREEN}TOUS LES CHECKS PASSENT - Prêt pour le commit!${NC}"
    exit 0
elif [ $errors -eq 0 ]; then
    echo -e "${YELLOW}$warnings warning(s) détecté(s) - Commit possible mais attention.${NC}"
    echo -e "${CYAN}Considérez corriger les warnings avant de commiter.${NC}"
    exit 0
else
    echo -e "${RED}$errors erreur(s) détectée(s) - COMMIT BLOQUÉ${NC}"
    echo -e "${YELLOW}Corrigez les erreurs avant de pouvoir commiter.${NC}"
    exit 1
fi