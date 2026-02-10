#!/bin/bash

# Script: verify-fixes.sh
# Description: Vérifie que les correctifs de compilation de base fonctionnent.

# --- Couleurs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# --- Header ---
echo -e "${CYAN}===============================================${NC}"
echo -e "  ${CYAN}Monero Marketplace - Vérification des Fixs${NC}"
echo -e "${CYAN}===============================================${NC}"
echo

# --- Vérifications ---

# 1. Vérifier l'installation de Rust
echo -e "${YELLOW}[1/6] Vérification de l'installation de Rust...${NC}"
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}❌ Cargo non trouvé. Veuillez installer Rust via https://rustup.rs/${NC}"
    exit 1
fi
rust_version=$(cargo --version)
echo -e "${GREEN}✅ Rust installé: $rust_version${NC}"
echo

# 2. Vérifier la structure du workspace
echo -e "${YELLOW}[2/6] Vérification de la structure du workspace...${NC}"
if [ ! -f "Cargo.toml" ]; then
    echo -e "${RED}❌ Cargo.toml non trouvé. Exécutez ce script depuis la racine du projet.${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Structure du workspace valide.${NC}"
echo

# 3. Lancer cargo check
echo -e "${YELLOW}[3/6] Lancement de cargo check...${NC}"
if check_output=$(cargo check --workspace 2>&1); then
    echo -e "${GREEN}✅ Cargo check passé - le code compile!${NC}"
else
    echo -e "${RED}❌ Échec de Cargo check:${NC}"
    echo -e "$check_output"
    exit 1
fi
echo

# 4. Lancer la compilation des tests
echo -e "${YELLOW}[4/6] Lancement de la compilation des tests...${NC}"
if test_output=$(cargo test --workspace --no-run 2>&1); then
    echo -e "${GREEN}✅ Tous les tests compilent avec succès.${NC}"
else
    echo -e "${RED}❌ La compilation des tests a échoué:${NC}"
    echo -e "$test_output"
    exit 1
fi
echo

# 5. Lancer clippy
echo -e "${YELLOW}[5/6] Lancement de clippy...${NC}"
if clippy_output=$(cargo clippy --workspace -- -D warnings 2>&1); then
    echo -e "${GREEN}✅ Clippy passé - aucun warning!${NC}"
else
    echo -e "${YELLOW}⚠️ Warnings Clippy trouvés:${NC}"
    echo -e "$clippy_output"
    echo -e "${YELLOW}Note: Les warnings Clippy ne bloquent pas la compilation mais devraient être corrigés.${NC}"
fi
echo

# 6. Vérifier le formatage
echo -e "${YELLOW}[6/6] Vérification du formatage du code...${NC}"
if fmt_output=$(cargo fmt --workspace --check 2>&1); then
    echo -e "${GREEN}✅ Le formatage du code est correct.${NC}"
else
    echo -e "${YELLOW}⚠️ Problèmes de formatage du code trouvés.${NC}"
    echo -e "${YELLOW}Lancez: cargo fmt --workspace${NC}"
fi
echo

# --- Résumé Final ---
echo -e "${CYAN}===============================================${NC}"
echo -e "  ${CYAN}Résumé de la Vérification${NC}"
echo -e "${CYAN}===============================================${NC}"
echo
echo -e "${GREEN}✅ Toutes les erreurs de compilation critiques sont CORRIGÉES!${NC}"
echo
echo -e "${CYAN}Prochaines étapes:${NC}"
echo -e "  ${WHITE}• Build: cargo build --workspace${NC}"
echo -e "  ${WHITE}• Test: cargo test --workspace${NC}"
echo -e "  ${WHITE}• Run: cargo run --package cli -- --help${NC}"
echo
