#!/bin/bash

# Script: demo-workflow.sh
# Description: Démontre le flux de travail de développement complet du projet.

# --- Couleurs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# --- Introduction ---
echo -e "${CYAN}DEMO WORKFLOW CURSOR RULES v2.0${NC}"
echo -e "${CYAN}=================================${NC}"

if [ ! -f ".cursorrules" ]; then
    echo -e "${RED}ERREUR: Exécutez ce script depuis la racine du projet.${NC}"
    exit 1
fi

echo -e "\n${WHITE}Ce script démontre le workflow complet:${NC}"
echo -e "1. Création d'une spec"
_spec.sh"
echo -e "2. Génération de code (simulée)"
echo -e "3. Reality check"
echo -e "4. Vérifications pre-commit"
echo -e "5. Mise à jour des métriques"

read -p "Continuer? (y/N) " response
if [[ ! "$response" =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Démo annulée.${NC}"
    exit 0
fi

# --- Étape 1: Création de la Spec ---
echo -e "\n${GREEN}=== ÉTAPE 1: CRÉATION D'UNE SPEC ===${NC}"
function_name="get_transaction_info"
echo -e "${YELLOW}Création de la spec pour: $function_name${NC}"

./scripts/new-spec.sh "$function_name"

if [ -f "docs/specs/$function_name.md" ]; then
    echo -e "${GREEN}Spec créée avec succès!${NC}"
else
    echo -e "${RED}Erreur lors de la création de la spec.${NC}"
    exit 1
fi

# --- Étape 2: Édition de la Spec (simulée) ---
echo -e "\n${GREEN}=== ÉTAPE 2: ÉDITION DE LA SPEC ===${NC}"
# Le contenu est directement écrit pour la démo
cat << EOF > "docs/specs/$function_name.md"
## Spec: $function_name

### Objectif
Récupère les informations d'une transaction Monero par son hash.

### Préconditions
- [ ] monero-wallet-rpc tourne sur localhost:18082
- [ ] Wallet ouvert et déverrouillé

### Input
```rust
tx_hash: String,
```

### Output
```rust
Result<TransactionInfo, Error>
```
EOF
echo -e "${GREEN}Spec éditée automatiquement pour la démo.${NC}"

# --- Étape 3: Génération de code (simulée) ---
echo -e "\n${GREEN}=== ÉTAPE 3: GÉNÉRATION DE CODE (SIMULÉE) ===${NC}"
echo -e "${YELLOW}À ce stade, vous demanderiez à une IA de générer le code basé sur la spec.${NC}"
echo -e "${CYAN}L'IA effectuerait automatiquement les vérifications et la génération.${NC}"

# --- Étape 4: Reality Check ---
echo -e "\n${GREEN}=== ÉTAPE 4: REALITY CHECK ===${NC}"
./scripts/reality-check.sh "$function_name"
if [ -f "docs/reality-checks/$function_name-$(date +'%Y-%m-%d').md" ]; then
    echo -e "${GREEN}Reality check créé avec succès!${NC}"
else
    echo -e "${RED}Erreur lors de la création du reality check.${NC}"
fi

# --- Étape 5: Pre-commit Checks ---
echo -e "\n${GREEN}=== ÉTAPE 5: VÉRIFICATIONS PRE-COMMIT ===${NC}"
echo -e "${YELLOW}Exécution des vérifications pre-commit...${NC}"
./scripts/pre-commit.sh

# --- Étape 6: Métriques ---
echo -e "\n${GREEN}=== ÉTAPE 6: MÉTRIQUES ===${NC}"
echo -e "${YELLOW}Mise à jour des métriques...${NC}"
./scripts/update-metrics.sh

# --- Fin ---
echo -e "\n${GREEN}=== DÉMO TERMINÉE ===${NC}"
echo -e "${GREEN}=====================${NC}"

echo -e "\n${CYAN}Le workflow de développement est maintenant unifié pour un environnement shell!${NC}"
