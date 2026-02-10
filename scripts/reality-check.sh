#!/bin/bash

# Script: reality-check.sh
# Description: Génère un fichier de "reality check" pour une fonction donnée.

# --- Couleurs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Vérification des arguments ---
if [ -z "$1" ]; then
    echo -e "${RED}ERREUR: Nom de la fonction manquant.${NC}"
    echo "Usage: $0 <function_name>"
    exit 1
fi

FunctionName=$1

# --- Vérification du répertoire racine ---
if [ ! -f ".cursorrules" ]; then
    echo -e "${RED}ERREUR: Exécutez ce script depuis la racine du projet.${NC}"
    exit 1
fi

# --- Vérification de l'existence de la spec ---
spec_file="docs/specs/${FunctionName}.md"
if [ ! -f "$spec_file" ]; then
    echo -e "${RED}ERREUR: La spec $spec_file n'existe pas.${NC}"
    echo -e "${YELLOW}Créez d'abord la spec avec: ./scripts/new-spec.sh $FunctionName${NC}"
    exit 1
fi

# --- Création du répertoire et gestion du fichier ---
reality_checks_dir="docs/reality-checks"
mkdir -p "$reality_checks_dir"

current_date=$(date +"%Y-%m-%d")
current_timestamp=$(date +"%Y-%m-%d %H:%M:%S")
reality_check_file="${reality_checks_dir}/${FunctionName}-${current_date}.md"

if [ -f "$reality_check_file" ]; then
    echo -e "${YELLOW}ATTENTION: Le reality check $reality_check_file existe déjà.${NC}"
    read -p "Voulez-vous le remplacer? (y/N) " overwrite
    if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Annulé.${NC}"
        exit 0
    fi
fi

# --- Template ---
# Le template est écrit dans le fichier, puis les variables sont substituées avec sed.
cats << 'EOF' > "$reality_check_file"
# Reality Check: ${FUNCTION_NAME}
**Date:** ${CURRENT_DATE}  
**Heure:** ${CURRENT_TIMESTAMP}  
**Fonction:** ${FUNCTION_NAME}

---

## Checklist de Validation

### Code Review
- [ ] **Spec respectée**: Le code implémente exactement ce qui est dans la spec
- [ ] **Error handling**: Tous les cas d'erreur sont gérés avec .context() ou match
- [ ] **Pas d'unwrap**: Aucun .unwrap() ou .expect() sans message

### Tests
- [ ] **Tests unitaires**: Au moins un test par cas d'usage principal
- [ ] **Tests d'erreur**: Tests pour les cas d'erreur documentés
- [ ] **Tous les tests passent**: cargo test sans erreur

### Performance & Securite
- [ ] **Pas de panics**: Aucun panic! dans le code
- [ ] **Pas de logs sensibles**: Aucun log de mots de passe/tokens

---

## Test Manuel

### Prérequis
```bash
# 1. Lancer Monero testnet
./scripts/setup-monero-testnet.sh

# 2. Vérifier que le RPC répond
curl --silent -X POST http://127.0.0.1:18082/json_rpc -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' | jq
```

### Test de la fonction
```bash
# [À compléter avec les commandes de test spécifiques]
# Exemple:
# cargo test test_${FUNCTION_NAME}
# cargo run --bin monero-marketplace -- ${FUNCTION_NAME} --param1 value1
```

### Résultat attendu
```
# [À compléter avec le résultat attendu]
```

---

## Validation Finale

- [ ] **Fonctionne**: La fonction fait ce qu'elle doit faire
- [ ] **Robuste**: Gère tous les cas d'erreur
- [ ] **Sécurisé**: Pas de vulnérabilités évidentes

---

## Validation

**Validé par:** [Nom]  
**Date de validation:** ${CURRENT_DATE}  
**Status:** [ ] VALIDE | [ ] REJETÉ | [ ] À CORRIGER

**Commentaires finaux:**
[À compléter]
EOF

# --- Substitution des variables dans le template ---
sed -i "s/${FUNCTION_NAME}/$FunctionName/g" "$reality_check_file"
sed -i "s/${CURRENT_DATE}/$current_date/g" "$reality_check_file"
sed -i "s/${CURRENT_TIMESTAMP}/$current_timestamp/g" "$reality_check_file"


echo -e "${GREEN}Reality check créé: $reality_check_file${NC}"
echo -e "${CYAN}Complétez-le maintenant avec vos tests et observations.${NC}"
