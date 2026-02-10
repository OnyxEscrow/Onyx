#!/bin/bash

# Script: new-spec.sh
# Crée une nouvelle spec à partir du template
# Usage: ./scripts/new-spec.sh <function_name>

# --- Couleurs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

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

# --- Création du répertoire ---
specs_dir="docs/specs"
mkdir -p "$specs_dir"

# --- Vérification de l'existence du fichier ---
spec_file="${specs_dir}/${FunctionName}.md"

if [ -f "$spec_file" ]; then
    echo -e "${YELLOW}ATTENTION: La spec $spec_file existe déjà.${NC}"
    read -p "Voulez-vous la remplacer? (y/N) " overwrite
    echo # Saut de ligne
    if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Annulé.${NC}"
        exit 0
    fi
fi

# --- Template de spec ---
# Using a quoted 'EOF' to prevent shell expansion inside the heredoc.
cat << 'EOF' > "$spec_file"
## Spec: $FunctionName

### Objectif
[Décrire en 1 ligne ce que fait cette fonction]

### Préconditions
- [ ] monero-wallet-rpc tourne sur localhost:18082
- [ ] Wallet ouvert et déverrouillé
- [ ] [Autres préconditions spécifiques]

### Input
``````rust
// Types exacts des paramètres
param1: Type1,
param2: Type2,
``````

### Output
``````rust
Result<ReturnType, ErrorType>
``````

### Erreurs Possibles
- ErrorType::Variant1 - [Quand ça arrive]
- ErrorType::Variant2 - [Quand ça arrive]

### Dépendances
``````toml
[dependencies]
dep1 = "version"
``````

### Test de Validation (Shell)
``````bash
# Setup
# ./scripts/start-testnet.sh (À adapter)

# Test manuel
curl --data-binary '''{"jsonrpc":"2.0","id":"0","method":"{rpc_method}"}''' -H 'Content-Type: application/json' http://127.0.0.1:18082/json_rpc

# Expected output:
# { ... "result": { ... } }
``````

### Estimation
- Code: XX min
- Test: XX min
- Total: XX min

### Status
- [ ] Spec validée
- [ ] Code écrit
- [ ] Tests passent
- [ ] Reality check fait
EOF

# --- Remplacement du placeholder ---
# The placeholder $FunctionName is not expanded in the heredoc, so we replace it now.
# Using sed -i for in-place replacement.
sed -i "s/\$FunctionName/$FunctionName/g" "$spec_file"


# --- Message de succès ---
echo -e "${GREEN}Spec créée: $spec_file${NC}"
echo -e "${CYAN}Éditez-la maintenant avec votre éditeur.${NC}"
echo -e "${CYAN}Puis demandez à l'IA de générer le code.${NC}"
