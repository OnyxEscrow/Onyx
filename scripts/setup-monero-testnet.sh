#!/bin/bash

# Script: setup-monero-testnet.sh
# Description: Configure et lance un environnement de testnet Monero complet.
# Usage: ./scripts/setup-monero-testnet.sh [nom_du_wallet]

# --- Couleurs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Configuration ---
WALLET_NAME=${1:-buyer} # Utilise le premier argument ou "buyer" par défaut

# --- Vérification des dépendances ---
echo -e "${CYAN}🔧 Vérification des binaires Monero...${NC}"

missing_binaries=false
for bin in monerod monero-wallet-cli monero-wallet-rpc; do
    if ! command -v $bin &> /dev/null; then
        echo -e "  ${RED}Binaire manquant: $bin. Assurez-vous qu'il est dans votre PATH.${NC}"
        missing_binaries=true
    else
        echo -e "  ${GREEN}Binaire trouvé: $(command -v $bin)${NC}"
    fi
done

if [ "$missing_binaries" = true ]; then
    echo -e "${RED}Installation Monero incomplète. Veuillez installer les outils Monero CLI.${NC}"
    exit 1
fi

# --- 1. Lancer le démon testnet (si pas déjà lancé) ---
if ! pgrep -x "monerod" > /dev/null; then
    echo -e "${YELLOW}1️⃣ Lancement du démon testnet...${NC}"
    monerod --testnet --detach
    echo -e "   ${CYAN}Attente de la synchronisation (10s)...${NC}"
    sleep 10
    echo -e "   ${GREEN}✅ Démon lancé.${NC}"
else
    echo -e "${GREEN}1️⃣ Démon déjà lancé ✅${NC}"
fi

# --- 2. Créer le portefeuille si nécessaire ---
# monero-wallet-cli crée les fichiers <wallet_name> et <wallet_name>.keys
if [ ! -f "$WALLET_NAME" ]; then
    echo -e "${YELLOW}2️⃣ Création du portefeuille testnet: $WALLET_NAME${NC}"
    echo -e "   ${CYAN}(Mot de passe vide pour les tests)${NC}"
    
    # Utilise --generate-new-wallet au lieu de la méthode JSON qui est moins standard
    monero-wallet-cli --testnet --generate-new-wallet "$WALLET_NAME" --password "" --mnemonic-language "English" --command exit
    
    if [ -f "$WALLET_NAME" ]; then
        echo -e "   ${GREEN}✅ Portefeuille créé.${NC}"
    else
        echo -e "   ${RED}❌ Erreur lors de la création du portefeuille.${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}2️⃣ Le portefeuille existe déjà ✅${NC}"
fi

# --- 3. Lancer le portefeuille RPC ---
# S'assure qu'aucune autre instance ne tourne pour éviter les conflits
if pgrep -f "monero-wallet-rpc.*--wallet-file $WALLET_NAME" > /dev/null; then
    echo -e "${GREEN}3️⃣ Le portefeuille RPC pour '$WALLET_NAME' est déjà lancé ✅${NC}"
else
    if pgrep -x "monero-wallet-rpc" > /dev/null; then
        echo -e "${YELLOW}3️⃣ Un autre portefeuille RPC est en cours d'exécution. Fermeture...${NC}"
        pkill -f "monero-wallet-rpc"
        sleep 2
    fi
    echo -e "${YELLOW}3️⃣ Lancement du portefeuille RPC pour: $WALLET_NAME${NC}"
    monero-wallet-rpc \
        --testnet \
        --wallet-file "$WALLET_NAME" \
        --password "" \
        --rpc-bind-ip "127.0.0.1" \
        --rpc-bind-port "18082" \
        --disable-rpc-login \
        --daemon-address "127.0.0.1:28081" \
        --log-level 1 \
        --detach

    echo -e "   ${CYAN}Attente du démarrage du RPC (5s)...${NC}"
    sleep 5
fi

# --- 4. Tester la connexion RPC ---
echo -e "${YELLOW}4️⃣ Test de la connexion RPC...${NC}"
rpc_response=$(curl --silent -X POST http://127.0.0.1:18082/json_rpc -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' --connect-timeout 5)

if [[ $rpc_response == *"result"* ]]; then
    version=$(echo "$rpc_response" | jq -r '.result.version')
    echo -e "   ${GREEN}✅ RPC accessible.${NC}"
    echo -e "   ${CYAN}Version: $version${NC}"
else
    echo -e "   ${RED}❌ RPC non accessible.${NC}"
    echo -e "   ${RED}Erreur: Assurez-vous que le RPC a bien démarré.${NC}"
    exit 1
fi

echo
echo -e "${GREEN}✅ Setup Monero Testnet complet!${NC}"
echo
echo -e "${CYAN}📋 Résumé:${NC}"
echo -e "  ${GREEN}Démon: testnet @ 127.0.0.1:28081${NC}"
echo -e "  ${GREEN}Portefeuille: $WALLET_NAME (mot de passe vide)${NC}"
echo -e "  ${GREEN}RPC: http://127.0.0.1:18082${NC}"
echo
echo -e "${CYAN}🧪 Prochaine étape:${NC}"
echo -e "  ${YELLOW}cargo test --workspace${NC}"