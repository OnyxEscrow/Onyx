#!/bin/bash

# Script: setup-monero-stagenet.sh
# Description: Configure et lance un environnement de STAGENET Monero complet.
# Usage: ./scripts/setup-monero-stagenet.sh [nom_du_wallet]

# --- Couleurs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Configuration ---
WALLET_NAME=${1:-buyer_stagenet} # Utilise le premier argument ou "buyer_stagenet" par défaut
DAEMON_PORT=38081
RPC_PORT=38082

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

# --- 1. Lancer le démon stagenet (si pas déjà lancé) ---
if ! pgrep -f "monerod.*--stagenet" > /dev/null; then
    echo -e "${YELLOW}1️⃣ Lancement du démon STAGENET...${NC}"
    monerod --stagenet --detach
    echo -e "   ${CYAN}Attente de la synchronisation (10s)...${NC}"
    sleep 10
    echo -e "   ${GREEN}✅ Démon lancé.${NC}"
else
    echo -e "${GREEN}1️⃣ Démon STAGENET déjà lancé ✅${NC}"
fi

# --- 2. Créer le portefeuille si nécessaire ---
# monero-wallet-cli crée les fichiers <wallet_name> et <wallet_name>.keys
if [ ! -f "$WALLET_NAME" ]; then
    echo -e "${YELLOW}2️⃣ Création du portefeuille STAGENET: $WALLET_NAME${NC}"
    echo -e "   ${CYAN}(Mot de passe vide pour les tests)${NC}"
    
    # Utilise --generate-new-wallet au lieu de la méthode JSON qui est moins standard
    monero-wallet-cli --stagenet --generate-new-wallet "$WALLET_NAME" --password "" --mnemonic-language "English" --command exit
    
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
    # Check if port is in use
    if lsof -i :$RPC_PORT > /dev/null; then
        echo -e "${YELLOW}⚠️  Port $RPC_PORT déjà utilisé. Tentative de libération...${NC}"
        fuser -k -n tcp $RPC_PORT
        sleep 2
    fi

    echo -e "${YELLOW}3️⃣ Lancement du portefeuille RPC pour: $WALLET_NAME${NC}"
    monero-wallet-rpc \
        --stagenet \
        --wallet-file "$WALLET_NAME" \
        --password "" \
        --rpc-bind-ip "127.0.0.1" \
        --rpc-bind-port "$RPC_PORT" \
        --disable-rpc-login \
        --daemon-address "127.0.0.1:$DAEMON_PORT" \
        --log-level 1 \
        --detach

    echo -e "   ${CYAN}Attente du démarrage du RPC (5s)...${NC}"
    sleep 5
fi

# --- 4. Tester la connexion RPC ---
echo -e "${YELLOW}4️⃣ Test de la connexion RPC...${NC}"
rpc_response=$(curl --silent -X POST http://127.0.0.1:$RPC_PORT/json_rpc -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":"0","method":"get_version"}' --connect-timeout 5)

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
echo -e "${GREEN}✅ Setup Monero STAGENET complet!${NC}"
echo
echo -e "${CYAN}📋 Résumé:${NC}"
echo -e "  ${GREEN}Démon: stagenet @ 127.0.0.1:$DAEMON_PORT${NC}"
echo -e "  ${GREEN}Portefeuille: $WALLET_NAME (mot de passe vide)${NC}"
echo -e "  ${GREEN}RPC: http://127.0.0.1:$RPC_PORT${NC}"
echo
echo -e "${CYAN}🧪 Pour lancer le serveur en mode Stagenet:${NC}"
echo -e "  ${YELLOW}MONERO_NETWORK=stagenet cargo run${NC}"
