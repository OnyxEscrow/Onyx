#!/bin/bash

# Script: setup-3-wallets-stagenet.sh
# Description: Configure 3 wallets (Buyer, Vendor, Arbiter) pour le développement STAGENET.
# Usage: ./scripts/setup-3-wallets-stagenet.sh

# --- Couleurs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Configuration ---
DAEMON_PORT=38081
BASE_RPC_PORT=38082

WALLETS=("buyer_stagenet" "vendor_stagenet" "arbiter_stagenet")
PORTS=($BASE_RPC_PORT $(($BASE_RPC_PORT + 1)) $(($BASE_RPC_PORT + 2)))

echo -e "${CYAN}🚀 Configuration de 3 wallets pour STAGENET...${NC}"

# --- 1. Vérifier le démon ---
if ! pgrep -f "monerod.*--stagenet" > /dev/null; then
    echo -e "${RED}❌ Le démon Monero Stagenet n'est pas lancé.${NC}"
    echo -e "   Veuillez lancer ./scripts/setup-monero-stagenet.sh d'abord."
    exit 1
fi

# --- 2. Créer et lancer les wallets ---
for i in "${!WALLETS[@]}"; do
    WALLET_NAME="${WALLETS[$i]}"
    RPC_PORT="${PORTS[$i]}"
    
    echo -e "\n${YELLOW}👉 Configuration de $WALLET_NAME (Port RPC: $RPC_PORT)${NC}"

    # Créer le wallet si nécessaire
    if [ ! -f "$WALLET_NAME" ]; then
        echo -e "   ${CYAN}Création du fichier wallet...${NC}"
        monero-wallet-cli --stagenet --generate-new-wallet "$WALLET_NAME" --password "" --mnemonic-language "English" --command exit > /dev/null 2>&1
    fi

    # Vérifier si le port est utilisé
    if lsof -i :$RPC_PORT > /dev/null; then
        echo -e "   ${YELLOW}⚠️  Port $RPC_PORT occupé. Tentative de libération...${NC}"
        fuser -k -n tcp $RPC_PORT
        sleep 1
    fi

    # Lancer le RPC
    echo -e "   ${CYAN}Lancement du RPC...${NC}"
    monero-wallet-rpc \
        --stagenet \
        --wallet-file "$WALLET_NAME" \
        --password "" \
        --rpc-bind-ip "127.0.0.1" \
        --rpc-bind-port "$RPC_PORT" \
        --disable-rpc-login \
        --daemon-address "127.0.0.1:$DAEMON_PORT" \
        --log-level 0 \
        --detach

    # Vérifier
    sleep 2
    if lsof -i :$RPC_PORT > /dev/null; then
        echo -e "   ${GREEN}✅ $WALLET_NAME RPC actif sur le port $RPC_PORT${NC}"
    else
        echo -e "   ${RED}❌ Échec du lancement pour $WALLET_NAME${NC}"
    fi
done

echo -e "\n${GREEN}✅ Configuration terminée!${NC}"
echo -e "${CYAN}📋 Récapitulatif RPC:${NC}"
echo -e "  Buyer:   http://127.0.0.1:${PORTS[0]}"
echo -e "  Vendor:  http://127.0.0.1:${PORTS[1]}"
echo -e "  Arbiter: http://127.0.0.1:${PORTS[2]}"
