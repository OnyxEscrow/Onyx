#!/bin/bash

# Script: test-rpc.sh
# Description: Teste la connexion aux différents RPC Monero.

# --- Couleurs ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# --- Initialisation ---
echo -e "${CYAN}TEST CONNEXION MONERO RPC${NC}"
echo -e "${CYAN}==========================${NC}"

if [ ! -f ".cursorrules" ]; then
    echo -e "${RED}ERREUR: Exécutez ce script depuis la racine du projet.${NC}"
    exit 1
fi

errors=0

# --- Fonction utilitaire RPC ---
call_rpc() {
    local port=$1
    local method=$2
    local body='''{"jsonrpc":"2.0","id":"0","method":"'''$method'''"}'''

    response=$(curl --silent -X POST "http://127.0.0.1:$port/json_rpc" \
        -H 'Content-Type: application/json' \
        -d "$body" --connect-timeout 5)

    if [ $? -ne 0 ]; then
        echo "RPC_ERROR: curl command failed to connect to port $port."
        return 1
    fi

    if ! echo "$response" | jq -e '.result' > /dev/null; then
        error_message=$(echo "$response" | jq -r '.error.message // "No result field and no error message."')
        echo "RPC_ERROR: $error_message"
        return 1
    fi

    echo "$response"
    return 0
}

# --- Début des tests ---

# 1. Test connexion daemon
echo -e "\n${YELLOW}1. Test connexion daemon (port 18081)...${NC}"
response=$(call_rpc 18081 "get_version")
if [[ $response == "RPC_ERROR"* ]]; then
    echo -e "   ${RED}Daemon non accessible: $response${NC}"
    ((errors++))
else
    version=$(echo "$response" | jq -r '.result.version')
    echo -e "   ${GREEN}Daemon accessible${NC}"
    echo -e "   ${WHITE}Version: $version${NC}"
fi

# 2. Test connexion wallet RPC
echo -e "\n${YELLOW}2. Test connexion wallet RPC (port 18082)...${NC}"
response=$(call_rpc 18082 "get_version")
if [[ $response == "RPC_ERROR"* ]]; then
    echo -e "   ${RED}Wallet RPC non accessible: $response${NC}"
    ((errors++))
else
    version=$(echo "$response" | jq -r '.result.version')
    echo -e "   ${GREEN}Wallet RPC accessible${NC}"
    echo -e "   ${WHITE}Version: $version${NC}"
fi

# 3. Test get_balance
echo -e "\n${YELLOW}3. Test get_balance...${NC}"
response=$(call_rpc 18082 "get_balance")
if [[ $response == "RPC_ERROR"* ]]; then
    echo -e "   ${RED}get_balance échoué: $response${NC}"
    ((errors++))
else
    balance=$(echo "$response" | jq -r '.result.balance')
    unlocked_balance=$(echo "$response" | jq -r '.result.unlocked_balance')
    echo -e "   ${GREEN}get_balance fonctionne${NC}"
    echo -e "   ${WHITE}Balance: $balance atomic units${NC}"
    echo -e "   ${WHITE}Unlocked: $unlocked_balance atomic units${NC}"
fi

# 4. Test is_multisig
echo -e "\n${YELLOW}4. Test is_multisig...${NC}"
response=$(call_rpc 18082 "is_multisig")
if [[ $response == "RPC_ERROR"* ]]; then
    echo -e "   ${RED}is_multisig échoué: $response${NC}"
    ((errors++))
else
    is_multisig=$(echo "$response" | jq -r '.result.multisig')
    echo -e "   ${GREEN}is_multisig fonctionne${NC}"
    echo -e "   ${WHITE}Multisig: $is_multisig${NC}"
fi

# 5. Test avec notre CLI
echo -e "\n${YELLOW}5. Test avec notre CLI...${NC}"
if ! command -v cargo &> /dev/null; then
    echo -e "   ${YELLOW}Cargo non disponible, test CLI ignoré.${NC}"
else
    echo -e "   ${GREEN}Cargo disponible${NC}"
    if cargo run --bin monero-marketplace -- test &> /dev/null; then
        echo -e "   ${GREEN}CLI fonctionne${NC}"
    else
        echo -e "   ${RED}CLI échoué${NC}"
        ((errors++))
    fi
fi

# --- Résumé ---
echo -e "\n${CYAN}RÉSUMÉ DES TESTS${NC}"
echo -e "${CYAN}=================${NC}"

if [ $errors -eq 0 ]; then
    echo -e "${GREEN}TOUS LES TESTS PASSENT!${NC}"
    echo -e "${GREEN}Monero RPC est prêt pour le développement.${NC}"
    exit 0
else
    echo -e "${RED}$errors test(s) échoué(s)${NC}"
    echo -e "\n${YELLOW}Solutions possibles:${NC}"
    echo -e "  ${WHITE}1. Lancer: ./scripts/setup-monero-testnet.sh${NC}"
    echo -e "  ${WHITE}2. Vérifier que les outils Monero CLI sont dans le PATH.${NC}"
    exit 1
fi