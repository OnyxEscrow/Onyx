#!/usr/bin/env bash
# scripts/setup-3-wallets-testnet.sh
# CORRECT APPROACH: Single RPC server with --wallet-dir managing multiple wallets

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}🔧 [V3] Setup 3-Wallet Monero Testnet Environment${NC}\n"

# --- Configuration ---
MONERO_PATH="$HOME/monero-testnet"
WALLET_DIR="$MONERO_PATH/rpc_wallets"
RPC_PORT="18082"  # Single RPC server on one port
declare -a WALLETS=("buyer" "vendor" "arbiter")

# --- Find Binaries ---
MONEROD=$(find "$MONERO_PATH" -name "monerod" -type f | head -n 1)
WALLET_RPC=$(find "$MONERO_PATH" -name "monero-wallet-rpc" -type f | head -n 1)

if [[ -z "$MONEROD" || -z "$WALLET_RPC" ]]; then
    echo -e "${RED}❌ Monero binaries not found in $MONERO_PATH${NC}"
    echo -e "${YELLOW}Please run ./scripts/ubuntu-setup.sh first.${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Monero binaries found.${NC}\n"

# --- 1. Start Daemon ---
echo -e "${YELLOW}1️⃣ Starting testnet daemon...${NC}"
if pgrep -x "monerod" > /dev/null; then
    echo -e "${GREEN}   ✅ Daemon already running${NC}"
else
    "$MONEROD" --testnet --detach --log-file "$MONERO_PATH/monerod.log"
    echo -e "${CYAN}   Waiting for daemon (10s)...${NC}"
    sleep 10
    echo -e "${GREEN}   ✅ Daemon started${NC}"
fi
echo ""

# --- 2. Clean Up Old Processes and Wallets ---
echo -e "${YELLOW}2️⃣ Cleaning up old environment...${NC}"
CLEANUP_SCRIPT="$(dirname "$0")/cleanup-monero.sh"
if [ -f "$CLEANUP_SCRIPT" ]; then
    chmod +x "$CLEANUP_SCRIPT"
    "$CLEANUP_SCRIPT"
    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ Cleanup failed. Please run cleanup-monero.sh manually.${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}⚠️  cleanup-monero.sh not found, using basic cleanup...${NC}"
    pkill -9 -f monero-wallet-rpc 2>/dev/null || true
    sleep 3
    rm -rf "$WALLET_DIR"
    mkdir -p "$WALLET_DIR"
    echo -e "${GREEN}   ✅ Basic cleanup done.${NC}"
fi
echo ""

# --- 3. Start SINGLE RPC Server with --wallet-dir ---
echo -e "${YELLOW}3️⃣ Starting RPC service...${NC}"
echo -e "${CYAN}   Starting wallet RPC on port $RPC_PORT with --wallet-dir...${NC}"

"$WALLET_RPC" \
    --testnet \
    --rpc-bind-ip 127.0.0.1 \
    --rpc-bind-port "$RPC_PORT" \
    --disable-rpc-login \
    --daemon-address 127.0.0.1:28081 \
    --wallet-dir "$WALLET_DIR" \
    --log-file "$MONERO_PATH/wallet-rpc.log" \
    --detach

echo -e "${CYAN}   Waiting for RPC to initialize (8s)...${NC}"
sleep 8
echo -e "${GREEN}   ✅ RPC service launched.${NC}\n"

# --- 4. Create Wallets via RPC ---
echo -e "${YELLOW}4️⃣ Creating wallets via RPC...${NC}"

for WALLET_NAME in "${WALLETS[@]}"; do
    echo -e "${CYAN}   Creating wallet '$WALLET_NAME'...${NC}"

    # Create wallet
    CREATE_RESPONSE=$(curl -s -X POST "http://127.0.0.1:$RPC_PORT/json_rpc" \
        -H 'Content-Type: application/json' \
        -d '{
            "jsonrpc":"2.0",
            "id":"0",
            "method":"create_wallet",
            "params":{
                "filename":"'$WALLET_NAME'",
                "password":"",
                "language":"English"
            }
        }')

    # Check for errors
    if echo "$CREATE_RESPONSE" | grep -q '"error"'; then
        ERROR_MSG=$(echo "$CREATE_RESPONSE" | grep -oP '(?<="message":")[^"]+')
        echo -e "${RED}   ❌ Failed to create $WALLET_NAME: $ERROR_MSG${NC}"
    else
        echo -e "${GREEN}   ✅ $WALLET_NAME created${NC}"
    fi

    # Open the wallet to get its address
    OPEN_RESPONSE=$(curl -s -X POST "http://127.0.0.1:$RPC_PORT/json_rpc" \
        -H 'Content-Type: application/json' \
        -d '{
            "jsonrpc":"2.0",
            "id":"0",
            "method":"open_wallet",
            "params":{
                "filename":"'$WALLET_NAME'",
                "password":""
            }
        }')

    sleep 1
done
echo -e "\n${GREEN}   ✅ All wallets created.${NC}\n"

# --- 5. Health Checks ---
echo -e "${YELLOW}5️⃣ Performing health checks...${NC}"
echo -e "${CYAN}   Testing each wallet...${NC}\n"

ALL_OK=true
for WALLET_NAME in "${WALLETS[@]}"; do
    echo -e "${CYAN}   Checking $WALLET_NAME...${NC}"

    # Open wallet
    curl -s -X POST "http://127.0.0.1:$RPC_PORT/json_rpc" \
        -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":"0","method":"open_wallet","params":{"filename":"'$WALLET_NAME'","password":""}}' > /dev/null

    sleep 1

    # Get address
    response=$(curl -s --max-time 5 \
        -X POST "http://127.0.0.1:$RPC_PORT/json_rpc" \
        -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":"0","method":"get_address"}')

    if [[ -z "$response" ]] || ! echo "$response" | grep -q "address"; then
        echo -e "${RED}   ❌ Failed to get address for $WALLET_NAME${NC}"
        echo -e "${YELLOW}      Check log: $MONERO_PATH/wallet-rpc.log${NC}"
        ALL_OK=false
    else
        ADDRESS=$(echo "$response" | grep -oP '(?<="address": ")([a-zA-Z0-9]+)' | head -n 1)
        echo -e "${GREEN}   ✅ $WALLET_NAME OK - Address: ${ADDRESS:0:12}...${NC}"
    fi
done

echo ""

if [ "$ALL_OK" = true ]; then
    echo -e "${GREEN}✅ All 3 wallets are working correctly!${NC}"
    echo -e "\n${CYAN}📋 Summary:${NC}"
    echo "  - RPC Server: http://127.0.0.1:$RPC_PORT"
    echo "  - Wallet Directory: $WALLET_DIR"
    echo "  - Wallets: buyer, vendor, arbiter"
    echo ""
    echo -e "${YELLOW}💡 Usage:${NC}"
    echo "  Use RPC calls to open_wallet before each operation:"
    echo "  curl -X POST http://127.0.0.1:$RPC_PORT/json_rpc -d '{\"method\":\"open_wallet\",\"params\":{\"filename\":\"buyer\"}}'"
    echo ""
    exit 0
else
    echo -e "${RED}❌ One or more wallets failed health check. Check logs.${NC}"
    exit 1
fi
