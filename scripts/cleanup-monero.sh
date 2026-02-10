#!/usr/bin/env bash
# scripts/cleanup-monero.sh
# Forcefully kills all Monero-related processes and frees up ports.

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}🧹 Cleaning up Monero processes and ports...${NC}\n"

# --- Ports to clean ---
declare -a PORTS_TO_CLEAN=("18081" "18082" "18083" "18084" "28081")

# --- Kill processes by port ---
echo -e "${YELLOW}1. Killing processes by port...${NC}"
for PORT in "${PORTS_TO_CLEAN[@]}"; do
    # Get PID listening on the port
    PID=$(lsof -t -i :"$PORT")

    if [ -n "$PID" ]; then
        echo -e "${CYAN}   Found process with PID $PID on port $PORT. Killing...${NC}"
        # Kill the process forcefully
        kill -9 "$PID"
        echo -e "${GREEN}   ✅ Killed PID $PID.${NC}"
    else
        echo -e "${GREEN}   ✅ Port $PORT is already free.${NC}"
    fi
done
echo ""

# --- Kill processes by name (fallback) ---
echo -e "${YELLOW}2. Force-killing remaining Monero processes by name...${NC}"

# Kill wallet RPC servers
if pgrep -f "monero-wallet-rpc" > /dev/null; then
    pkill -9 -f monero-wallet-rpc
    echo -e "${GREEN}   ✅ All 'monero-wallet-rpc' processes killed.${NC}"
else
    echo -e "${GREEN}   No 'monero-wallet-rpc' processes found. ✅${NC}"
fi

# Kill the daemon
if pgrep -f "monerod" > /dev/null; then
    pkill -9 -f monerod
    echo -e "${GREEN}   ✅ All 'monerod' processes killed.${NC}"
else
    echo -e "${GREEN}   No 'monerod' processes found. ✅${NC}"
fi

echo ""
echo -e "${GREEN}✅ Cleanup complete!${NC}"
exit 0