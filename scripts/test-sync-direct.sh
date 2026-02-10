#!/bin/bash
# Test direct de la synchronisation multisig via les logs du serveur

ESCROW_ID="32eff079-b7d0-4b8a-9bc0-095e0e2ebdab"

echo "=========================================="
echo "Test de synchronisation multisig directe"
echo "=========================================="
echo ""
echo "Escrow ID: $ESCROW_ID"
echo ""

# Créer un script Rust temporaire pour tester
cat > /tmp/test_sync.rs << 'EOF'
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Cette approche nécessite d'accéder au WalletManager...
    // Pour l'instant, utilisons les RPC directement
    println!("Test de sync multisig...");
    Ok(())
}
EOF

echo "La méthode sync_multisig_wallets est implémentée dans:"
echo "  server/src/wallet_manager.rs:941-1092"
echo ""
echo "Pour tester sans authentification, on va utiliser les RPC directement:"
echo ""

# Test manuel de sync via RPC
echo "=== Étape 1: Export multisig info de chaque wallet ==="
echo ""

BUYER_PORT=18082
VENDOR_PORT=18083
ARBITER_PORT=18084

# Export buyer
echo "📤 Export de buyer..."
buyer_export=$(curl -s http://127.0.0.1:$BUYER_PORT/json_rpc -d '{
  "jsonrpc":"2.0",
  "id":"0",
  "method":"export_multisig_info"
}' | jq -r '.result.info' 2>/dev/null)

if [ -z "$buyer_export" ] || [ "$buyer_export" = "null" ]; then
    echo "❌ Erreur: buyer export failed"
    exit 1
fi
echo "✅ Buyer export: ${#buyer_export} caractères"

# Export vendor
echo "📤 Export de vendor..."
vendor_export=$(curl -s http://127.0.0.1:$VENDOR_PORT/json_rpc -d '{
  "jsonrpc":"2.0",
  "id":"0",
  "method":"export_multisig_info"
}' | jq -r '.result.info' 2>/dev/null)

if [ -z "$vendor_export" ] || [ "$vendor_export" = "null" ]; then
    echo "❌ Erreur: vendor export failed"
    exit 1
fi
echo "✅ Vendor export: ${#vendor_export} caractères"

# Export arbiter
echo "📤 Export de arbiter..."
arbiter_export=$(curl -s http://127.0.0.1:$ARBITER_PORT/json_rpc -d '{
  "jsonrpc":"2.0",
  "id":"0",
  "method":"export_multisig_info"
}' | jq -r '.result.info' 2>/dev/null)

if [ -z "$arbiter_export" ] || [ "$arbiter_export" = "null" ]; then
    echo "❌ Erreur: arbiter export failed"
    exit 1
fi
echo "✅ Arbiter export: ${#arbiter_export} caractères"

echo ""
echo "=== Étape 2: Import croisé ==="
echo ""

# Buyer imports vendor + arbiter
echo "📥 Buyer importe vendor + arbiter..."
curl -s http://127.0.0.1:$BUYER_PORT/json_rpc -d "{
  \"jsonrpc\":\"2.0\",
  \"id\":\"0\",
  \"method\":\"import_multisig_info\",
  \"params\":{\"info\":[\"$vendor_export\",\"$arbiter_export\"]}
}" | jq '.result.n_outputs' > /dev/null 2>&1 && echo "✅ Buyer import OK" || echo "❌ Buyer import FAILED"

# Vendor imports buyer + arbiter
echo "📥 Vendor importe buyer + arbiter..."
curl -s http://127.0.0.1:$VENDOR_PORT/json_rpc -d "{
  \"jsonrpc\":\"2.0\",
  \"id\":\"0\",
  \"method\":\"import_multisig_info\",
  \"params\":{\"info\":[\"$buyer_export\",\"$arbiter_export\"]}
}" | jq '.result.n_outputs' > /dev/null 2>&1 && echo "✅ Vendor import OK" || echo "❌ Vendor import FAILED"

# Arbiter imports buyer + vendor
echo "📥 Arbiter importe buyer + vendor..."
curl -s http://127.0.0.1:$ARBITER_PORT/json_rpc -d "{
  \"jsonrpc\":\"2.0\",
  \"id\":\"0\",
  \"method\":\"import_multisig_info\",
  \"params\":{\"info\":[\"$buyer_export\",\"$vendor_export\"]}
}" | jq '.result.n_outputs' > /dev/null 2>&1 && echo "✅ Arbiter import OK" || echo "❌ Arbiter import FAILED"

echo ""
echo "=== Étape 3: Vérification du balance après sync ==="
echo ""

# Check buyer balance
buyer_balance=$(curl -s http://127.0.0.1:$BUYER_PORT/json_rpc -d '{
  "jsonrpc":"2.0",
  "id":"0",
  "method":"get_balance"
}' | jq -r '.result.balance' 2>/dev/null)

buyer_xmr=$(echo "scale=12; $buyer_balance / 1000000000000" | bc 2>/dev/null)

echo "💰 Buyer balance: $buyer_balance atomic units ($buyer_xmr XMR)"

if [ "$buyer_balance" -gt 0 ]; then
    echo ""
    echo "🎉 SUCCESS! Les XMR sont maintenant visibles!"
    echo "   Balance: $buyer_xmr XMR"
else
    echo ""
    echo "⚠️  Balance toujours à 0 après sync"
    echo "   Vérifie que la transaction est confirmée sur la blockchain"
fi

echo ""
echo "Pour voir le balance de tous les wallets:"
echo "  bash scripts/check-multisig-balance.sh $ESCROW_ID"
