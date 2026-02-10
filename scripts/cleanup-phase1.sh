#!/bin/bash
# Phase 1: Nettoyage fichiers temporaires
# SAFE: Ne touche PAS au code source, templates, static, ou crates

set -e

echo "🧹 Phase 1: Nettoyage fichiers temporaires"
echo "==========================================="
echo ""

# Fonction pour supprimer en toute sécurité
safe_remove() {
    if [ -e "$1" ]; then
        echo "  ❌ Suppression: $1"
        rm -rf "$1"
    else
        echo "  ⏭️  Déjà absent: $1"
    fi
}

echo "📦 1. Binaires et archives..."
safe_remove "buyer"
safe_remove "linux64"
safe_remove "mingw-temp.zip"
safe_remove "go-ipfs_v0.24.0_linux-amd64.tar.gz"

echo ""
echo "📁 2. Dossiers temporaires..."
safe_remove "4.5"
safe_remove "4.s"
safe_remove "archive"
safe_remove "venv"
safe_remove "go-ipfs"
safe_remove "monero-x86_64-linux-gnu-v0.18.4.3"

echo ""
echo "📝 3. Logs..."
safe_remove "*.log"
safe_remove "server*.log"
safe_remove "build.log"
safe_remove "ipfs.log"
safe_remove "monero-wallet-rpc.log"
safe_remove "monero-wallet-cli.log"

echo ""
echo "🗑️  4. Fichiers temporaires..."
safe_remove "test.txt"
safe_remove "cookies.txt"
safe_remove "ma_requette.json"
safe_remove "buyer.keys"
safe_remove "buyer.address.txt"
safe_remove "corrected_torrc.md"
safe_remove "commande.md"
safe_remove "etatglobal.md"
safe_remove "guidtechnique.md"
safe_remove "simple.md"

echo ""
echo "🐍 5. Python temporaire..."
safe_remove "code_validator_mcp.py"
safe_remove "main.py"
safe_remove "models.py"
safe_remove "requirements.txt"

echo ""
echo "📦 6. Node modules..."
safe_remove "node_modules"
safe_remove "package.json"
safe_remove "package-lock.json"

echo ""
echo "💾 7. Bases de données temporaires..."
safe_remove "sqlite:marketplace.db"
safe_remove "data"
safe_remove "database"

echo ""
echo "🔧 8. Scripts d'installation temporaires..."
safe_remove "rustup-init.sh"
safe_remove "install-pipx.sh"
safe_remove "install-node-v22.sh"
safe_remove "install-nodejs-latest.sh"
safe_remove "install-gemini-skill.sh"

echo ""
echo "📂 9. Dossiers vides..."
safe_remove "messagerie"
safe_remove "custodial"

echo ""
echo "✅ Phase 1 terminée!"
echo ""
echo "📊 Vérification..."
du -sh . 2>/dev/null || true
echo ""
echo "⚠️  IMPORTANT: Vérifier que le serveur fonctionne toujours:"
echo "   cargo build --workspace"
echo "   cargo test --workspace --lib"
