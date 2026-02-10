#!/bin/bash
# Script de nettoyage et redémarrage propre du serveur
# Usage: ./scripts/restart-server-clean.sh

set -e

echo "🧹 NETTOYAGE COMPLET DES SERVEURS..."
echo ""

# 1. Tuer TOUS les processus serveur
echo "1️⃣  Arrêt de tous les serveurs en cours..."
killall -9 server 2>/dev/null || true
pkill -9 -f "target/release/server" 2>/dev/null || true
pkill -9 -f "target/debug/server" 2>/dev/null || true
sleep 1

# 2. Vérifier le port 8080
echo "2️⃣  Vérification du port 8080..."
if lsof -i :8080 >/dev/null 2>&1; then
    echo "   ⚠️  Port 8080 encore occupé, nettoyage forcé..."
    lsof -ti :8080 | xargs kill -9 2>/dev/null || true
    sleep 1
else
    echo "   ✅ Port 8080 libre"
fi

# 3. Vérifier qu'il n'y a plus de serveurs
echo "3️⃣  Vérification finale..."
RUNNING_SERVERS=$(ps aux | grep -E "[t]arget/release/server|[t]arget/debug/server" | wc -l)
if [ "$RUNNING_SERVERS" -gt 0 ]; then
    echo "   ⚠️  Il reste $RUNNING_SERVERS serveur(s) en cours:"
    ps aux | grep -E "[t]arget/release/server|[t]arget/debug/server" || true
    echo ""
    echo "   Tentative de nettoyage final..."
    ps aux | grep -E "[t]arget/release/server|[t]arget/debug/server" | awk '{print $2}' | xargs kill -9 2>/dev/null || true
    sleep 1
else
    echo "   ✅ Aucun serveur en cours"
fi

# 4. Vérifier que le binaire existe
echo "4️⃣  Vérification du binaire..."
if [ ! -f "./target/release/server" ]; then
    echo "   ❌ Binaire non trouvé: ./target/release/server"
    echo "   Compilation requise: cargo build --release --package server"
    exit 1
else
    echo "   ✅ Binaire trouvé"
    ls -lh ./target/release/server | awk '{print "      Taille:", $5, "| Modifié:", $6, $7, $8}'
fi

echo ""
echo "🚀 DÉMARRAGE DU SERVEUR NEXUS..."
echo ""
echo "   Port: http://127.0.0.1:8080"
echo "   Design: NEXUS (templates/listings/index.html)"
echo "   CSS: static/css/nexus-true.css"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# 5. Démarrer le serveur
exec ./target/release/server
