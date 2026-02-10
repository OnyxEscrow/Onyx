#!/bin/bash

# --- Protocole Beta Terminal - Lanceur Guidé ---
# Version: 0.1.0
# Nom de code: Moulinex
# Objectif: Guider l'exécution manuelle du protocole Beta Terminal.

echo "🔬 Lancement du Protocole Beta Terminal (Mode Guidé 'Moulinex')..."
echo "--------------------------------------------------------"
echo "⚠️  Ce script est un guide. L'analyse détaillée de chaque agent reste manuelle."
echo "--------------------------------------------------------"

# --- Pré-requis ---
echo "[ÉTAPE 0/7] Vérification des pré-requis..."
echo "   - Assurez-vous que 'cargo test', 'cargo clippy', 'cargo fmt' passent sans erreur."
echo "   - Vérification de la connexion à Tor..."
curl --socks5-hostname 127.0.0.1:9050 -s https://check.torproject.org/api/ip | grep -q '"IsTor":true'
if [ $? -eq 0 ]; then
    echo "   - ✅ Connexion à Tor réussie."
else
    echo "   - ❌ ERREUR: Impossible de se connecter à Tor. Veuillez démarrer Tor et réessayer."
    exit 1
fi
read -p "   Appuyez sur Entrée pour commencer avec l'Agent 1..."

# --- Exécution des Agents (Guidée) ---

echo ""
echo "[ÉTAPE 1/7] Agent 1: Anti-Hallucination Validator"
echo "   - MISSION: Vérifier que le code est réel (pas d'APIs/fonctions inventées)."
echo "   - ACTION: Examinez manuellement les changements de code. Validez les dépendances sur crates.io."
read -p "   - Une fois terminé, appuyez sur Entrée pour continuer..."

echo ""
echo "[ÉTAPE 2/7] Agent 2: HTMX Template Generator"
echo "   - MISSION: Valider la conformité et la sécurité des templates Tera + HTMX."
echo "   - ACTION: Examinez les fichiers .html pour des attributs HTMX invalides ou des failles XSS."
read -p "   - Une fois terminé, appuyez sur Entrée pour continuer..."

echo ""
echo "[ÉTAPE 3/7] Agent 3: Milestone Tracker"
echo "   - MISSION: Vérifier que la progression déclarée correspond au code implémenté."
echo "   - ACTION: Comparez les tâches du milestone avec le code, les tests et la documentation."
read -p "   - Une fois terminé, appuyez sur Entrée pour continuer..."

echo ""
echo "[ÉTAPE 4/7] Agent 4: Monero Security Validator"
echo "   - MISSION: Auditer l'OPSEC Monero (pas de logs sensibles, RPC local uniquement)."
echo "   - ACTION: Recherchez les logs de données sensibles (.onion, clés). Vérifiez que le RPC est bien sur 127.0.0.1."
read -p "   - Une fois terminé, appuyez sur Entrée pour continuer..."

echo ""
echo "[ÉTAPE 5/7] Agent 5: Production-Ready Enforcer"
echo "   - MISSION: Détecter le code non-production (unwrap, expect, println)."
echo "   - ACTION: Lancez 'cargo clippy --workspace -- -D warnings' et 'cargo test --workspace'."
echo "   - ACTION: Recherchez manuellement les .unwrap(), .expect(), println!() restants."
cargo clippy --workspace -- -D warnings
cargo test --workspace
read -p "   - Une fois les tests et l'analyse terminés, appuyez sur Entrée pour continuer..."

echo ""
echo "[ÉTAPE 6/7] Agent 6: Reality Check Generator"
echo "   - MISSION: Valider l'isolation réseau et l'absence de fuites d'IP."
echo "   - ACTION: Utilisez 'netstat' et 'tcpdump' pour confirmer que le trafic passe par Tor et que les RPCs ne sont pas publics."
read -p "   - Une fois terminé, appuyez sur Entrée pour continuer..."

echo ""
echo "[ÉTAPE 7/7] Finalisation"
echo "--------------------------------------------------------"
echo "✅ Protocole Beta Terminal (Mode Guidé 'Moulinex') terminé."
echo "N'oubliez pas de :"
echo "   1. Calculer le score global pondéré en fonction de vos observations."
echo "   2. Rédiger le rapport de validation."
echo "   3. Corriger les 'blockers' si le score est < 85/100."
echo "--------------------------------------------------------"
