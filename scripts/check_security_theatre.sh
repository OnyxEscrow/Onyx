#!/bin/bash
# scripts/check_security_theatre.sh

set -e
echo "🔍 Démarrage du scan de sécurité avancé..."

# 1. Vérification des outils requis
check_command() {
    if ! command -v $1 &> /dev/null; then
        echo "❌ $1 n'est pas installé. Installation recommandée: $2"
        return 1
    fi
}

check_command "grep" "sudo apt-get install grep"
check_command "find" "sudo apt-get install findutils"

# 2. Vérification de l'argument --with-audit
RUN_AUDIT=0
if [[ "$1" == "--with-audit" ]]; then
    RUN_AUDIT=1
    check_command "cargo" "https://rustup.rs/"
    
    if ! cargo audit --version &> /dev/null; then
        echo "🛠️ Installation de cargo-audit..."
        cargo install cargo-audit --locked
    fi
    
    echo "🔎 Vérification des vulnérabilités connues (cargo audit)..."
    cargo audit || {
        echo "⚠️ Des vulnérabilités ont été trouvées. Pour les ignorer, exécutez sans --with-audit"
        exit 1
    }
    echo "✅ Aucune vulnérabilité critique trouvée dans les dépendances"
fi

# 3. Détection des problèmes de sécurité
echo "🔍 Analyse du code source..."

# a) Mots de passe et clés en dur
echo "\n🔑 RECHERCHE DE SECRETS EN DUR"
echo "============================"
SECRET_PATTERNS=(
    "password[[:space:]]*=[[:space:]]*['\"].+['\"]"
    "secret[[:space:]]*=[[:space:]]*['\"].+['\"]"
    "token[[:space:]]*=[[:space:]]*['\"].+['\"]"
    "api[_-]?key[[:space:]]*=[[:space:]]*['\"].+['\"]"
    "private[_-]?key[[:space:]]*=[[:space:]]*['\"].+['\"]"
    "arbiter.*password"
    "encryption.*key"
)

FOUND_SECRETS=0
for pattern in "${SECRET_PATTERNS[@]}"; do
    echo "\n🔎 Recherche: $pattern"
    if grep -nHrI --color=always --exclude-dir=target --exclude-dir=.git --exclude=Cargo.lock \
        -E "$pattern" .; then
        FOUND_SECRETS=1
    fi
done

# b) Gestion dangereuse des erreurs
echo "\n⚠️ ERREURS NON GÉRÉES (unwrap/expect/panic)"
echo "================================"
FOUND_UNWRAPS=0
if grep -nHrI --color=always --exclude-dir=target --exclude-dir=.git \
    -E "\\.unwrap\(|\\.expect\(|\\bpanic\(\)" src/; then
    FOUND_UNWRAPS=1
fi

# c) TODOs et FIXMEs critiques
echo "\n📝 TODOS CRITIQUES (SECURITY)"
echo "=========================="
FOUND_TODOS=0
if grep -nHrI --color=always --exclude-dir=target --exclude-dir=.git \
    -E "TODO\\(SECURITY\\)|FIXME\\(SECURITY\\)|XXX\\(SECURITY\\)" .; then
    FOUND_TODOS=1
fi

# d) Fichiers sensibles
echo "\n🔒 FICHIERS SENSIBLES TROUVÉS"
echo "========================"
find . -type f \( -name "*.key" -o -name "*.pem" -o -name "*.crt" \) -ls -exec ls -la {} \; 2>/dev/null || true

# e) Vérification des variables d'environnement
echo "\n🌐 VARIABLES D'ENVIRONNEMENT REQUISES"
echo "================================"
REQUIRED_ENV=(
    "DATABASE_URL"
    "DB_ENCRYPTION_KEY"
    "JWT_SECRET"
    "MONERO_RPC_USER"
    "MONERO_RPC_PASS"
)

MISSING_ENV=0
for var in "${REQUIRED_ENV[@]}"; do
    if ! grep -rq "$var" .; then
        echo "❌ $var n'est pas référencé dans le code mais est probablement nécessaire"
        MISSING_ENV=1
    fi
done

# Résumé
echo "\n📊 RÉSUMÉ DE L'ANALYSE"
echo "=================="

if [ $FOUND_SECRETS -eq 1 ]; then
    echo "❌ Des secrets potentiels ont été trouvés dans le code"
else
    echo "✅ Aucun secret détecté dans le code"
fi

if [ $FOUND_UNWRAPS -eq 1 ]; then
    echo "⚠️  Des appels potentiellement dangereux (unwrap/expect/panic) détectés"
else
    echo "✅ Aucun appel dangereux détecté"
fi

if [ $FOUND_TODOS -eq 1 ]; then
    echo "📝 Des TODOs critiques ont été trouvés"
else
    echo "✅ Aucun TODO critique trouvé"
fi

if [ $MISSING_ENV -eq 1 ]; then
    echo "🌐 Des variables d'environnement requises pourraient manquer"
else
    echo "✅ Toutes les variables d'environnement requises sont référencées"
fi

echo "\n✅ Analyse de sécurité terminée"

# Code de sortie basé sur les problèmes trouvés
if [ $FOUND_SECRETS -eq 1 ] || [ $MISSING_ENV -eq 1 ]; then
    exit 1
else
    exit 0
fi
