#!/bin/bash
# Script de build optimisé pour Monero Marketplace
# Linux - WSL Ubuntu

set -euo pipefail

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Fonction pour afficher les messages
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

log_build() {
    echo -e "${CYAN}🔨 $1${NC}"
}

# Fonction d'aide
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help     Afficher cette aide"
    echo "  -d, --dev      Build de développement (défaut)"
    echo "  -r, --release  Build de production optimisé"
    echo "  -t, --test     Build et lancer les tests"
    echo "  -c, --check    Vérification rapide (cargo check)"
    echo "  -f, --format   Formater le code"
    echo "  -l, --lint     Lancer Clippy"
    echo "  -a, --all      Build complet avec tous les checks"
    echo ""
    echo "Exemples:"
    echo "  $0 --dev       # Build de développement"
    echo "  $0 --release   # Build de production"
    echo "  $0 --all       # Build complet avec tests et linting"
}

# Variables par défaut
BUILD_MODE="dev"
RUN_TESTS=false
RUN_LINT=false
RUN_FORMAT=false
RUN_CHECK=false
RUN_ALL=false

# Parser les arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -d|--dev)
            BUILD_MODE="dev"
            shift
            ;;
        -r|--release)
            BUILD_MODE="release"
            shift
            ;;
        -t|--test)
            RUN_TESTS=true
            shift
            ;;
        -c|--check)
            RUN_CHECK=true
            shift
            ;;
        -f|--format)
            RUN_FORMAT=true
            shift
            ;;
        -l|--lint)
            RUN_LINT=true
            shift
            ;;
        -a|--all)
            RUN_ALL=true
            shift
            ;;
        *)
            log_error "Option inconnue: $1"
            show_help
            exit 1
            ;;
    esac
done

# Si --all est spécifié, activer tous les checks
if [[ "$RUN_ALL" == true ]]; then
    RUN_TESTS=true
    RUN_LINT=true
    RUN_FORMAT=true
    RUN_CHECK=true
fi

echo "🚀 Monero Marketplace - Build Optimisé"
echo "======================================"

# Vérifier que nous sommes dans le bon répertoire
if [[ ! -f "Cargo.toml" ]]; then
    log_error "Ce script doit être exécuté depuis la racine du projet"
    exit 1
fi

# Vérifier que Cargo est installé
if ! command -v cargo &> /dev/null; then
    log_error "Cargo n'est pas installé"
    exit 1
fi

# Afficher les informations système
log_info "Système: $(uname -a)"
log_info "Rust: $(rustc --version)"
log_info "Cargo: $(cargo --version)"
log_info "Mode de build: $BUILD_MODE"

# Nettoyer le cache si nécessaire
if [[ "$BUILD_MODE" == "release" ]]; then
    log_build "Nettoyage du cache pour build release..."
    cargo clean
fi

# Formater le code si demandé
if [[ "$RUN_FORMAT" == true ]]; then
    log_build "Formatage du code..."
    cargo fmt --all
    log_success "Code formaté"
fi

# Vérification rapide si demandée
if [[ "$RUN_CHECK" == true ]]; then
    log_build "Vérification rapide (cargo check)..."
    cargo check --workspace
    log_success "Vérification terminée"
fi

# Linting avec Clippy si demandé
if [[ "$RUN_LINT" == true ]]; then
    log_build "Linting avec Clippy..."
    cargo clippy --workspace -- -D warnings
    log_success "Linting terminé"
fi

# Build principal
log_build "Compilation en mode $BUILD_MODE..."
if [[ "$BUILD_MODE" == "release" ]]; then
    cargo build --workspace --release
    log_success "Build de production terminé"
else
    cargo build --workspace
    log_success "Build de développement terminé"
fi

# Tests si demandés
if [[ "$RUN_TESTS" == true ]]; then
    log_build "Lancement des tests..."
    cargo test --workspace
    log_success "Tous les tests passent"
fi

# Afficher les binaires générés
echo ""
log_info "Binaires générés:"
if [[ "$BUILD_MODE" == "release" ]]; then
    find target/release -name "monero-marketplace*" -type f -executable 2>/dev/null || true
    find target/release -name "cli" -type f -executable 2>/dev/null || true
else
    find target/debug -name "monero-marketplace*" -type f -executable 2>/dev/null || true
    find target/debug -name "cli" -type f -executable 2>/dev/null || true
fi

# Résumé final
echo ""
log_success "Build terminé avec succès !"
log_info "Prêt pour le développement Monero Marketplace"

# Afficher les prochaines étapes
echo ""
echo "📋 Prochaines étapes recommandées:"
echo "  1. Installer Monero CLI: sudo apt install monero"
echo "  2. Configurer Tor: sudo systemctl enable tor"
echo "  3. Tester les fonctionnalités: cargo test --workspace"
echo "  4. Lancer le CLI: cargo run --bin cli"
