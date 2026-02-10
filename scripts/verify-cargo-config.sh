#!/bin/bash
# Script de vérification de la configuration Cargo
# Monero Marketplace - Linux

set -euo pipefail

echo "🔧 Vérification de la configuration Cargo..."

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

# Vérifier que Cargo est installé
if ! command -v cargo &> /dev/null; then
    log_error "Cargo n'est pas installé"
    exit 1
fi
log_success "Cargo est installé"

# Vérifier la version de Rust
RUST_VERSION=$(rustc --version | cut -d' ' -f2)
log_info "Version Rust: $RUST_VERSION"

# Vérifier que le fichier de configuration existe
if [[ ! -f ".cargo/config.toml" ]]; then
    log_error "Fichier .cargo/config.toml manquant"
    exit 1
fi
log_success "Configuration Cargo trouvée"

# Vérifier la syntaxe de la configuration
if ! cargo check --quiet 2>/dev/null; then
    log_error "Erreur de syntaxe dans la configuration Cargo"
    cargo check
    exit 1
fi
log_success "Syntaxe de configuration valide"

# Vérifier les toolchains installés
log_info "Toolchains Rust installés:"
rustup show

# Vérifier les targets installés
log_info "Targets installés:"
rustup target list --installed

# Vérifier les composants installés
log_info "Composants installés:"
rustup component list --installed

# Test de compilation rapide
log_info "Test de compilation rapide..."
if cargo check --workspace --quiet; then
    log_success "Compilation de vérification réussie"
else
    log_error "Erreur de compilation"
    cargo check --workspace
    exit 1
fi

# Vérifier Clippy
log_info "Test de Clippy..."
if cargo clippy --workspace --quiet -- -D warnings; then
    log_success "Clippy passe sans erreurs"
else
    log_warning "Clippy a détecté des problèmes"
    cargo clippy --workspace -- -D warnings
fi

# Vérifier les tests
log_info "Test des tests unitaires..."
if cargo test --workspace --quiet; then
    log_success "Tous les tests passent"
else
    log_warning "Certains tests échouent"
    cargo test --workspace
fi

# Vérifier le formatage
log_info "Vérification du formatage..."
if cargo fmt --check --quiet; then
    log_success "Code correctement formaté"
else
    log_warning "Code nécessite un formatage"
    cargo fmt --check
fi

# Résumé
echo ""
log_success "Configuration Cargo optimisée et fonctionnelle !"
log_info "Prêt pour le développement Monero Marketplace sur Linux"

# Afficher les optimisations activées
echo ""
echo "🚀 Optimisations activées:"
echo "  • Compilation incrémentale"
echo "  • Optimisations CPU natives"
echo "  • LTO pour les builds release"
echo "  • Clippy strict (anti-security theatre)"
echo "  • Profils optimisés (dev/release/test/bench)"
echo "  • Variables d'environnement optimisées"
