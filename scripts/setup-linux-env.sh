#!/bin/bash
# Script de configuration de l'environnement Linux
# Monero Marketplace - WSL Ubuntu

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

log_install() {
    echo -e "${CYAN}📦 $1${NC}"
}

echo "🐧 Configuration de l'environnement Linux"
echo "========================================"

# Vérifier que nous sommes sur Ubuntu/Debian
if ! command -v apt &> /dev/null; then
    log_error "Ce script est conçu pour Ubuntu/Debian"
    exit 1
fi

# Mettre à jour le système
log_install "Mise à jour du système..."
sudo apt update && sudo apt upgrade -y
log_success "Système mis à jour"

# Installer les outils de développement essentiels
log_install "Installation des outils de développement..."
sudo apt install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    curl \
    git \
    wget \
    unzip \
    cmake \
    ninja-build \
    clang \
    llvm \
    libclang-dev
log_success "Outils de développement installés"

# Installer Rust si pas déjà installé
if ! command -v cargo &> /dev/null; then
    log_install "Installation de Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source ~/.cargo/env
    log_success "Rust installé"
else
    log_info "Rust déjà installé: $(rustc --version)"
fi

# Installer les composants Rust supplémentaires
log_install "Installation des composants Rust..."
rustup component add rustfmt clippy
rustup target add x86_64-unknown-linux-gnu
log_success "Composants Rust installés"

# Installer Monero CLI (optionnel)
log_install "Installation de Monero CLI..."
if sudo apt install -y monero; then
    log_success "Monero CLI installé"
else
    log_warning "Monero CLI non disponible dans les repos Ubuntu"
    log_info "Vous pouvez l'installer manuellement depuis https://getmonero.org/downloads/"
fi

# Installer et configurer Tor
log_install "Installation et configuration de Tor..."
sudo apt install -y tor
sudo systemctl enable tor
sudo systemctl start tor
log_success "Tor installé et démarré"

# Vérifier le statut de Tor
if systemctl is-active --quiet tor; then
    log_success "Tor est actif"
else
    log_warning "Tor n'est pas actif, vérifiez la configuration"
fi

# Installer des outils utiles pour le développement
log_install "Installation d'outils de développement supplémentaires..."
sudo apt install -y \
    htop \
    tree \
    jq \
    ripgrep \
    fd-find \
    bat \
    exa \
    zsh \
    tmux \
    vim \
    nano
log_success "Outils supplémentaires installés"

# Configurer Git (si pas déjà configuré)
if ! git config --global user.name &> /dev/null; then
    log_info "Configuration de Git..."
    read -p "Nom d'utilisateur Git: " git_name
    read -p "Email Git: " git_email
    git config --global user.name "$git_name"
    git config --global user.email "$git_email"
    log_success "Git configuré"
fi

# Créer les répertoires de travail
log_install "Création des répertoires de travail..."
mkdir -p ~/projects
mkdir -p ~/.local/bin
log_success "Répertoires créés"

# Configurer le PATH
if ! echo "$PATH" | grep -q "$HOME/.local/bin"; then
    log_install "Configuration du PATH..."
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
    export PATH="$HOME/.local/bin:$PATH"
    log_success "PATH configuré"
fi

# Installer des outils Rust utiles
log_install "Installation d'outils Rust utiles..."
cargo install --quiet \
    cargo-watch \
    cargo-expand \
    cargo-audit \
    cargo-outdated \
    cargo-tree \
    cargo-udeps \
    cargo-machete \
    cargo-deny
log_success "Outils Rust installés"

# Configurer les alias utiles
log_install "Configuration des alias..."
cat >> ~/.bashrc << 'EOF'

# Aliases pour Monero Marketplace
alias mm-build='cargo build --workspace'
alias mm-test='cargo test --workspace'
alias mm-check='cargo check --workspace'
alias mm-clippy='cargo clippy --workspace -- -D warnings'
alias mm-fmt='cargo fmt --all'
alias mm-clean='cargo clean'
alias mm-run='cargo run --bin cli'

# Aliases généraux
alias ll='exa -la'
alias la='exa -a'
alias l='exa -l'
alias cat='bat'
alias find='fd'
alias grep='rg'

# Fonction pour build complet
mm-all() {
    echo "🔨 Build complet Monero Marketplace..."
    cargo fmt --all
    cargo clippy --workspace -- -D warnings
    cargo test --workspace
    cargo build --workspace
    echo "✅ Build complet terminé !"
}
EOF
log_success "Aliases configurés"

# Vérifier la configuration
echo ""
log_info "Vérification de la configuration..."

# Vérifier Rust
if command -v rustc &> /dev/null; then
    log_success "Rust: $(rustc --version)"
else
    log_error "Rust non trouvé"
fi

# Vérifier Cargo
if command -v cargo &> /dev/null; then
    log_success "Cargo: $(cargo --version)"
else
    log_error "Cargo non trouvé"
fi

# Vérifier Git
if command -v git &> /dev/null; then
    log_success "Git: $(git --version)"
else
    log_error "Git non trouvé"
fi

# Vérifier Tor
if systemctl is-active --quiet tor; then
    log_success "Tor: Actif"
else
    log_warning "Tor: Inactif"
fi

# Vérifier Monero
if command -v monero-wallet-cli &> /dev/null; then
    log_success "Monero CLI: Installé"
else
    log_warning "Monero CLI: Non installé"
fi

# Résumé final
echo ""
log_success "Configuration de l'environnement Linux terminée !"
echo ""
echo "📋 Prochaines étapes:"
echo "  1. Recharger le shell: source ~/.bashrc"
echo "  2. Aller dans le projet: cd ~/projects/monero-marketplace"
echo "  3. Tester la compilation: mm-build"
echo "  4. Lancer les tests: mm-test"
echo ""
echo "🛠️  Commandes utiles:"
echo "  • mm-build    - Compiler le projet"
echo "  • mm-test     - Lancer les tests"
echo "  • mm-clippy   - Linter avec Clippy"
echo "  • mm-fmt      - Formater le code"
echo "  • mm-all      - Build complet avec tous les checks"
echo ""
echo "🎉 Environnement prêt pour le développement Monero Marketplace !"
