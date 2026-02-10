#!/usr/bin/env bash
#
# AUDIT RÉALISTE - Monero Marketplace
# Ce script vérifie les VRAIS problèmes qui bloquent le développement
#
# Basé sur les douleurs réelles identifiées:
# 1. schema.rs manquant ou désynchronisé
# 2. Migrations non appliquées
# 3. Tests E2E qui ne compilent pas
# 4. Secrets dans git
# 5. Configuration manquante
#
# Usage: ./scripts/audit-real.sh [--verbose]
#

set -e  # Exit on error (mais pas pipefail pour éviter les blocages)

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Couleurs simples
R='\033[0;31m'
G='\033[0;32m'
Y='\033[1;33m'
B='\033[0;34m'
NC='\033[0m'

VERBOSE=false
[[ "${1:-}" == "--verbose" ]] && VERBOSE=true

CRITICAL=0
HIGH=0
MEDIUM=0

error() {
    echo -e "${R}✗ CRITIQUE:${NC} $*"
    ((CRITICAL++))
}

warn() {
    echo -e "${Y}⚠ WARNING:${NC} $*"
    ((HIGH++))
}

info() {
    echo -e "${B}ℹ INFO:${NC} $*"
    ((MEDIUM++))
}

ok() {
    echo -e "${G}✓${NC} $*"
}

section() {
    echo
    echo -e "${B}━━━ $* ━━━${NC}"
}

# ============================================================================
# VÉRIFICATION 1: DIESEL + DATABASE (Douleur #1)
# ============================================================================

check_database_setup() {
    section "1. DIESEL + DATABASE (bloqueur critique)"

    # schema.rs au BON endroit
    if [[ ! -f "server/src/schema.rs" ]]; then
        error "server/src/schema.rs MANQUANT!"
        echo "  Fix: DATABASE_URL=marketplace.db diesel print-schema > server/src/schema.rs"
        return
    fi

    # Vérifier qu'il n'est pas vide
    if [[ ! -s "server/src/schema.rs" ]]; then
        error "server/src/schema.rs est VIDE!"
        return
    fi

    # Compter les tables
    local tables=$(grep -c "diesel::table!" server/src/schema.rs 2>/dev/null || echo "0")
    if [[ "$tables" -lt 5 ]]; then
        error "schema.rs n'a que $tables tables (attendu: 6+)"
    else
        ok "schema.rs présent avec $tables tables"
    fi

    # Database existe
    if [[ ! -f "marketplace.db" ]]; then
        error "marketplace.db MANQUANT!"
        echo "  Fix: diesel setup && diesel migration run"
        return
    fi

    ok "marketplace.db existe ($(du -h marketplace.db | cut -f1))"

    # Migrations (si diesel installé)
    if command -v diesel &> /dev/null; then
        local pending=$(DATABASE_URL=marketplace.db diesel migration list 2>/dev/null | grep -c "\[ \]" 2>/dev/null || echo "0")
        pending=$(echo "$pending" | tr -d '\n ')
        if [[ "$pending" -gt 0 ]]; then
            error "$pending migrations NON APPLIQUÉES!"
            echo "  Fix: DATABASE_URL=marketplace.db diesel migration run"
        else
            ok "Toutes les migrations appliquées"
        fi
    else
        info "diesel CLI absent - impossible de vérifier les migrations"
    fi

    # diesel.toml (optionnel mais recommandé)
    if [[ ! -f "diesel.toml" ]]; then
        warn "diesel.toml manquant (recommandé pour la config)"
    else
        ok "diesel.toml présent"
    fi
}

# ============================================================================
# VÉRIFICATION 2: COMPILATION (Douleur #2)
# ============================================================================

check_compilation() {
    section "2. COMPILATION (bloqueur critique)"

    if ! command -v cargo &> /dev/null; then
        error "cargo non installé!"
        return
    fi

    # cargo check rapide (pas de build complet)
    echo "  Vérification de la compilation (peut prendre 30s)..."
    if cargo check --quiet --workspace 2>&1 | grep -q "error"; then
        error "Le code NE COMPILE PAS!"
        echo "  Voir les erreurs: cargo check"
    else
        ok "Le code compile (cargo check)"
    fi

    # Vérifier spécifiquement les tests E2E
    echo "  Vérification des tests E2E..."
    if cargo check --tests --quiet 2>&1 | grep -q "error\|could not compile"; then
        error "Les TESTS E2E ne compilent pas!"
        echo "  Problème connu: NewListing manque le champ images_ipfs_cids"
        echo "  Fix: Éditer server/tests/escrow_e2e.rs"
    else
        ok "Les tests E2E compilent"
    fi
}

# ============================================================================
# VÉRIFICATION 3: CONFIGURATION (.env) (Douleur #3)
# ============================================================================

check_configuration() {
    section "3. CONFIGURATION (.env)"

    # .env existe
    if [[ ! -f ".env" ]]; then
        error ".env MANQUANT!"
        echo "  Fix: cp .env.example .env"
        return
    fi

    ok ".env présent"

    # .env pas dans git (CRITIQUE)
    if git ls-files --error-unmatch .env &>/dev/null; then
        error ".env est TRACKÉ PAR GIT! SECRETS EXPOSÉS!"
        echo "  Fix: git rm --cached .env"
    else
        ok ".env pas dans git (bon)"
    fi

    # Secrets configurés
    local missing=()

    if ! grep -q "^DATABASE_URL=" .env; then
        missing+=("DATABASE_URL")
    fi

    if ! grep -q "^DB_ENCRYPTION_KEY=" .env; then
        missing+=("DB_ENCRYPTION_KEY")
    else
        local key_len=$(grep "^DB_ENCRYPTION_KEY=" .env | cut -d'=' -f2 | tr -d '\n' | wc -c)
        if [[ "$key_len" -lt 32 ]]; then
            warn "DB_ENCRYPTION_KEY trop court ($key_len chars)"
        fi
    fi

    if ! grep -q "^JWT_SECRET=" .env; then
        missing+=("JWT_SECRET")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        error "Variables manquantes dans .env: ${missing[*]}"
    else
        ok "Toutes les variables critiques présentes"
    fi
}

# ============================================================================
# VÉRIFICATION 4: SÉCURITÉ MONERO (Douleur #4)
# ============================================================================

check_monero_security() {
    section "4. SÉCURITÉ MONERO"

    # RPC localhost only
    if grep -rq "http://127.0.0.1:18082\|http://localhost:18082" --include="*.rs" . 2>/dev/null; then
        ok "RPC Monero sur localhost (sécurisé)"
    else
        warn "Configuration RPC Monero introuvable ou non localhost"
    fi

    # Multisig implémenté
    local multisig_count=$(grep -r "prepare_multisig\|make_multisig\|export_multisig" --include="*.rs" . 2>/dev/null | wc -l || echo "0")
    if [[ "$multisig_count" -gt 10 ]]; then
        ok "Multisig implémenté ($multisig_count références)"
    else
        warn "Multisig incomplet ou absent ($multisig_count références)"
    fi

    # Clés privées PAS dans les logs
    if [[ -f "server.log" ]]; then
        if grep -iq "private_key\|spend_key\|view_key" server.log 2>/dev/null; then
            error "CLÉS PRIVÉES DANS LES LOGS!"
        else
            ok "Pas de clés privées dans les logs"
        fi
    fi
}

# ============================================================================
# VÉRIFICATION 5: TOR (Douleur #5)
# ============================================================================

check_tor() {
    section "5. TOR (anonymat)"

    # Tor daemon actif
    if pgrep -x "tor" > /dev/null; then
        ok "Tor daemon actif"

        # SOCKS port accessible
        if ss -tulpn 2>/dev/null | grep -q ":9050"; then
            ok "Port SOCKS 9050 accessible"
        else
            warn "Port SOCKS 9050 pas accessible"
        fi
    else
        error "Tor daemon PAS actif!"
        echo "  Fix: sudo systemctl start tor"
    fi

    # Pas de services publics exposés
    local public=$(ss -tulpn 2>/dev/null | grep -c "0.0.0.0:8080\|0.0.0.0:18082" || echo "0")
    if [[ "$public" -gt 0 ]]; then
        error "$public services exposés sur 0.0.0.0 (public)!"
        echo "  Les services doivent être sur 127.0.0.1 uniquement"
    else
        ok "Aucun service exposé publiquement"
    fi
}

# ============================================================================
# VÉRIFICATION 6: TESTS (Douleur #6)
# ============================================================================

check_tests() {
    section "6. TESTS"

    # Tests unitaires
    local test_files=$(find . -name "*.rs" -path "*/src/*" -exec grep -l "#\[test\]" {} \; 2>/dev/null | wc -l || echo "0")
    if [[ "$test_files" -eq 0 ]]; then
        warn "Aucun test unitaire trouvé"
    else
        ok "$test_files fichiers avec tests unitaires"
    fi

    # Tests E2E
    if [[ -f "server/tests/escrow_e2e.rs" ]]; then
        ok "Tests E2E escrow présents"
    else
        warn "Tests E2E escrow absents"
    fi

    # Optionnel: lancer les tests si demandé
    if [[ "$VERBOSE" == "true" ]]; then
        echo "  Lancement des tests (peut prendre 1-2 min)..."
        if cargo test --lib --quiet 2>&1 | grep -q "test result: ok"; then
            ok "Tests unitaires passent"
        else
            warn "Certains tests échouent"
        fi
    fi
}

# ============================================================================
# VÉRIFICATION 7: DÉPENDANCES VULNÉRABLES (Douleur #7)
# ============================================================================

check_dependencies() {
    section "7. DÉPENDANCES VULNÉRABLES"

    if command -v cargo-audit &> /dev/null; then
        local vulns=$(cargo audit 2>&1 | grep -c "error:\|Vulnerability:" || echo "0")
        if [[ "$vulns" -gt 0 ]]; then
            error "$vulns vulnérabilités dans les dépendances"
            echo "  Fix: cargo audit fix"
        else
            ok "Aucune vulnérabilité connue"
        fi
    else
        info "cargo-audit absent (installer: cargo install cargo-audit)"
    fi
}

# ============================================================================
# VÉRIFICATION 8: DOCUMENTATION (Douleur #8)
# ============================================================================

check_documentation() {
    section "8. DOCUMENTATION"

    local missing_docs=()

    [[ ! -f "README.md" ]] && missing_docs+=("README.md")
    [[ ! -f "CLAUDE.md" ]] && missing_docs+=("CLAUDE.md")
    [[ ! -f ".env.example" ]] && missing_docs+=(".env.example")

    if [[ ${#missing_docs[@]} -gt 0 ]]; then
        warn "Documentation manquante: ${missing_docs[*]}"
    else
        ok "Documentation essentielle présente"
    fi
}

# ============================================================================
# RÉSUMÉ FINAL
# ============================================================================

print_summary() {
    echo
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "           ${B}RÉSUMÉ DE L'AUDIT${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo

    local total=$((CRITICAL + HIGH + MEDIUM))

    echo -e "${R}Critiques (bloqueurs):${NC} $CRITICAL"
    echo -e "${Y}Warnings (high):${NC}      $HIGH"
    echo -e "${B}Info (medium):${NC}        $MEDIUM"
    echo

    # Score simple
    local score=100
    ((score -= CRITICAL * 30))
    ((score -= HIGH * 10))
    ((score -= MEDIUM * 3))
    [[ $score -lt 0 ]] && score=0

    # Verdict
    if [[ "$CRITICAL" -eq 0 ]] && [[ "$HIGH" -eq 0 ]]; then
        echo -e "${G}✓ EXCELLENT${NC} - Score: $score/100"
        echo "  Projet prêt pour staging"
    elif [[ "$CRITICAL" -eq 0 ]]; then
        echo -e "${Y}⚠ BON${NC} - Score: $score/100"
        echo "  Quelques améliorations recommandées"
    else
        echo -e "${R}✗ BLOQUÉ${NC} - Score: $score/100"
        echo "  ${CRITICAL} problèmes CRITIQUES à corriger avant de continuer"
    fi

    echo
    echo "Audit terminé: $(date '+%Y-%m-%d %H:%M:%S')"
    echo

    # Exit code
    [[ "$CRITICAL" -gt 0 ]] && exit 1
    [[ "$HIGH" -gt 3 ]] && exit 2
    exit 0
}

# ============================================================================
# MAIN
# ============================================================================

main() {
    echo "╔════════════════════════════════════════════════════╗"
    echo "║        AUDIT RÉALISTE - Monero Marketplace        ║"
    echo "║          Vérifie les VRAIS problèmes              ║"
    echo "╚════════════════════════════════════════════════════╝"

    check_database_setup
    check_compilation
    check_configuration
    check_monero_security
    check_tor
    check_tests
    check_dependencies
    check_documentation

    print_summary
}

main "$@"
