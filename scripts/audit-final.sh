#!/usr/bin/env bash
#
# AUDIT FINAL - Monero Marketplace
# Script d'audit DEFINITIF qui teste VRAIMENT ce qui compte
#
# Ce script a été créé après avoir appris de tous les échecs précédents:
# - audit-pragmatic.sh: Ne lance pas cargo test (trop optimiste)
# - swissy.sh: Faux positifs massifs
# - suissemade.sh: Security theatre (2164 lignes inutiles)
#
# Ce script teste LES VRAIES DOULEURS:
# 1. Le code compile-t-il ?
# 2. Les tests passent-ils ?
# 3. Le serveur démarre-t-il ?
# 4. Les routes critiques fonctionnent-elles ?
# 5. La base de données est-elle OK ?
#
# Usage: ./scripts/audit-final.sh [--quick|--full]
#   --quick: Compilation + DB seulement (~10s)
#   --full:  Tous les tests (~2min)
#   (default: tests essentiels ~30s)
#

set +e  # Ne pas crash sur erreurs (on les compte)
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Couleurs
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; P='\033[0;35m'; NC='\033[0m'

# Compteurs
CRITICAL=0; HIGH=0; MEDIUM=0; LOW=0

# Mode
MODE="${1:---normal}"
QUICK=false
FULL=false
[[ "$MODE" == "--quick" ]] && QUICK=true
[[ "$MODE" == "--full" ]] && FULL=true

# Helpers
error() { echo -e "${R}✗ CRITIQUE:${NC} $*"; ((CRITICAL++)); }
warn() { echo -e "${Y}⚠ WARNING:${NC} $*"; ((HIGH++)); }
info() { echo -e "${B}ℹ INFO:${NC} $*"; ((MEDIUM++)); }
ok() { echo -e "${G}✓${NC} $*"; }
section() { echo; echo -e "${P}━━━ $* ━━━${NC}"; }
progress() { echo -e "${B}  →${NC} $*"; }

# Header
clear
echo "╔═══════════════════════════════════════════════════════╗"
echo "║       AUDIT FINAL - Monero Marketplace v2.0           ║"
echo "║         Tests RÉELS - Pas de Security Theatre         ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo
[[ "$QUICK" == "true" ]] && echo "Mode: QUICK (compilation + DB)"
[[ "$FULL" == "true" ]] && echo "Mode: FULL (tous les tests)"
[[ "$QUICK" == "false" ]] && [[ "$FULL" == "false" ]] && echo "Mode: NORMAL (tests essentiels)"

START_TIME=$(date +%s)

# ============================================================================
# 1. INFRASTRUCTURE CRITIQUE
# ============================================================================
section "1. INFRASTRUCTURE CRITIQUE"

# schema.rs
if [[ ! -f "server/src/schema.rs" ]]; then
    error "server/src/schema.rs MANQUANT!"
    echo "  Fix: DATABASE_URL=marketplace.db diesel print-schema > server/src/schema.rs"
elif [[ ! -s "server/src/schema.rs" ]]; then
    error "server/src/schema.rs est VIDE!"
else
    tables=$(grep -c "diesel::table!" server/src/schema.rs 2>/dev/null || echo "0")
    if [[ "$tables" -lt 5 ]]; then
        warn "schema.rs incomplet ($tables tables, attendu 6+)"
    else
        ok "schema.rs OK ($tables tables)"
    fi
fi

# Database
if [[ ! -f "marketplace.db" ]]; then
    error "marketplace.db MANQUANT!"
    echo "  Fix: diesel setup && diesel migration run"
else
    db_size=$(du -h marketplace.db | cut -f1)
    ok "marketplace.db OK ($db_size)"

    # Integrity
    if command -v sqlite3 &>/dev/null; then
        if sqlite3 marketplace.db "PRAGMA integrity_check;" 2>/dev/null | grep -q "ok"; then
            ok "Intégrité DB OK"
        else
            error "Intégrité DB corrompue!"
        fi
    fi
fi

# Migrations
if command -v diesel &>/dev/null; then
    pending=$(DATABASE_URL=marketplace.db diesel migration list 2>/dev/null | grep "\[ \]" | wc -l || echo "0")
    pending=$(echo "$pending" | tr -d ' \n')
    if [[ "$pending" -gt 0 ]]; then
        error "$pending migrations NON appliquées!"
        echo "  Fix: DATABASE_URL=marketplace.db diesel migration run"
    else
        ok "Migrations à jour"
    fi
else
    info "diesel CLI absent (skip migration check)"
fi

# diesel.toml
[[ ! -f "diesel.toml" ]] && warn "diesel.toml manquant (recommandé)" || ok "diesel.toml présent"

# .env
if [[ ! -f ".env" ]]; then
    error ".env MANQUANT!"
    echo "  Fix: cp .env.example .env"
else
    ok ".env présent"

    # .env dans git?
    if git ls-files --error-unmatch .env &>/dev/null; then
        error ".env TRACKÉ PAR GIT! SECRETS EXPOSÉS!"
        echo "  Fix: git rm --cached .env"
    else
        ok ".env pas dans git"
    fi

    # Secrets configurés?
    missing=()
    grep -q "^DATABASE_URL=" .env || missing+=("DATABASE_URL")
    grep -q "^DB_ENCRYPTION_KEY=" .env || missing+=("DB_ENCRYPTION_KEY")
    grep -q "^JWT_SECRET=" .env || missing+=("JWT_SECRET")

    if [[ ${#missing[@]} -gt 0 ]]; then
        error "Variables manquantes: ${missing[*]}"
    else
        ok "Variables critiques OK"
    fi
fi

# ============================================================================
# 2. COMPILATION
# ============================================================================
section "2. COMPILATION"

progress "Compilation workspace (30s max)..."
if timeout 45 cargo check --workspace --quiet 2>&1 | grep -qi "error"; then
    error "Code NE COMPILE PAS!"
    echo "  Détails: cargo check"
else
    ok "Code compile"
fi

# Clippy (seulement erreurs, pas warnings)
progress "Clippy (erreurs seulement)..."
clippy_errors=$(cargo clippy --workspace --quiet 2>&1 | grep -c "^error" || echo "0")
if [[ "$clippy_errors" -gt 0 ]]; then
    error "Clippy: $clippy_errors erreurs"
else
    ok "Clippy: pas d'erreurs"
fi

[[ "$QUICK" == "true" ]] && {
    echo
    echo "Mode QUICK: Skip tests et serveur live"
    echo "Pour tests complets: ./scripts/audit-final.sh --full"
    jump_to_summary=true
}

# ============================================================================
# 3. TESTS UNITAIRES
# ============================================================================
if [[ "$jump_to_summary" != "true" ]]; then
    section "3. TESTS UNITAIRES"

    if [[ "$FULL" == "true" ]]; then
        progress "Tests complets (peut prendre 2 min)..."
        test_output=$(cargo test --workspace 2>&1 || true)
    else
        progress "Tests lib seulement (30s)..."
        test_output=$(cargo test --workspace --lib 2>&1 || true)
    fi

    if echo "$test_output" | grep -q "test result: FAILED"; then
        failed=$(echo "$test_output" | grep "test result:" | grep -oP '\d+ failed' | grep -oP '\d+' | head -1 || echo "0")
        error "$failed tests ÉCHOUENT!"
        echo "  Le code a des bugs - voir: cargo test"

        # Montrer quels tests échouent
        echo "$test_output" | grep "test.*FAILED" | head -5 | sed 's/^/    /'
    elif echo "$test_output" | grep -q "test result: ok"; then
        passed=$(echo "$test_output" | grep "test result:" | grep -oP '\d+ passed' | grep -oP '\d+' | head -1 || echo "0")
        ok "$passed tests passent"
    else
        warn "Impossible de parser résultat tests"
    fi

    # Warnings (seulement si --full)
    if [[ "$FULL" == "true" ]]; then
        warnings=$(echo "$test_output" | grep -c "^warning:" || echo "0")
        [[ "$warnings" -gt 20 ]] && warn "$warnings warnings compilateur"
    fi
fi

# ============================================================================
# 4. SERVEUR LIVE (test des routes réelles)
# ============================================================================
if [[ "$jump_to_summary" != "true" ]]; then
    section "4. SERVEUR LIVE (routes réelles)"

    # Kill anciens serveurs
    pkill -9 server 2>/dev/null || true
    sleep 2

    # Build release si absent
    if [[ ! -f "./target/release/server" ]]; then
        progress "Build release (1 min)..."
        if ! cargo build --release --package server --quiet 2>&1 | grep -qi "error"; then
            ok "Release binary créé"
        else
            error "Build release échoué"
        fi
    fi

    # Lancer serveur
    if [[ -f "./target/release/server" ]]; then
        progress "Démarrage serveur..."
        ./target/release/server > /tmp/audit_server.log 2>&1 &
        SERVER_PID=$!
        sleep 5

        # Test health
        if curl -s --max-time 3 http://localhost:8080/ 2>/dev/null | grep -qi "monero\|marketplace\|login\|register"; then
            ok "Serveur démarre (page d'accueil OK)"
        else
            warn "Serveur démarre mais page d'accueil vide"
        fi

        # Test register PAGE (GET)
        status=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/register 2>/dev/null)
        if [[ "$status" == "200" ]]; then
            ok "Page /register accessible (HTTP $status)"
        else
            warn "Page /register status: $status"
        fi

        # Test login PAGE (GET)
        status=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/login 2>/dev/null)
        if [[ "$status" == "200" ]]; then
            ok "Page /login accessible (HTTP $status)"
        else
            warn "Page /login status: $status"
        fi

        # Test si listings page existe
        status=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/listings 2>/dev/null)
        if [[ "$status" == "200" ]]; then
            ok "Page /listings accessible (HTTP $status)"
        elif [[ "$status" == "404" ]]; then
            info "Page /listings absente (normal si pas implémentée)"
        else
            info "Page /listings status: $status"
        fi

        # Killer serveur
        kill $SERVER_PID 2>/dev/null || true
        sleep 1
    else
        error "Binary release absent - impossible de tester serveur live"
    fi
fi

# ============================================================================
# 5. SÉCURITÉ (checks rapides)
# ============================================================================
if [[ "$jump_to_summary" != "true" ]] && [[ "$FULL" == "true" ]]; then
    section "5. SÉCURITÉ"

    # Tor
    if pgrep -x "tor" >/dev/null; then
        ok "Tor actif"
    else
        warn "Tor PAS actif (nécessaire pour prod)"
    fi

    # Ports publics
    if command -v ss &>/dev/null; then
        public=$(ss -tulpn 2>/dev/null | grep -c "0.0.0.0:8080\|0.0.0.0:18082" || echo "0")
        if [[ "$public" -gt 0 ]]; then
            error "$public services sur 0.0.0.0 (public)!"
        else
            ok "Pas de services publics exposés"
        fi
    fi

    # Clés dans logs
    if [[ -f "server.log" ]]; then
        if grep -iq "private_key\|spend_key\|view_key" server.log 2>/dev/null; then
            error "CLÉS PRIVÉES dans logs!"
        else
            ok "Logs propres (pas de clés)"
        fi
    fi

    # CSRF
    if grep -rq "csrf\|CsrfToken" --include="*.rs" ./server 2>/dev/null; then
        ok "Protection CSRF présente"
    else
        warn "Pas de protection CSRF détectée"
    fi
fi

# ============================================================================
# RÉSUMÉ & SCORE
# ============================================================================
section "RÉSUMÉ"

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo
echo "Durée: ${DURATION}s"
echo
echo -e "${R}Critiques (bloqueurs):${NC}  $CRITICAL"
echo -e "${Y}Warnings (important):${NC}   $HIGH"
echo -e "${B}Info (amélioration):${NC}    $MEDIUM"
echo

# Calcul score
score=100
score=$((score - CRITICAL * 30))
score=$((score - HIGH * 10))
score=$((score - MEDIUM * 3))
[[ $score -lt 0 ]] && score=0

# Grade
if [[ $score -ge 90 ]]; then
    grade="A+"; color="$G"
elif [[ $score -ge 80 ]]; then
    grade="A"; color="$G"
elif [[ $score -ge 70 ]]; then
    grade="B"; color="$Y"
elif [[ $score -ge 60 ]]; then
    grade="C"; color="$Y"
else
    grade="F"; color="$R"
fi

echo -e "Score: ${color}${score}/100${NC} (Grade: ${color}${grade}${NC})"
echo

# Verdict
if [[ "$CRITICAL" -eq 0 ]] && [[ "$HIGH" -eq 0 ]]; then
    echo -e "${G}✓ EXCELLENT${NC} - Projet en excellent état"
    echo "  Prêt pour staging/testnet"
elif [[ "$CRITICAL" -eq 0 ]]; then
    echo -e "${Y}⚠ BON${NC} - Fonctionnel avec quelques améliorations"
    echo "  Peut tourner mais corriger les warnings avant prod"
else
    echo -e "${R}✗ BLOQUÉ${NC} - ${CRITICAL} problèmes critiques"
    echo "  CORRIGER AVANT DE CONTINUER"
    echo
    echo "Actions prioritaires:"
    [[ ! -f "server/src/schema.rs" ]] && echo "  1. Générer schema.rs"
    [[ ! -f "marketplace.db" ]] && echo "  2. Créer base de données"
    grep -q "test result: FAILED" <(echo "$test_output") && echo "  3. Fixer les tests qui échouent"
fi

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Audit terminé: $(date '+%Y-%m-%d %H:%M:%S')"
[[ -f "/tmp/audit_server.log" ]] && echo "Logs serveur: /tmp/audit_server.log"

# Exit codes
[[ "$CRITICAL" -gt 0 ]] && exit 1
[[ "$HIGH" -gt 5 ]] && exit 2
exit 0
