#!/usr/bin/env bash
#
# AUDIT MOULINEX - Version améliorée qui teste VRAIMENT
# Basé sur les leçons apprises: les fichiers peuvent exister mais les routes ne pas marcher!
#

set -e
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; NC='\033[0m'
CRITICAL=0; HIGH=0; MEDIUM=0

error() { echo -e "${R}✗ CRITIQUE:${NC} $*"; ((CRITICAL++)); }
warn() { echo -e "${Y}⚠ WARNING:${NC} $*"; ((HIGH++)); }
ok() { echo -e "${G}✓${NC} $*"; }
section() { echo; echo -e "${B}━━━ $* ━━━${NC}"; }

echo "╔════════════════════════════════════════════════════╗"
echo "║         AUDIT MOULINEX - Tests Réels              ║"
echo "╚════════════════════════════════════════════════════╝"

# ============================================================================
# 1. COMPILATION
# ============================================================================
section "1. COMPILATION (bloqueur absolu)"

echo "  Compilation (peut prendre 30s)..."
if cargo check --workspace --quiet 2>&1 | grep -q "error"; then
    error "Code ne compile pas!"
    echo "  Voir: cargo check"
else
    ok "Code compile"
fi

# ============================================================================
# 2. TESTS
# ============================================================================
section "2. TESTS (vrais problèmes)"

echo "  Lancement des tests (1 min)..."
TEST_OUTPUT=$(cargo test --workspace --lib 2>&1 || true)

if echo "$TEST_OUTPUT" | grep -q "test result: FAILED"; then
    FAILED=$(echo "$TEST_OUTPUT" | grep "test result:" | grep -oP '\d+ failed' | grep -oP '\d+' || echo "0")
    error "$FAILED tests échouent!"
    echo "  Tests cassés détectés - le code ne marche pas vraiment"
else
    ok "Tests passent"
fi

# ============================================================================
# 3. SERVER EN LIVE (le vrai test!)
# ============================================================================
section "3. SERVEUR EN LIVE (vrais endpoints)"

# Killer tous les serveurs
pkill -9 server 2>/dev/null || true
sleep 2

# Lancer le serveur
if [[ ! -f "./target/release/server" ]]; then
    warn "Binary release absent - building..."
    cargo build --release --package server --quiet
fi

./target/release/server > /tmp/audit_server.log 2>&1 &
SERVER_PID=$!
sleep 4

# Test health
if curl -s --max-time 2 http://localhost:8080/api/health | grep -q "ok\|healthy"; then
    ok "Health endpoint OK"
else
    warn "Health endpoint absent ou cassé"
fi

# Test register route
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:8080/register \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=test&password=test&role=buyer" 2>/dev/null)

if [[ "$STATUS" == "200" ]] || [[ "$STATUS" == "302" ]]; then
    ok "Route /register fonctionne (HTTP $STATUS)"
elif [[ "$STATUS" == "404" ]]; then
    error "Route /register INEXISTANTE (404)!"
else
    warn "Route /register status: $STATUS"
fi

# Test login route
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:8080/login \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=test&password=test" 2>/dev/null)

if [[ "$STATUS" == "200" ]] || [[ "$STATUS" == "302" ]] || [[ "$STATUS" == "401" ]]; then
    ok "Route /login existe (HTTP $STATUS)"
elif [[ "$STATUS" == "404" ]]; then
    error "Route /login INEXISTANTE (404)!"
else
    warn "Route /login status: $STATUS"
fi

# Test listings
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:8080/api/listings \
    -H "Content-Type: application/json" \
    -d '{"title":"Test"}' 2>/dev/null)

if [[ "$STATUS" == "200" ]] || [[ "$STATUS" == "401" ]] || [[ "$STATUS" == "403" ]]; then
    ok "Route /api/listings existe (HTTP $STATUS)"
elif [[ "$STATUS" == "404" ]]; then
    error "Route /api/listings INEXISTANTE (404)!"
elif [[ "$STATUS" == "415" ]]; then
    warn "Route /api/listings refuse JSON (415) - teste form-data"

    # Retry with form-urlencoded
    STATUS2=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:8080/api/listings \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "title=Test&price_xmr=0.1" 2>/dev/null)

    if [[ "$STATUS2" == "200" ]] || [[ "$STATUS2" == "401" ]]; then
        ok "Listings accepte form-urlencoded (HTTP $STATUS2)"
    fi
else
    warn "Route /api/listings status: $STATUS"
fi

# Killer le serveur
kill $SERVER_PID 2>/dev/null || true

# ============================================================================
# 4. DATABASE
# ============================================================================
section "4. DATABASE"

[[ ! -f "server/src/schema.rs" ]] && error "schema.rs MANQUANT!"  || ok "schema.rs OK"
[[ ! -f "marketplace.db" ]] && error "marketplace.db MANQUANT!" || ok "marketplace.db OK"

if command -v diesel &>/dev/null; then
    pending=$(DATABASE_URL=marketplace.db diesel migration list 2>/dev/null | grep -c "\[ \]" || echo "0")
    [[ "$pending" -gt 0 ]] && error "$pending migrations non appliquées" || ok "Migrations OK"
fi

# ============================================================================
# 5. CONFIGURATION
# ============================================================================
section "5. CONFIGURATION"

[[ ! -f ".env" ]] && error ".env MANQUANT!" || ok ".env présent"
git ls-files --error-unmatch .env &>/dev/null && error ".env dans git!" || ok ".env pas tracké"

# ============================================================================
# RÉSUMÉ
# ============================================================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "           ${B}RÉSUMÉ - AUDIT RÉEL${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo -e "${R}Critiques (bloqueurs):${NC} $CRITICAL"
echo -e "${Y}Warnings:${NC}              $HIGH"
echo

score=$((100 - CRITICAL * 30 - HIGH * 10))
[[ $score -lt 0 ]] && score=0

if [[ "$CRITICAL" -eq 0 ]] && [[ "$HIGH" -eq 0 ]]; then
    echo -e "${G}✓ EXCELLENT${NC} - Score: $score/100"
    echo "  Le serveur FONCTIONNE vraiment"
elif [[ "$CRITICAL" -eq 0 ]]; then
    echo -e "${Y}⚠ BON${NC} - Score: $score/100"
    echo "  Quelques problèmes mais fonctionnel"
else
    echo -e "${R}✗ BLOQUÉ${NC} - Score: $score/100"
    echo "  ${CRITICAL} bloqueurs - le serveur ne peut pas fonctionner correctement"
fi

echo
echo "Logs serveur: /tmp/audit_server.log"
echo "Audit: $(date '+%Y-%m-%d %H:%M:%S')"

[[ "$CRITICAL" -gt 0 ]] && exit 1
[[ "$HIGH" -gt 3 ]] && exit 2
exit 0
