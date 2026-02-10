#!/usr/bin/env bash
#
# AUDIT PRAGMATIQUE - Monero Marketplace
# Script d'audit qui FONCTIONNE vraiment - Version finale
#

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; NC='\033[0m'

CRITICAL=0; HIGH=0; MEDIUM=0

error() { echo -e "${R}✗ CRITIQUE:${NC} $*"; ((CRITICAL++)); }
warn() { echo -e "${Y}⚠ WARNING:${NC} $*"; ((HIGH++)); }
info() { echo -e "${B}ℹ INFO:${NC} $*"; ((MEDIUM++)); }
ok() { echo -e "${G}✓${NC} $*"; }
section() { echo; echo -e "${B}━━━ $* ━━━${NC}"; }

echo "╔════════════════════════════════════════════════════╗"
echo "║      AUDIT PRAGMAT IQUE - Monero Marketplace      ║"
echo "╚════════════════════════════════════════════════════╝"

# ============================================================================
# 1. DATABASE
# ============================================================================
section "1. DATABASE (bloqueur critique)"

[[ ! -f "server/src/schema.rs" ]] && error "schema.rs MANQUANT!" || {
    tables=$(grep -c "diesel::table!" server/src/schema.rs 2>/dev/null || echo "0")
    [[ "$tables" -lt 5 ]] && error "schema.rs incomplet ($tables tables)" || ok "schema.rs OK ($tables tables)"
}

[[ ! -f "marketplace.db" ]] && error "marketplace.db MANQUANT!" || ok "marketplace.db OK ($(du -h marketplace.db | cut -f1))"

if command -v diesel &>/dev/null; then
    pending=$(DATABASE_URL=marketplace.db diesel migration list 2>/dev/null | grep -c "\[ \]" || echo "0")
    [[ "$pending" -gt 0 ]] && error "$pending migrations non appliquées" || ok "Migrations OK"
fi

# ============================================================================
# 2. CONFIGURATION
# ============================================================================
section "2. CONFIGURATION (.env)"

[[ ! -f ".env" ]] && error ".env MANQUANT!" || ok ".env présent"

git ls-files --error-unmatch .env &>/dev/null && error ".env dans git!" || ok ".env pas tracké"

if [[ -f ".env" ]]; then
    grep -q "^DB_ENCRYPTION_KEY=" .env && ok "DB_ENCRYPTION_KEY OK" || error "DB_ENCRYPTION_KEY manquant"
    grep -q "^JWT_SECRET=" .env && ok "JWT_SECRET OK" || warn "JWT_SECRET manquant"
fi

# ============================================================================
# 3. MONERO
# ============================================================================
section "3. MONERO"

grep -rq "127.0.0.1.*18082\|localhost.*18082" --include="*.rs" . 2>/dev/null && ok "RPC localhost" || warn "RPC config à vérifier"

multisig=$(grep -r "prepare_multisig\|make_multisig" --include="*.rs" . 2>/dev/null | wc -l || echo "0")
[[ "$multisig" -gt 10 ]] && ok "Multisig implémenté ($multisig refs)" || warn "Multisig incomplet ($multisig refs)"

# ============================================================================
# 4. TOR
# ============================================================================
section "4. TOR"

pgrep -x "tor" >/dev/null && ok "Tor actif" || error "Tor PAS actif!"

ss -tulpn 2>/dev/null | grep -q ":9050" && ok "SOCKS 9050 OK" || warn "Port 9050 absent"

public=$(ss -tulpn 2>/dev/null | grep -c "0.0.0.0:8080\|0.0.0.0:18082" || echo "0")
[[ "$public" -gt 0 ]] && error "$public services sur 0.0.0.0!" || ok "Pas de services publics"

# ============================================================================
# 5. TESTS
# ============================================================================
section "5. TESTS"

test_files=$(find . -name "*.rs" -path "*/src/*" -exec grep -l "#\[test\]" {} \; 2>/dev/null | wc -l || echo "0")
[[ "$test_files" -eq 0 ]] && warn "Aucun test unitaire" || ok "$test_files fichiers avec tests"

[[ -f "server/tests/escrow_e2e.rs" ]] && ok "Tests E2E escrow présents" || warn "Tests E2E absents"

# ============================================================================
# 6. SÉCURITÉ
# ============================================================================
section "6. SÉCURITÉ"

if [[ -f "server.log" ]]; then
    grep -iq "private_key\|spend_key\|view_key" server.log 2>/dev/null && error "CLÉS PRIVÉES dans logs!" || ok "Logs OK"
fi

grep -rq "csrf\|CsrfToken" --include="*.rs" ./server 2>/dev/null && ok "CSRF protection" || warn "Pas de CSRF"

# ============================================================================
# RÉSUMÉ
# ============================================================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "           ${B}RÉSUMÉ${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo -e "${R}Critiques:${NC} $CRITICAL"
echo -e "${Y}Warnings:${NC}  $HIGH"
echo -e "${B}Info:${NC}      $MEDIUM"
echo

score=$((100 - CRITICAL * 30 - HIGH * 10 - MEDIUM * 3))
[[ $score -lt 0 ]] && score=0

if [[ "$CRITICAL" -eq 0 ]] && [[ "$HIGH" -eq 0 ]]; then
    echo -e "${G}✓ EXCELLENT${NC} - Score: $score/100"
elif [[ "$CRITICAL" -eq 0 ]]; then
    echo -e "${Y}⚠ BON${NC} - Score: $score/100"
else
    echo -e "${R}✗ BLOQUÉ${NC} - Score: $score/100"
    echo "  ${CRITICAL} problèmes critiques à corriger!"
fi

echo
echo "Audit: $(date '+%Y-%m-%d %H:%M:%S')"

[[ "$CRITICAL" -gt 0 ]] && exit 1
[[ "$HIGH" -gt 3 ]] && exit 2
exit 0
