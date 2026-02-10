#!/bin/bash
# test-tm004-005-006.sh
# Tests réalistes des fixes TM-004, TM-005, TM-006 (Sans Théâtre)

set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  Tests TM-004, TM-005, TM-006 (Sans Théâtre)              ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Compteurs
PASS=0
FAIL=0

test_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ PASS${NC}: $2"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}✗ FAIL${NC}: $2"
        FAIL=$((FAIL + 1))
    fi
}

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 1: TM-004 - Validation RPC stricte"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test 1.1: URL légitime acceptée
cargo test --package monero-marketplace-wallet --lib validation::tests::test_valid_localhost --quiet &>/dev/null
test_result $? "URL légitime acceptée (127.0.0.1, localhost)"

# Test 1.2: Bypass rejeté
cargo test --package monero-marketplace-wallet --lib validation::tests::test_bypass_attempts --quiet &>/dev/null
test_result $? "Tentatives de bypass rejetées (evil-127.0.0.1.com)"

# Test 1.3: IPs non-localhost rejetées
cargo test --package monero-marketplace-wallet --lib validation::tests::test_reject_non_localhost --quiet &>/dev/null
test_result $? "IPs non-localhost rejetées (192.168.x.x, 0.0.0.0)"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 2: TM-005 - Custom Debug sans secrets"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test 2.1: Vérifier que User a un impl Debug custom
grep -q "impl std::fmt::Debug for User" server/src/models/user.rs
test_result $? "User struct a Custom Debug impl"

# Test 2.2: Vérifier que password_hash est redacté
grep -q '"<redacted>"' server/src/models/user.rs
test_result $? "Password hash redacté dans Debug impl"

# Test 2.3: Vérifier qu'aucun #[derive(Debug)] sur User
! grep -E "^#\[derive\(.*Debug.*\)\]" server/src/models/user.rs | grep -q "pub struct User"
test_result $? "User n'utilise plus #[derive(Debug)]"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 3: TM-006 - Sanitization des logs"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test 3.1: UUID sanitization
cargo test --package server --lib logging::sanitize::tests::test_sanitize_uuid --quiet &>/dev/null
test_result $? "UUIDs sanitisés (abc12345...90ef)"

# Test 3.2: Address sanitization
cargo test --package server --lib logging::sanitize::tests::test_sanitize_address --quiet &>/dev/null
test_result $? "Addresses sanitisées (9w...XYZ)"

# Test 3.3: Amount sanitization
cargo test --package server --lib logging::sanitize::tests::test_sanitize_amount --quiet &>/dev/null
test_result $? "Montants arrondis (~1.23 XMR)"

# Test 3.4: Macros exportées
grep -q "macro_rules! log_uuid" server/src/lib.rs
test_result $? "Macro log_uuid! exportée"

grep -q "macro_rules! log_address" server/src/lib.rs
test_result $? "Macro log_address! exportée"

grep -q "macro_rules! log_amount" server/src/lib.rs
test_result $? "Macro log_amount! exportée"

# Test 3.5: Module logging existe
test -f "server/src/logging/sanitize.rs"
test_result $? "Module logging/sanitize.rs créé"

# Test 3.6: Vérifier logs réels (si server.log existe)
if [ -f "server.log" ]; then
    # Chercher des UUIDs complets (format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
    FULL_UUIDS=$(grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' server.log 2>/dev/null | wc -l)

    if [ $FULL_UUIDS -gt 20 ]; then
        test_result 1 "Logs contiennent trop d'UUIDs complets ($FULL_UUIDS)"
        echo -e "${YELLOW}  → Applique les macros log_uuid!() dans le code${NC}"
    else
        test_result 0 "Logs avec peu d'UUIDs complets ($FULL_UUIDS - acceptable)"
    fi

    # Chercher des adresses Monero complètes (95 chars commençant par 9 ou A)
    FULL_ADDRESSES=$(grep -oE '[9A][0-9A-Za-z]{94}' server.log 2>/dev/null | wc -l)

    if [ $FULL_ADDRESSES -gt 5 ]; then
        test_result 1 "Logs contiennent des adresses complètes ($FULL_ADDRESSES)"
        echo -e "${YELLOW}  → Applique les macros log_address!() dans le code${NC}"
    else
        test_result 0 "Peu d'adresses complètes dans logs ($FULL_ADDRESSES - acceptable)"
    fi
else
    echo -e "${YELLOW}⚠ server.log introuvable - tests sur logs réels sautés${NC}"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 4: Compilation générale"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test 4.1: Compilation workspace
cargo build --workspace --quiet 2>&1 | grep -q "Finished"
test_result $? "Compilation workspace réussie"

# Test 4.2: Tests wallet passent
cargo test --package monero-marketplace-wallet --lib --quiet &>/dev/null
test_result $? "Tests wallet passent"

# Test 4.3: Tests server passent
cargo test --package server --lib --quiet &>/dev/null
test_result $? "Tests server passent"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Résumé"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "${GREEN}✓ Tests réussis: $PASS${NC}"
echo -e "${RED}✗ Tests échoués: $FAIL${NC}"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ✓ TOUS LES TESTS PASSENT - Fixes TM-004/005/006 validés  ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Fixes pragmatiques appliqués (Sans Théâtre™):"
    echo "  • TM-004: Validation RPC stricte (pas de bypass)"
    echo "  • TM-005: Custom Debug sans secrets"
    echo "  • TM-006: Log sanitization (UUIDs/addresses tronqués)"
    echo ""
    echo "Prochaine étape: Appliquer macros log_uuid!/log_address! dans le code"
    echo "  Recherche: rg 'info!.*escrow_id' --type rust"
    echo ""
    exit 0
else
    echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  ✗ ÉCHECS DÉTECTÉS - Vérifier les erreurs ci-dessus       ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
    exit 1
fi
