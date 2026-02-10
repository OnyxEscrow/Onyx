#!/bin/bash
# Script d'aide pour démarrer Phase 1 de la migration non-custodiale
# Date: 2025-11-08
# Usage: ./scripts/start-phase1-noncustodial.sh

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}   Migration Non-Custodial - Phase 1: Dual Mode Setup${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# 1. Vérifier qu'on est sur master
echo -e "${YELLOW}[1/7]${NC} Vérification branche master..."
CURRENT_BRANCH=$(git branch --show-current)
if [ "$CURRENT_BRANCH" != "master" ]; then
    echo -e "${RED}❌ Erreur: Vous devez être sur la branche master${NC}"
    echo -e "   Branche actuelle: ${CURRENT_BRANCH}"
    exit 1
fi
echo -e "${GREEN}✅ Sur branche master${NC}"
echo ""

# 2. Créer branche feature
echo -e "${YELLOW}[2/7]${NC} Création branche feature/noncustodial-phase1..."
BRANCH_NAME="feature/noncustodial-phase1-$(date +%Y%m%d)"

if git show-ref --verify --quiet refs/heads/$BRANCH_NAME; then
    echo -e "${YELLOW}⚠️  La branche $BRANCH_NAME existe déjà${NC}"
    read -p "Voulez-vous la réutiliser? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${RED}Annulé${NC}"
        exit 1
    fi
    git checkout $BRANCH_NAME
else
    git checkout -b $BRANCH_NAME
fi
echo -e "${GREEN}✅ Branche $BRANCH_NAME active${NC}"
echo ""

# 3. Créer structure de répertoires
echo -e "${YELLOW}[3/7]${NC} Création structure Phase 1..."
mkdir -p server/src/coordination
mkdir -p server/tests/noncustodial

echo -e "${GREEN}✅ Répertoires créés:${NC}"
echo "   - server/src/coordination/"
echo "   - server/tests/noncustodial/"
echo ""

# 4. Créer fichiers squelettes
echo -e "${YELLOW}[4/7]${NC} Création fichiers squelettes..."

# coordination/mod.rs
cat > server/src/coordination/mod.rs << 'EOF'
//! Non-custodial escrow coordination
//!
//! This module provides the EscrowCoordinator which acts as a pure coordinator
//! for client-side wallets, inspired by Haveno DEX architecture.
//!
//! **IMPORTANT:** This is the non-custodial implementation. The server NEVER
//! creates or manages wallets - it only coordinates multisig info exchange.

pub mod escrow_coordinator;

pub use escrow_coordinator::EscrowCoordinator;
EOF

# coordination/escrow_coordinator.rs
cat > server/src/coordination/escrow_coordinator.rs << 'EOF'
//! Non-custodial escrow coordinator
//!
//! Inspired by Haveno DEX architecture:
//! - Server coordinates multisig info exchange ONLY
//! - Clients run their own monero-wallet-rpc instances
//! - Private keys NEVER leave client wallets
//! - Server validates but doesn't perform crypto operations

use monero_marketplace_common::error::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Pure coordinator for non-custodial escrow
pub struct EscrowCoordinator {
    coordinations: Arc<RwLock<HashMap<String, EscrowCoordination>>>,
}

/// Coordination state for one escrow
pub struct EscrowCoordination {
    pub escrow_id: String,
    pub buyer_rpc_url: Option<String>,
    pub seller_rpc_url: Option<String>,
    pub arbiter_rpc_url: Option<String>,
    pub state: CoordinationState,
}

/// States of coordination process
#[derive(Debug, Clone, PartialEq)]
pub enum CoordinationState {
    AwaitingRegistrations,
    AllRegistered,
    Prepared,
    Ready,
}

impl EscrowCoordinator {
    /// Create new coordinator
    pub fn new() -> Self {
        Self {
            coordinations: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a client wallet (Phase 1 skeleton)
    pub async fn register_client_wallet(
        &self,
        escrow_id: &str,
        role: &str,
        rpc_url: String,
    ) -> Result<()> {
        info!("📝 Registering {} wallet for escrow {}", role, escrow_id);

        // TODO Phase 1:
        // 1. Validate localhost with validate_localhost_strict()
        // 2. Check RPC connectivity
        // 3. Store URL (not the wallet!)

        let mut coords = self.coordinations.write().await;
        let coord = coords
            .entry(escrow_id.to_string())
            .or_insert_with(|| EscrowCoordination {
                escrow_id: escrow_id.to_string(),
                buyer_rpc_url: None,
                seller_rpc_url: None,
                arbiter_rpc_url: None,
                state: CoordinationState::AwaitingRegistrations,
            });

        match role {
            "buyer" => coord.buyer_rpc_url = Some(rpc_url),
            "seller" => coord.seller_rpc_url = Some(rpc_url),
            "arbiter" => coord.arbiter_rpc_url = Some(rpc_url),
            _ => warn!("Unknown role: {}", role),
        }

        Ok(())
    }

    /// Coordinate multisig exchange (Phase 1 skeleton)
    pub async fn coordinate_exchange(&self, escrow_id: &str) -> Result<String> {
        info!("🔄 Coordinating multisig exchange for escrow {}", escrow_id);

        // TODO Phase 1:
        // 1. Verify 3 wallets registered
        // 2. Request prepare_multisig from each
        // 3. Validate formats
        // 4. Exchange infos

        Ok("Exchange coordinated (skeleton)".to_string())
    }
}

impl Default for EscrowCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_coordinator_creation() {
        let coordinator = EscrowCoordinator::new();
        assert!(coordinator.coordinations.read().await.is_empty());
    }

    #[tokio::test]
    async fn test_register_wallet() {
        let coordinator = EscrowCoordinator::new();
        let result = coordinator
            .register_client_wallet(
                "escrow_123",
                "buyer",
                "http://127.0.0.1:18083".to_string(),
            )
            .await;
        assert!(result.is_ok());
    }
}
EOF

# Test squelette
cat > server/tests/noncustodial/mod.rs << 'EOF'
//! Non-custodial escrow tests
//!
//! These tests verify the non-custodial coordinator functionality.
//! They require local monero-wallet-rpc instances.

#[cfg(test)]
mod escrow_coordinator_tests {
    #[tokio::test]
    #[ignore] // Requires manual setup
    async fn test_full_noncustodial_flow() {
        // TODO Phase 1:
        // 1. Start 3 local wallet-rpc instances
        // 2. Register each with coordinator
        // 3. Coordinate exchange
        // 4. Verify multisig created locally
    }
}
EOF

echo -e "${GREEN}✅ Fichiers squelettes créés${NC}"
echo ""

# 5. Ajouter coordination au server/src/lib.rs
echo -e "${YELLOW}[5/7]${NC} Mise à jour server/src/lib.rs..."

if ! grep -q "pub mod coordination" server/src/lib.rs; then
    echo "pub mod coordination;" >> server/src/lib.rs
    echo -e "${GREEN}✅ Module coordination ajouté${NC}"
else
    echo -e "${YELLOW}⚠️  Module coordination déjà présent${NC}"
fi
echo ""

# 6. Vérifier compilation
echo -e "${YELLOW}[6/7]${NC} Vérification compilation..."
if cargo check --package server --quiet; then
    echo -e "${GREEN}✅ Compilation réussie${NC}"
else
    echo -e "${RED}❌ Erreur de compilation${NC}"
    echo -e "${YELLOW}Corrigez les erreurs avant de continuer${NC}"
    exit 1
fi
echo ""

# 7. Résumé et prochaines étapes
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✅ Phase 1 Setup Complete!${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${GREEN}Fichiers créés:${NC}"
echo "  📁 server/src/coordination/mod.rs"
echo "  📁 server/src/coordination/escrow_coordinator.rs"
echo "  📁 server/tests/noncustodial/mod.rs"
echo ""
echo -e "${YELLOW}Prochaines étapes:${NC}"
echo ""
echo "1. Implémenter validation localhost dans register_client_wallet():"
echo "   ${BLUE}use crate::validation::validate_localhost_strict;${NC}"
echo ""
echo "2. Ajouter routes API dans server/src/main.rs:"
echo "   ${BLUE}.route(\"/api/escrow/register-wallet\", web::post().to(handlers::register_wallet))${NC}"
echo ""
echo "3. Tester avec:"
echo "   ${BLUE}cargo test --package server coordination${NC}"
echo ""
echo "4. Lire le plan complet:"
echo "   ${BLUE}cat DOX/guides/MIGRATION-NON-CUSTODIAL-PLAN.md${NC}"
echo ""
echo -e "${GREEN}Bonne migration! 🚀${NC}"
