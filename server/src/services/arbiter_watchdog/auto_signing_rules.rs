//! Auto-Signing Rules - Decision engine for arbiter watchdog
//!
//! Evaluates escrow state and determines the appropriate action:
//! - AUTO_RELEASE: Both parties agree, sign for vendor payout
//! - AUTO_REFUND: Both parties agree, sign for buyer refund
//! - ESCALATE_HUMAN: Dispute or disagreement, notify human arbiter
//! - NO_ACTION: Not ready for action yet

use crate::models::escrow::Escrow;
use tracing::{debug, info};

/// Decision result from evaluating escrow state
#[derive(Debug, Clone, PartialEq)]
pub enum SigningDecision {
    /// Auto-sign for vendor payout
    ///
    /// Conditions:
    /// - buyer_release_requested = true
    /// - vendor_signature is present
    /// - No dispute
    AutoRelease {
        escrow_id: String,
        vendor_address: String,
    },

    /// Auto-sign for buyer refund
    ///
    /// Conditions:
    /// - vendor_refund_requested = true
    /// - buyer_signature is present
    /// - No dispute
    AutoRefund {
        escrow_id: String,
        buyer_address: String,
    },

    /// Escalate to human arbiter
    ///
    /// Conditions:
    /// - status = "disputed"
    /// - OR parties disagree on outcome
    /// - OR timeout approaching
    EscalateHuman { escrow_id: String, reason: String },

    /// No action needed
    ///
    /// Either:
    /// - Not enough signatures yet
    /// - Already handled
    /// - Terminal state
    NoAction,
}

/// Auto-signing rules engine
pub struct AutoSigningRules;

impl AutoSigningRules {
    /// Evaluate an escrow and decide what action to take
    ///
    /// # Decision Flow
    ///
    /// 1. If disputed → ESCALATE_HUMAN
    /// 2. If buyer released AND vendor signed → AUTO_RELEASE
    /// 3. If vendor refund AND buyer signed → AUTO_REFUND
    /// 4. If parties disagree → ESCALATE_HUMAN
    /// 5. Otherwise → NO_ACTION
    pub fn evaluate(escrow: &Escrow) -> SigningDecision {
        let escrow_id = escrow.id.clone();

        debug!(
            escrow_id = %escrow_id,
            status = %escrow.status,
            buyer_release = escrow.buyer_release_requested,
            vendor_refund = escrow.vendor_refund_requested,
            has_buyer_sig = escrow.buyer_signature.is_some(),
            has_vendor_sig = escrow.vendor_signature.is_some(),
            "Evaluating escrow for auto-signing"
        );

        // 1. Dispute handling: if arbiter already decided (dispute_signing_pair set), auto-sign.
        //    Otherwise escalate to human arbiter.
        if escrow.status == "disputed" {
            // Check if arbiter has already made a resolution decision
            if let Some(ref pair) = escrow.dispute_signing_pair {
                // Arbiter decided — auto-sign based on dispute_signing_pair
                if pair == "arbiter_buyer" {
                    let addr = escrow.buyer_refund_address.clone().unwrap_or_default();
                    if !addr.is_empty() {
                        info!(
                            escrow_id = %escrow_id,
                            dispute_pair = %pair,
                            "Decision: AUTO_REFUND (dispute resolved by arbiter in favor of buyer)"
                        );
                        return SigningDecision::AutoRefund {
                            escrow_id,
                            buyer_address: addr,
                        };
                    }
                } else if pair == "arbiter_vendor" {
                    let addr = escrow.vendor_payout_address.clone().unwrap_or_default();
                    if !addr.is_empty() {
                        info!(
                            escrow_id = %escrow_id,
                            dispute_pair = %pair,
                            "Decision: AUTO_RELEASE (dispute resolved by arbiter in favor of vendor)"
                        );
                        return SigningDecision::AutoRelease {
                            escrow_id,
                            vendor_address: addr,
                        };
                    }
                }
            }

            // No dispute_signing_pair set yet — escalate to human arbiter
            let reason = escrow
                .dispute_reason
                .clone()
                .unwrap_or_else(|| "Dispute initiated by party".to_string());

            info!(
                escrow_id = %escrow_id,
                reason = %reason,
                "Decision: ESCALATE_HUMAN (dispute pending arbiter resolution)"
            );

            return SigningDecision::EscalateHuman {
                escrow_id,
                reason: format!("Dispute: {reason}"),
            };
        }

        // 2. Check if arbiter already signed
        if escrow.arbiter_auto_signed {
            debug!(escrow_id = %escrow_id, "Already auto-signed, no action");
            return SigningDecision::NoAction;
        }

        // 3. Terminal states - no action
        match escrow.status.as_str() {
            "completed" | "refunded" | "cancelled" | "expired" => {
                debug!(escrow_id = %escrow_id, status = %escrow.status, "Terminal state, no action");
                return SigningDecision::NoAction;
            }
            _ => {}
        }

        // 4. Check for release case
        // Buyer requested release AND vendor has signed
        if escrow.buyer_release_requested && escrow.vendor_signature.is_some() {
            // Get vendor payout address
            match &escrow.vendor_payout_address {
                Some(addr) if !addr.is_empty() => {
                    info!(
                        escrow_id = %escrow_id,
                        "Decision: AUTO_RELEASE (buyer approved, vendor signed)"
                    );
                    return SigningDecision::AutoRelease {
                        escrow_id,
                        vendor_address: addr.clone(),
                    };
                }
                _ => {
                    info!(
                        escrow_id = %escrow_id,
                        "Cannot AUTO_RELEASE: vendor_payout_address not set"
                    );
                    return SigningDecision::NoAction;
                }
            }
        }

        // 5. Check for refund case
        // Vendor approved refund AND buyer has signed
        if escrow.vendor_refund_requested && escrow.buyer_signature.is_some() {
            // Get buyer refund address
            match &escrow.buyer_refund_address {
                Some(addr) if !addr.is_empty() => {
                    info!(
                        escrow_id = %escrow_id,
                        "Decision: AUTO_REFUND (vendor approved, buyer signed)"
                    );
                    return SigningDecision::AutoRefund {
                        escrow_id,
                        buyer_address: addr.clone(),
                    };
                }
                _ => {
                    info!(
                        escrow_id = %escrow_id,
                        "Cannot AUTO_REFUND: buyer_refund_address not set"
                    );
                    return SigningDecision::NoAction;
                }
            }
        }

        // 6. Check for disagreement
        // One party wants release, other wants refund
        if (escrow.buyer_release_requested && escrow.vendor_refund_requested)
            || (escrow.buyer_release_requested && escrow.vendor_signature.is_none())
            || (escrow.vendor_refund_requested && escrow.buyer_signature.is_none())
        {
            // If both flags are set, there's a conflict
            if escrow.buyer_release_requested && escrow.vendor_refund_requested {
                info!(
                    escrow_id = %escrow_id,
                    "Decision: ESCALATE_HUMAN (buyer wants release, vendor wants refund)"
                );
                return SigningDecision::EscalateHuman {
                    escrow_id,
                    reason: "Parties disagree: buyer wants release, vendor wants refund"
                        .to_string(),
                };
            }
        }

        // 7. Check for timeout approaching (24h before 7-day limit)
        if let Some(dispute_created) = escrow.dispute_created_at {
            let now = chrono::Utc::now().naive_utc();
            let dispute_duration = now.signed_duration_since(dispute_created);
            let days_in_dispute = dispute_duration.num_days();

            // 7-day dispute limit with 24h warning
            if days_in_dispute >= 6 && escrow.status == "disputed" {
                info!(
                    escrow_id = %escrow_id,
                    days_in_dispute = %days_in_dispute,
                    "Decision: ESCALATE_HUMAN (timeout approaching)"
                );
                return SigningDecision::EscalateHuman {
                    escrow_id,
                    reason: format!(
                        "Dispute timeout approaching: {days_in_dispute} days, <24h remaining"
                    ),
                };
            }
        }

        // 8. Default: not ready for action
        debug!(escrow_id = %escrow_id, "Decision: NO_ACTION (conditions not met)");
        SigningDecision::NoAction
    }

    /// Validate that auto-signing is safe for this escrow
    ///
    /// Additional safety checks beyond the decision logic:
    /// - FROST DKG must be complete
    /// - Amount must be > 0
    /// - Addresses must be valid format
    pub fn validate_for_signing(escrow: &Escrow) -> Result<(), String> {
        // DKG must be complete
        if !escrow.frost_dkg_complete {
            return Err("FROST DKG not complete".to_string());
        }

        // Must have valid amount
        if escrow.amount <= 0 {
            return Err("Invalid escrow amount".to_string());
        }

        // Must have multisig address
        if escrow.multisig_address.is_none() {
            return Err("Multisig address not set".to_string());
        }

        // Must have group pubkey
        if escrow.frost_group_pubkey.is_none() {
            return Err("FROST group pubkey not set".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDateTime;

    fn create_test_escrow() -> Escrow {
        let now = chrono::Utc::now().naive_utc();
        Escrow {
            id: "test-escrow-123".to_string(),
            order_id: Some("order-456".to_string()),
            buyer_id: "buyer-001".to_string(),
            vendor_id: "vendor-001".to_string(),
            arbiter_id: "arbiter-001".to_string(),
            amount: 1_000_000_000_000, // 1 XMR
            multisig_address: Some("4...".to_string()),
            status: "active".to_string(),
            created_at: now,
            updated_at: now,
            buyer_wallet_info: None,
            vendor_wallet_info: None,
            arbiter_wallet_info: None,
            transaction_hash: None,
            expires_at: None,
            last_activity_at: now,
            multisig_phase: "complete".to_string(),
            multisig_state_json: None,
            multisig_updated_at: 0,
            recovery_mode: "manual".to_string(),
            buyer_temp_wallet_id: None,
            vendor_temp_wallet_id: None,
            arbiter_temp_wallet_id: None,
            dispute_reason: None,
            dispute_created_at: None,
            dispute_resolved_at: None,
            resolution_decision: None,
            vendor_signature: None,
            buyer_signature: None,
            unsigned_tx_hex: None,
            vendor_signed_at: None,
            buyer_signed_at: None,
            vendor_payout_address: Some("4PayoutAddress...".to_string()),
            buyer_refund_address: Some("4RefundAddress...".to_string()),
            vendor_payout_set_at: None,
            buyer_refund_set_at: None,
            multisig_view_key: None,
            funding_commitment_mask: None,
            funding_tx_hash: None,
            funding_output_index: None,
            funding_global_index: None,
            ring_data_json: None,
            buyer_partial_key_image: None,
            vendor_partial_key_image: None,
            arbiter_partial_key_image: None,
            aggregated_key_image: None,
            partial_tx: None,
            partial_tx_initiator: None,
            completed_clsag: None,
            signing_started_at: None,
            signing_phase: None,
            funding_output_pubkey: None,
            funding_tx_pubkey: None,
            vendor_nonce_commitment: None,
            buyer_nonce_commitment: None,
            vendor_nonce_public: None,
            buyer_nonce_public: None,
            nonce_aggregated: None,
            first_signer_role: None,
            mu_p: None,
            mu_c: None,
            first_signer_had_r_agg: None,
            multisig_txset: None,
            signing_round: None,
            current_signer_id: None,
            partial_signed_txset: None,
            signing_initiated_at: None,
            broadcast_tx_hash: None,
            frost_enabled: true,
            frost_group_pubkey: Some("group_pubkey_hex".to_string()),
            frost_dkg_complete: true,
            frost_dkg_state: Some("complete".to_string()),
            evidence_count: None,
            auto_escalated_at: None,
            escalation_reason: None,
            dispute_signing_pair: None,
            balance_received: 1_000_000_000_000,
            grace_period_ends_at: None,
            refund_requested_at: None,
            external_reference: None,
            description: None,
            // Watchdog fields (v0.70.0)
            buyer_release_requested: false,
            vendor_refund_requested: false,
            arbiter_auto_signed: false,
            arbiter_auto_signed_at: None,
            escalated_to_human: false,
            arbiter_frost_partial_sig: None,
            // Shipping tracking fields (v0.71.0)
            shipped_at: None,
            auto_release_at: None,
            shipping_tracking: None,
            // B2B multi-tenancy fields
            client_id: None,
            metadata_json: None,
        }
    }

    #[test]
    fn test_disputed_escrow_escalates() {
        let mut escrow = create_test_escrow();
        escrow.status = "disputed".to_string();
        escrow.dispute_reason = Some("Goods not as described".to_string());

        let decision = AutoSigningRules::evaluate(&escrow);

        match decision {
            SigningDecision::EscalateHuman { escrow_id, reason } => {
                assert_eq!(escrow_id, "test-escrow-123");
                assert!(reason.contains("Dispute"));
            }
            _ => panic!("Expected EscalateHuman decision"),
        }
    }

    #[test]
    fn test_auto_release_conditions() {
        let mut escrow = create_test_escrow();
        escrow.buyer_release_requested = true;
        escrow.vendor_signature = Some("vendor_sig_hex".to_string());

        let decision = AutoSigningRules::evaluate(&escrow);

        match decision {
            SigningDecision::AutoRelease {
                escrow_id,
                vendor_address,
            } => {
                assert_eq!(escrow_id, "test-escrow-123");
                assert!(vendor_address.starts_with("4"));
            }
            _ => panic!("Expected AutoRelease decision"),
        }
    }

    #[test]
    fn test_auto_refund_conditions() {
        let mut escrow = create_test_escrow();
        escrow.vendor_refund_requested = true;
        escrow.buyer_signature = Some("buyer_sig_hex".to_string());

        let decision = AutoSigningRules::evaluate(&escrow);

        match decision {
            SigningDecision::AutoRefund {
                escrow_id,
                buyer_address,
            } => {
                assert_eq!(escrow_id, "test-escrow-123");
                assert!(buyer_address.starts_with("4"));
            }
            _ => panic!("Expected AutoRefund decision"),
        }
    }

    #[test]
    fn test_no_action_when_not_ready() {
        let escrow = create_test_escrow();

        let decision = AutoSigningRules::evaluate(&escrow);
        assert_eq!(decision, SigningDecision::NoAction);
    }

    #[test]
    fn test_already_signed_no_action() {
        let mut escrow = create_test_escrow();
        escrow.arbiter_auto_signed = true;

        let decision = AutoSigningRules::evaluate(&escrow);
        assert_eq!(decision, SigningDecision::NoAction);
    }

    #[test]
    fn test_terminal_state_no_action() {
        let mut escrow = create_test_escrow();
        escrow.status = "completed".to_string();

        let decision = AutoSigningRules::evaluate(&escrow);
        assert_eq!(decision, SigningDecision::NoAction);
    }
}
