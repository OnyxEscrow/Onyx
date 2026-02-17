// @generated automatically by Diesel CLI.

diesel::table! {
    api_keys (id) {
        id -> Text,
        user_id -> Text,
        name -> Text,
        key_hash -> Text,
        key_prefix -> Text,
        tier -> Text,
        rate_limit_override -> Nullable<Integer>,
        is_active -> Integer,
        expires_at -> Nullable<Text>,
        created_at -> Text,
        last_used_at -> Nullable<Text>,
        total_requests -> Integer,
        metadata -> Nullable<Text>,
        scopes -> Nullable<Text>,
        allowed_origins -> Nullable<Text>,
    }
}

diesel::table! {
    dispute_evidence (id) {
        id -> Text,
        escrow_id -> Text,
        uploader_id -> Text,
        uploader_role -> Text,
        ipfs_cid -> Text,
        file_name -> Text,
        file_size -> Integer,
        mime_type -> Text,
        description -> Nullable<Text>,
        created_at -> Timestamp,
    }
}

diesel::table! {
    encrypted_relay (id) {
        id -> Text,
        escrow_id -> Text,
        encrypted_blob -> Text,
        first_signer_role -> Text,
        first_signer_pubkey -> Text,
        nonce -> Text,
        created_at -> Text,
        expires_at -> Text,
        consumed_at -> Nullable<Text>,
        status -> Text,
    }
}

diesel::table! {
    escrow_chat_keypairs (id) {
        id -> Text,
        escrow_id -> Text,
        user_id -> Text,
        role -> Text,
        public_key -> Text,
        created_at -> Text,
    }
}

diesel::table! {
    escrow_chat_read_receipts (id) {
        id -> Text,
        message_id -> Text,
        user_id -> Text,
        read_at -> Text,
    }
}

diesel::table! {
    escrows (id) {
        id -> Text,
        order_id -> Nullable<Text>,
        buyer_id -> Text,
        vendor_id -> Text,
        arbiter_id -> Text,
        amount -> BigInt,
        multisig_address -> Nullable<Text>,
        status -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        buyer_wallet_info -> Nullable<Binary>,
        vendor_wallet_info -> Nullable<Binary>,
        arbiter_wallet_info -> Nullable<Binary>,
        transaction_hash -> Nullable<Text>,
        expires_at -> Nullable<Timestamp>,
        last_activity_at -> Timestamp,
        multisig_phase -> Text,
        multisig_state_json -> Nullable<Text>,
        multisig_updated_at -> Integer,
        recovery_mode -> Text,
        buyer_temp_wallet_id -> Nullable<Text>,
        vendor_temp_wallet_id -> Nullable<Text>,
        arbiter_temp_wallet_id -> Nullable<Text>,
        dispute_reason -> Nullable<Text>,
        dispute_created_at -> Nullable<Timestamp>,
        dispute_resolved_at -> Nullable<Timestamp>,
        resolution_decision -> Nullable<Text>,
        vendor_signature -> Nullable<Text>,
        buyer_signature -> Nullable<Text>,
        unsigned_tx_hex -> Nullable<Text>,
        vendor_signed_at -> Nullable<Integer>,
        buyer_signed_at -> Nullable<Integer>,
        vendor_payout_address -> Nullable<Text>,
        buyer_refund_address -> Nullable<Text>,
        vendor_payout_set_at -> Nullable<Integer>,
        buyer_refund_set_at -> Nullable<Integer>,
        multisig_view_key -> Nullable<Text>,
        funding_commitment_mask -> Nullable<Text>,
        funding_tx_hash -> Nullable<Text>,
        funding_output_index -> Nullable<Integer>,
        funding_global_index -> Nullable<Integer>,
        ring_data_json -> Nullable<Text>,
        buyer_partial_key_image -> Nullable<Text>,
        vendor_partial_key_image -> Nullable<Text>,
        arbiter_partial_key_image -> Nullable<Text>,
        aggregated_key_image -> Nullable<Text>,
        partial_tx -> Nullable<Text>,
        partial_tx_initiator -> Nullable<Text>,
        completed_clsag -> Nullable<Text>,
        signing_started_at -> Nullable<Integer>,
        signing_phase -> Nullable<Text>,
        balance_received -> BigInt,
        grace_period_ends_at -> Nullable<Timestamp>,
        refund_requested_at -> Nullable<Timestamp>,
        external_reference -> Nullable<Text>,
        description -> Nullable<Text>,
        frost_enabled -> Bool,
        frost_group_pubkey -> Nullable<Text>,
        frost_dkg_complete -> Bool,
        frost_dkg_state -> Nullable<Text>,
        funding_output_pubkey -> Nullable<Text>,
        funding_tx_pubkey -> Nullable<Text>,
        vendor_nonce_commitment -> Nullable<Text>,
        buyer_nonce_commitment -> Nullable<Text>,
        vendor_nonce_public -> Nullable<Text>,
        buyer_nonce_public -> Nullable<Text>,
        nonce_aggregated -> Nullable<Text>,
        first_signer_role -> Nullable<Text>,
        mu_p -> Nullable<Text>,
        mu_c -> Nullable<Text>,
        first_signer_had_r_agg -> Nullable<Integer>,
        multisig_txset -> Nullable<Text>,
        signing_round -> Nullable<Integer>,
        current_signer_id -> Nullable<Text>,
        partial_signed_txset -> Nullable<Text>,
        signing_initiated_at -> Nullable<Text>,
        broadcast_tx_hash -> Nullable<Text>,
        evidence_count -> Nullable<Integer>,
        auto_escalated_at -> Nullable<Timestamp>,
        escalation_reason -> Nullable<Text>,
        dispute_signing_pair -> Nullable<Text>,
        buyer_release_requested -> Bool,
        vendor_refund_requested -> Bool,
        arbiter_auto_signed -> Bool,
        arbiter_auto_signed_at -> Nullable<Timestamp>,
        escalated_to_human -> Bool,
        arbiter_frost_partial_sig -> Nullable<Text>,
        shipped_at -> Nullable<Timestamp>,
        auto_release_at -> Nullable<Timestamp>,
        shipping_tracking -> Nullable<Text>,
        client_id -> Nullable<Text>,
        metadata_json -> Nullable<Text>,
    }
}

diesel::table! {
    frost_dkg_state (escrow_id) {
        escrow_id -> Text,
        buyer_round1_package -> Nullable<Text>,
        vendor_round1_package -> Nullable<Text>,
        arbiter_round1_package -> Nullable<Text>,
        round1_complete -> Bool,
        buyer_to_vendor_round2 -> Nullable<Text>,
        buyer_to_arbiter_round2 -> Nullable<Text>,
        vendor_to_buyer_round2 -> Nullable<Text>,
        vendor_to_arbiter_round2 -> Nullable<Text>,
        arbiter_to_buyer_round2 -> Nullable<Text>,
        arbiter_to_vendor_round2 -> Nullable<Text>,
        round2_complete -> Bool,
        created_at -> Text,
        updated_at -> Text,
    }
}

diesel::table! {
    frost_signing_state (escrow_id) {
        escrow_id -> Nullable<Text>,
        tx_prefix_hash -> Text,
        clsag_message_hash -> Text,
        ring_data_json -> Text,
        pseudo_out -> Nullable<Text>,
        recipient_address -> Text,
        amount_atomic -> Text,
        buyer_nonce_commitment -> Nullable<Text>,
        buyer_r_public -> Nullable<Text>,
        buyer_r_prime_public -> Nullable<Text>,
        vendor_nonce_commitment -> Nullable<Text>,
        vendor_r_public -> Nullable<Text>,
        vendor_r_prime_public -> Nullable<Text>,
        aggregated_r -> Nullable<Text>,
        aggregated_r_prime -> Nullable<Text>,
        buyer_partial_submitted -> Nullable<Bool>,
        vendor_partial_submitted -> Nullable<Bool>,
        arbiter_partial_submitted -> Nullable<Bool>,
        aggregated_key_image -> Nullable<Text>,
        final_clsag_json -> Nullable<Text>,
        broadcasted_tx_hash -> Nullable<Text>,
        status -> Text,
        created_at -> Nullable<Timestamp>,
        updated_at -> Nullable<Timestamp>,
        bulletproof_bytes -> Nullable<Text>,
        pseudo_out_hex -> Nullable<Text>,
        tx_secret_key -> Nullable<Text>,
        ring_indices_json -> Nullable<Text>,
        round_id -> Nullable<Text>,
        signer_set_hash -> Nullable<Text>,
    }
}

diesel::table! {
    login_attempts (id) {
        id -> Text,
        username -> Text,
        ip_address -> Nullable<Text>,
        attempt_type -> Text,
        created_at -> Timestamp,
    }
}

diesel::table! {
    message_keypairs (id) {
        id -> Text,
        user_id -> Text,
        public_key -> Text,
        encrypted_private_key -> Text,
        key_salt -> Text,
        created_at -> Text,
        is_active -> Integer,
    }
}

diesel::table! {
    message_read_receipts (message_id) {
        message_id -> Text,
        read_at -> Text,
    }
}

diesel::table! {
    messages (id) {
        id -> Text,
        escrow_id -> Text,
        sender_id -> Text,
        content -> Text,
        created_at -> Timestamp,
        is_read -> Bool,
    }
}

diesel::table! {
    multisig_challenges (id) {
        id -> Text,
        user_id -> Text,
        escrow_id -> Text,
        nonce -> Binary,
        created_at -> Integer,
        expires_at -> Integer,
    }
}

diesel::table! {
    multisig_participants (id) {
        id -> Text,
        session_id -> Text,
        role -> Text,
        participant_type -> Text,
        wallet_id -> Nullable<Text>,
        user_id -> Nullable<Text>,
        has_submitted_round1 -> Bool,
        has_submitted_round2 -> Bool,
        public_spend_key -> Nullable<Text>,
        multisig_info_round1 -> Nullable<Text>,
        multisig_info_round2 -> Nullable<Text>,
        submitted_at_round1 -> Nullable<Integer>,
        submitted_at_round2 -> Nullable<Integer>,
    }
}

diesel::table! {
    multisig_sessions (id) {
        id -> Text,
        escrow_id -> Text,
        stage -> Text,
        created_at -> Integer,
        updated_at -> Integer,
        timeout_at -> Nullable<Integer>,
        multisig_address -> Nullable<Text>,
    }
}

diesel::table! {
    notifications (id) {
        id -> Text,
        user_id -> Text,
        notification_type -> Text,
        title -> Text,
        message -> Text,
        link -> Nullable<Text>,
        data -> Nullable<Text>,
        read -> Integer,
        created_at -> Timestamp,
    }
}

diesel::table! {
    recovery_codes (id) {
        id -> Text,
        user_id -> Text,
        code_hash -> Text,
        used_at -> Nullable<Timestamp>,
        created_at -> Timestamp,
    }
}

diesel::table! {
    secure_escrow_messages (id) {
        id -> Text,
        escrow_id -> Text,
        sender_id -> Text,
        sender_role -> Text,
        encrypted_content_buyer -> Text,
        encrypted_content_vendor -> Text,
        encrypted_content_arbiter -> Text,
        sender_ephemeral_pubkey -> Text,
        nonce -> Text,
        frost_signature -> Nullable<Text>,
        created_at -> Text,
    }
}

diesel::table! {
    secure_messages (id) {
        id -> Text,
        conversation_id -> Text,
        sender_id -> Text,
        recipient_id -> Text,
        encrypted_content -> Text,
        nonce -> Text,
        sender_ephemeral_pubkey -> Text,
        created_at -> Text,
        expires_at -> Nullable<Text>,
        is_deleted_by_sender -> Integer,
        is_deleted_by_recipient -> Integer,
    }
}

diesel::table! {
    shield_backups (id) {
        id -> Text,
        escrow_id -> Text,
        user_id -> Text,
        role -> Text,
        backup_id -> Text,
        created_at -> Timestamp,
        verified_at -> Nullable<Timestamp>,
        download_count -> Integer,
        last_verified_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    signing_sessions (session_id) {
        session_id -> Text,
        escrow_id -> Text,
        tx_secret_key_encrypted -> Text,
        tx_pubkey -> Text,
        derivation -> Text,
        output_mask -> Text,
        pseudo_out_mask -> Text,
        mask_delta -> Text,
        ring_data_json -> Text,
        real_ring_index -> Integer,
        expected_one_time_pubkey -> Text,
        expected_key_image -> Text,
        tx_prefix_hash -> Text,
        clsag_message -> Text,
        bulletproof_plus_json -> Text,
        dest_spend_pubkey -> Text,
        dest_view_pubkey -> Text,
        funding_tx_hash -> Text,
        funding_output_index -> Integer,
        funding_amount -> Integer,
        output_commitment -> Text,
        pseudo_out -> Text,
        buyer_partial_sig -> Nullable<Text>,
        vendor_partial_sig -> Nullable<Text>,
        buyer_partial_ki -> Nullable<Text>,
        vendor_partial_ki -> Nullable<Text>,
        created_at -> Text,
        expires_at -> Text,
        status -> Text,
        initiator_role -> Text,
    }
}

diesel::table! {
    transactions (id) {
        id -> Text,
        escrow_id -> Text,
        tx_hash -> Nullable<Text>,
        amount_xmr -> BigInt,
        confirmations -> Integer,
        created_at -> Timestamp,
    }
}

diesel::table! {
    user_escrow_roles (id) {
        id -> Nullable<Text>,
        user_id -> Text,
        escrow_id -> Text,
        role -> Text,
        created_at -> Integer,
    }
}

diesel::table! {
    users (id) {
        id -> Text,
        username -> Text,
        password_hash -> Text,
        role -> Text,
        wallet_address -> Nullable<Text>,
        wallet_id -> Nullable<Text>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        encrypted_wallet_seed -> Nullable<Binary>,
        wallet_seed_salt -> Nullable<Binary>,
        bip39_backup_seed -> Nullable<Text>,
        seed_created_at -> Nullable<Integer>,
        seed_backup_acknowledged -> Nullable<Bool>,
    }
}

diesel::table! {
    wallet_address_history (id) {
        id -> Text,
        user_id -> Text,
        old_address -> Nullable<Text>,
        new_address -> Text,
        changed_at -> Integer,
        ip_address -> Nullable<Text>,
        user_agent -> Nullable<Text>,
    }
}

diesel::table! {
    wallet_rpc_configs (wallet_id) {
        wallet_id -> Nullable<Text>,
        escrow_id -> Text,
        role -> Text,
        rpc_url_encrypted -> Binary,
        rpc_user_encrypted -> Nullable<Binary>,
        rpc_password_encrypted -> Nullable<Binary>,
        created_at -> Integer,
        last_connected_at -> Nullable<Integer>,
        connection_attempts -> Integer,
        last_error -> Nullable<Text>,
    }
}

diesel::table! {
    wallets (id) {
        id -> Text,
        user_id -> Text,
        address -> Text,
        address_hash -> Text,
        spend_key_pub -> Text,
        view_key_pub -> Text,
        signature -> Nullable<Text>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        daily_limit_atomic -> Nullable<BigInt>,
        monthly_limit_atomic -> Nullable<BigInt>,
        last_withdrawal_date -> Nullable<Date>,
        withdrawn_today_atomic -> Nullable<BigInt>,
    }
}

diesel::table! {
    wasm_multisig_infos (id) {
        id -> Text,
        escrow_id -> Text,
        role -> Text,
        multisig_info -> Text,
        view_key_component -> Nullable<Text>,
        created_at -> Integer,
    }
}

diesel::table! {
    webhook_deliveries (id) {
        id -> Text,
        webhook_id -> Text,
        event_type -> Text,
        event_id -> Text,
        payload -> Text,
        status -> Text,
        http_status_code -> Nullable<Integer>,
        response_body -> Nullable<Text>,
        error_message -> Nullable<Text>,
        attempt_count -> Integer,
        next_retry_at -> Nullable<Text>,
        created_at -> Text,
        delivered_at -> Nullable<Text>,
    }
}

diesel::table! {
    webhooks (id) {
        id -> Text,
        api_key_id -> Text,
        url -> Text,
        secret -> Text,
        events -> Text,
        is_active -> Integer,
        consecutive_failures -> Integer,
        last_failure_reason -> Nullable<Text>,
        description -> Nullable<Text>,
        created_at -> Text,
        updated_at -> Text,
    }
}

diesel::table! {
    marketplace_clients (id) {
        id -> Text,
        api_key_user_id -> Text,
        name -> Text,
        display_name -> Nullable<Text>,
        fee_bps -> Integer,
        webhook_url -> Nullable<Text>,
        is_active -> Integer,
        created_at -> Text,
        updated_at -> Text,
    }
}

diesel::table! {
    fee_ledger (id) {
        id -> Text,
        escrow_id -> Text,
        client_id -> Nullable<Text>,
        fee_type -> Text,
        amount_atomic -> BigInt,
        tx_hash -> Nullable<Text>,
        created_at -> Text,
    }
}

diesel::joinable!(api_keys -> users (user_id));
diesel::joinable!(escrow_chat_keypairs -> escrows (escrow_id));
diesel::joinable!(escrow_chat_read_receipts -> secure_escrow_messages (message_id));
diesel::joinable!(secure_escrow_messages -> escrows (escrow_id));
diesel::joinable!(dispute_evidence -> escrows (escrow_id));
diesel::joinable!(encrypted_relay -> escrows (escrow_id));
diesel::joinable!(frost_dkg_state -> escrows (escrow_id));
diesel::joinable!(frost_signing_state -> escrows (escrow_id));
diesel::joinable!(message_keypairs -> users (user_id));
diesel::joinable!(message_read_receipts -> secure_messages (message_id));
diesel::joinable!(messages -> escrows (escrow_id));
diesel::joinable!(messages -> users (sender_id));
diesel::joinable!(multisig_participants -> multisig_sessions (session_id));
diesel::joinable!(multisig_sessions -> escrows (escrow_id));
diesel::joinable!(notifications -> users (user_id));
diesel::joinable!(recovery_codes -> users (user_id));
diesel::joinable!(shield_backups -> escrows (escrow_id));
diesel::joinable!(shield_backups -> users (user_id));
diesel::joinable!(signing_sessions -> escrows (escrow_id));
diesel::joinable!(transactions -> escrows (escrow_id));
diesel::joinable!(user_escrow_roles -> escrows (escrow_id));
diesel::joinable!(user_escrow_roles -> users (user_id));
diesel::joinable!(wallet_address_history -> users (user_id));
diesel::joinable!(wallet_rpc_configs -> escrows (escrow_id));
diesel::joinable!(wallets -> users (user_id));
diesel::joinable!(webhook_deliveries -> webhooks (webhook_id));
diesel::joinable!(marketplace_clients -> users (api_key_user_id));
diesel::joinable!(fee_ledger -> escrows (escrow_id));

diesel::allow_tables_to_appear_in_same_query!(
    api_keys,
    dispute_evidence,
    encrypted_relay,
    escrow_chat_keypairs,
    escrow_chat_read_receipts,
    escrows,
    fee_ledger,
    frost_dkg_state,
    frost_signing_state,
    login_attempts,
    marketplace_clients,
    message_keypairs,
    message_read_receipts,
    messages,
    multisig_challenges,
    multisig_participants,
    multisig_sessions,
    notifications,
    recovery_codes,
    secure_escrow_messages,
    secure_messages,
    shield_backups,
    signing_sessions,
    transactions,
    user_escrow_roles,
    users,
    wallet_address_history,
    wallet_rpc_configs,
    wallets,
    wasm_multisig_infos,
    webhook_deliveries,
    webhooks,
);
