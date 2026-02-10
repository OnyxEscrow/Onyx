-- Migration: Add BTC Payment Support (Track 1: External Swap Services)
-- This migration adds support for BTC->XMR swaps via external providers (FixedFloat, Trocador)

-- New table: swap_orders
-- Tracks individual BTC->XMR swap transactions via external providers
CREATE TABLE swap_orders (
    id TEXT PRIMARY KEY NOT NULL,
    -- Link to marketplace order
    order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,

    -- Swap provider info
    provider TEXT NOT NULL CHECK(provider IN ('fixedfloat', 'trocador', 'atomic')),
    provider_order_id TEXT,                    -- External provider's order ID

    -- Currency pair (always BTC->XMR for now)
    from_currency TEXT NOT NULL DEFAULT 'BTC',
    to_currency TEXT NOT NULL DEFAULT 'XMR',

    -- Amounts
    from_amount_sats BIGINT NOT NULL,          -- BTC amount in satoshis
    to_amount_atomic BIGINT,                   -- Expected XMR amount in piconeros

    -- Exchange rate at time of quote
    rate_btc_per_xmr REAL,                     -- e.g., 0.0062 BTC/XMR
    rate_locked_at DATETIME,                   -- When rate was locked
    rate_expires_at DATETIME,                  -- Quote expiration

    -- Deposit address (where user sends BTC)
    btc_deposit_address TEXT NOT NULL,

    -- Swap status
    status TEXT NOT NULL DEFAULT 'awaiting_deposit' CHECK(status IN (
        'awaiting_deposit',    -- Waiting for user to send BTC
        'deposit_detected',    -- BTC tx seen in mempool
        'deposit_confirmed',   -- BTC tx has min confirmations
        'swapping',            -- Provider is executing swap
        'swap_complete',       -- XMR sent to escrow
        'completed',           -- Full flow done
        'expired',             -- Quote expired before deposit
        'failed',              -- Swap failed
        'refunded'             -- BTC returned to user
    )),

    -- Transaction hashes
    btc_tx_hash TEXT,                          -- User's BTC deposit tx
    btc_tx_confirmations INTEGER DEFAULT 0,
    xmr_tx_hash TEXT,                          -- Provider's XMR payout tx

    -- Provider response data (JSON)
    provider_response_json TEXT,

    -- Error tracking
    last_error TEXT,
    retry_count INTEGER DEFAULT 0,

    -- Timestamps
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deposit_detected_at DATETIME,
    swap_initiated_at DATETIME,
    completed_at DATETIME
);

-- Add payment_method to orders table
ALTER TABLE orders ADD COLUMN payment_method TEXT DEFAULT 'xmr' CHECK(payment_method IN ('xmr', 'btc_onchain', 'btc_lightning'));

-- Add swap_order_id reference to orders
ALTER TABLE orders ADD COLUMN swap_order_id TEXT REFERENCES swap_orders(id);

-- Indexes for efficient queries
CREATE INDEX idx_swap_orders_order_id ON swap_orders(order_id);
CREATE INDEX idx_swap_orders_status ON swap_orders(status);
CREATE INDEX idx_swap_orders_provider ON swap_orders(provider);
CREATE INDEX idx_swap_orders_btc_address ON swap_orders(btc_deposit_address);
CREATE INDEX idx_orders_payment_method ON orders(payment_method);
