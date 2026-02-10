-- Multi-coin support migration
-- Adds supported_coins table to track which cryptocurrencies can be swapped to XMR

-- Table of supported coins for swap (e.g., BTC, LTC, ETH, USDT)
CREATE TABLE supported_coins (
    ticker TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    network TEXT NOT NULL,          -- "mainnet", "erc20", "trc20", "bep20", etc.
    divisibility INTEGER NOT NULL,  -- 8 (BTC), 18 (ETH), 6 (USDT), 12 (XMR)
    icon_name TEXT,                 -- lucide icon name (e.g., "bitcoin", "circle-dollar-sign")
    min_amount TEXT,                -- Min swap amount in human units (e.g., "0.0001")
    max_amount TEXT,                -- Max swap amount in human units (e.g., "5")
    enabled INTEGER NOT NULL DEFAULT 1,   -- 1=enabled, 0=disabled
    display_order INTEGER NOT NULL DEFAULT 0,  -- For UI sorting
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Insert initial supported coins
INSERT INTO supported_coins (ticker, name, network, divisibility, icon_name, min_amount, max_amount, enabled, display_order) VALUES
    ('BTC', 'Bitcoin', 'mainnet', 8, 'bitcoin', '0.0001', '5', 1, 1),
    ('LTC', 'Litecoin', 'mainnet', 8, 'circle-dollar-sign', '0.01', '100', 1, 2),
    ('ETH', 'Ethereum', 'mainnet', 18, 'circle-dollar-sign', '0.001', '10', 1, 3),
    ('USDT', 'Tether (ERC-20)', 'erc20', 6, 'circle-dollar-sign', '10', '10000', 1, 4),
    ('USDC', 'USD Coin (ERC-20)', 'erc20', 6, 'circle-dollar-sign', '10', '10000', 1, 5),
    ('DOGE', 'Dogecoin', 'mainnet', 8, 'dog', '10', '100000', 1, 6),
    ('TRX', 'TRON', 'mainnet', 6, 'circle-dollar-sign', '50', '50000', 1, 7),
    ('SOL', 'Solana', 'mainnet', 9, 'circle-dollar-sign', '0.1', '500', 1, 8),
    ('BNB', 'BNB (BSC)', 'bep20', 18, 'circle-dollar-sign', '0.01', '50', 1, 9),
    ('MATIC', 'Polygon', 'mainnet', 18, 'circle-dollar-sign', '10', '50000', 1, 10);

-- Add from_network column to swap_orders for network-specific routing
ALTER TABLE swap_orders ADD COLUMN from_network TEXT NOT NULL DEFAULT 'mainnet';

-- Create index for fast lookup
CREATE INDEX idx_supported_coins_enabled ON supported_coins(enabled);
CREATE INDEX idx_swap_orders_from_currency ON swap_orders(from_currency);
