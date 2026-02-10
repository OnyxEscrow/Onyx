#!/bin/bash
# Apply missing migration to encrypted SQLCipher database

set -e

echo "🔧 Applying missing migration: add_temp_wallet_ids_to_escrows"
echo ""

# Load .env to get DB_ENCRYPTION_KEY
export $(grep -v '^#' .env | grep DB_ENCRYPTION_KEY | xargs)

if [ -z "$DB_ENCRYPTION_KEY" ]; then
    echo "❌ ERROR: DB_ENCRYPTION_KEY not found in .env"
    exit 1
fi

echo "✅ Loaded encryption key from .env"

# Apply migration SQL
sqlcipher marketplace.db <<EOF
PRAGMA key='$DB_ENCRYPTION_KEY';

-- Add temporary wallet ID columns
ALTER TABLE escrows ADD COLUMN buyer_temp_wallet_id TEXT DEFAULT NULL;
ALTER TABLE escrows ADD COLUMN vendor_temp_wallet_id TEXT DEFAULT NULL;
ALTER TABLE escrows ADD COLUMN arbiter_temp_wallet_id TEXT DEFAULT NULL;

-- Add indexes
CREATE INDEX idx_escrows_buyer_temp_wallet ON escrows(buyer_temp_wallet_id);
CREATE INDEX idx_escrows_vendor_temp_wallet ON escrows(vendor_temp_wallet_id);
CREATE INDEX idx_escrows_arbiter_temp_wallet ON escrows(arbiter_temp_wallet_id);

-- Verify
SELECT COUNT(*) as escrow_count FROM escrows;
EOF

echo ""
echo "✅ Migration applied successfully!"
echo "🔄 Restart the server for changes to take effect"
