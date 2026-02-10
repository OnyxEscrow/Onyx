#!/bin/bash
# Initialize marketplace database with SQLCipher

set -e

DB_FILE="${1:-marketplace.db}"
DB_KEY="${DB_ENCRYPTION_KEY:-1507741993bdf8914031465a9dc63dd7e1f32a7bc2cd2b49e647042450503724}"

echo "🔐 Initializing encrypted database: $DB_FILE"
echo "================================================"

# Remove old DB if exists
if [ -f "$DB_FILE" ]; then
    echo "⚠️  Removing existing database..."
    rm -f "$DB_FILE"
fi

# Create encrypted database with SQLCipher
echo "📦 Creating encrypted database..."
sqlcipher "$DB_FILE" <<EOF
PRAGMA key = '$DB_KEY';
PRAGMA cipher_page_size = 4096;
PRAGMA kdf_iter = 256000;
PRAGMA cipher_hmac_algorithm = HMAC_SHA512;
PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;

-- Users table
CREATE TABLE users (
    id TEXT PRIMARY KEY NOT NULL,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    wallet_address TEXT,
    wallet_id TEXT,
    role TEXT NOT NULL CHECK(role IN ('buyer', 'vendor', 'arbiter')),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_role ON users(role);

-- Listings table
CREATE TABLE listings (
    id TEXT PRIMARY KEY NOT NULL,
    vendor_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    price_xmr REAL NOT NULL,
    category TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active', 'sold', 'removed')),
    images TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vendor_id) REFERENCES users(id)
);

CREATE INDEX idx_listings_vendor ON listings(vendor_id);
CREATE INDEX idx_listings_status ON listings(status);
CREATE INDEX idx_listings_category ON listings(category);

-- Orders table
CREATE TABLE orders (
    id TEXT PRIMARY KEY NOT NULL,
    listing_id TEXT NOT NULL,
    buyer_id TEXT NOT NULL,
    vendor_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'funded', 'shipped', 'completed', 'disputed', 'cancelled')),
    total_xmr REAL NOT NULL,
    shipping_address TEXT,
    tracking_number TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (listing_id) REFERENCES listings(id),
    FOREIGN KEY (buyer_id) REFERENCES users(id),
    FOREIGN KEY (vendor_id) REFERENCES users(id)
);

CREATE INDEX idx_orders_buyer ON orders(buyer_id);
CREATE INDEX idx_orders_vendor ON orders(vendor_id);
CREATE INDEX idx_orders_status ON orders(status);

-- Escrows table
CREATE TABLE escrows (
    id TEXT PRIMARY KEY NOT NULL,
    order_id TEXT NOT NULL UNIQUE,
    buyer_id TEXT NOT NULL,
    vendor_id TEXT NOT NULL,
    arbiter_id TEXT,
    amount_xmr REAL NOT NULL,
    multisig_address TEXT,
    state TEXT NOT NULL CHECK(state IN ('pending_setup', 'ready', 'funded', 'released', 'refunded', 'disputed')),
    buyer_multisig_info TEXT,
    vendor_multisig_info TEXT,
    arbiter_multisig_info TEXT,
    transaction_hash TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (order_id) REFERENCES orders(id),
    FOREIGN KEY (buyer_id) REFERENCES users(id),
    FOREIGN KEY (vendor_id) REFERENCES users(id),
    FOREIGN KEY (arbiter_id) REFERENCES users(id)
);

CREATE INDEX idx_escrows_order ON escrows(order_id);
CREATE INDEX idx_escrows_state ON escrows(state);

-- Reviews table
CREATE TABLE reviews (
    id TEXT PRIMARY KEY NOT NULL,
    order_id TEXT NOT NULL,
    reviewer_id TEXT NOT NULL,
    reviewee_id TEXT NOT NULL,
    rating INTEGER NOT NULL CHECK(rating >= 1 AND rating <= 5),
    comment TEXT,
    signature TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (order_id) REFERENCES orders(id),
    FOREIGN KEY (reviewer_id) REFERENCES users(id),
    FOREIGN KEY (reviewee_id) REFERENCES users(id)
);

CREATE INDEX idx_reviews_order ON reviews(order_id);
CREATE INDEX idx_reviews_reviewee ON reviews(reviewee_id);

-- Reputation scores table
CREATE TABLE reputation_scores (
    user_id TEXT PRIMARY KEY NOT NULL,
    total_score INTEGER NOT NULL DEFAULT 0,
    total_reviews INTEGER NOT NULL DEFAULT 0,
    average_rating REAL NOT NULL DEFAULT 0.0,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

.tables
.schema
EOF

echo ""
echo "✅ Database initialized successfully!"
echo ""
echo "📊 Database info:"
ls -lh "$DB_FILE"
echo ""
echo "🔑 Encryption key: $DB_KEY"
echo ""
echo "🚀 You can now start the server with:"
echo "   DATABASE_URL=sqlite:$DB_FILE DB_ENCRYPTION_KEY=$DB_KEY cargo run -p server"
