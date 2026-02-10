#!/bin/bash
# ============================================================================
# NEXUS/ONYX Production Deployment Script
# Target: Ubuntu 24.04 LTS VPS (onyx-escrow.com)
# ============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[DEPLOY]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# ============================================================================
# PHASE 1: System Setup
# ============================================================================

phase1_system_setup() {
    log "Phase 1: System Setup"

    # Update system
    sudo apt update && sudo apt upgrade -y

    # Install essential packages
    sudo apt install -y \
        build-essential \
        pkg-config \
        libssl-dev \
        libsqlite3-dev \
        curl \
        wget \
        git \
        unzip \
        htop \
        tmux \
        ufw \
        fail2ban \
        certbot \
        python3-certbot-nginx \
        nginx

    log "System packages installed"
}

# ============================================================================
# PHASE 2: Rust Installation
# ============================================================================

phase2_rust_install() {
    log "Phase 2: Rust Installation"

    # Install Rust via rustup
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"

    # Verify version
    rustc --version
    cargo --version

    log "Rust installed"
}

# ============================================================================
# PHASE 3: Node.js Installation
# ============================================================================

phase3_nodejs_install() {
    log "Phase 3: Node.js Installation"

    # Install Node.js 22.x via NodeSource
    curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
    sudo apt install -y nodejs

    # Verify version
    node --version
    npm --version

    log "Node.js installed"
}

# ============================================================================
# PHASE 4: Monero Installation
# ============================================================================

phase4_monero_install() {
    log "Phase 4: Monero Installation"

    MONERO_VERSION="0.18.4.3"
    MONERO_DIR="/opt/monero"

    # Download Monero
    cd /tmp
    wget "https://downloads.getmonero.org/cli/monero-linux-x64-v${MONERO_VERSION}.tar.bz2"
    tar -xvf "monero-linux-x64-v${MONERO_VERSION}.tar.bz2"

    # Install to /opt/monero
    sudo mkdir -p "$MONERO_DIR"
    sudo mv monero-x86_64-linux-gnu-v${MONERO_VERSION}/* "$MONERO_DIR/"

    # Create symlinks
    sudo ln -sf "$MONERO_DIR/monerod" /usr/local/bin/monerod
    sudo ln -sf "$MONERO_DIR/monero-wallet-rpc" /usr/local/bin/monero-wallet-rpc
    sudo ln -sf "$MONERO_DIR/monero-wallet-cli" /usr/local/bin/monero-wallet-cli

    # Verify
    monerod --version
    monero-wallet-rpc --version

    log "Monero installed"
}

# ============================================================================
# PHASE 5: Redis Installation
# ============================================================================

phase5_redis_install() {
    log "Phase 5: Redis Installation"

    sudo apt install -y redis-server

    # Configure Redis for production
    sudo sed -i 's/^bind .*/bind 127.0.0.1 ::1/' /etc/redis/redis.conf
    sudo sed -i 's/^# maxmemory .*/maxmemory 256mb/' /etc/redis/redis.conf
    sudo sed -i 's/^# maxmemory-policy .*/maxmemory-policy allkeys-lru/' /etc/redis/redis.conf

    sudo systemctl enable redis-server
    sudo systemctl restart redis-server

    log "Redis installed and configured"
}

# ============================================================================
# PHASE 6: Tor Installation (Optional - for future .onion)
# ============================================================================

phase6_tor_install() {
    log "Phase 6: Tor Installation"

    # Add Tor repository
    sudo apt install -y apt-transport-https
    echo "deb [signed-by=/usr/share/keyrings/tor-archive-keyring.gpg] https://deb.torproject.org/torproject.org noble main" | sudo tee /etc/apt/sources.list.d/tor.list
    wget -qO- https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | sudo gpg --dearmor -o /usr/share/keyrings/tor-archive-keyring.gpg

    sudo apt update
    sudo apt install -y tor deb.torproject.org-keyring

    sudo systemctl enable tor
    sudo systemctl start tor

    log "Tor installed"
}

# ============================================================================
# PHASE 7: Firewall Configuration
# ============================================================================

phase7_firewall_setup() {
    log "Phase 7: Firewall Configuration"

    # Reset UFW
    sudo ufw --force reset

    # Default policies
    sudo ufw default deny incoming
    sudo ufw default allow outgoing

    # Allow SSH (CRITICAL - don't lock yourself out!)
    sudo ufw allow 22/tcp

    # Allow HTTP/HTTPS
    sudo ufw allow 80/tcp
    sudo ufw allow 443/tcp

    # Monero P2P (mainnet)
    sudo ufw allow 18080/tcp

    # DO NOT expose these publicly:
    # - 18081 (Monero RPC) - localhost only
    # - 18082-18084 (wallet RPC) - localhost only
    # - 8080 (Actix server) - behind nginx
    # - 6379 (Redis) - localhost only

    sudo ufw --force enable
    sudo ufw status verbose

    log "Firewall configured"
}

# ============================================================================
# PHASE 8: Create Application User
# ============================================================================

phase8_create_user() {
    log "Phase 8: Create Application User"

    # Create nexus user if doesn't exist
    if ! id "nexus" &>/dev/null; then
        sudo useradd -m -s /bin/bash nexus
        sudo usermod -aG sudo nexus
    fi

    # Create directories
    sudo mkdir -p /opt/nexus
    sudo mkdir -p /var/log/nexus
    sudo mkdir -p /var/lib/nexus/wallets
    sudo mkdir -p /var/lib/monero

    # Set ownership
    sudo chown -R nexus:nexus /opt/nexus
    sudo chown -R nexus:nexus /var/log/nexus
    sudo chown -R nexus:nexus /var/lib/nexus
    sudo chown -R nexus:nexus /var/lib/monero

    log "Application user created"
}

# ============================================================================
# PHASE 9: Nginx Configuration
# ============================================================================

phase9_nginx_setup() {
    log "Phase 9: Nginx Configuration"

    # Create Nginx config for onyx-escrow.com
    sudo tee /etc/nginx/sites-available/onyx-escrow.com << 'EOF'
server {
    listen 80;
    server_name onyx-escrow.com www.onyx-escrow.com;

    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name onyx-escrow.com www.onyx-escrow.com;

    # SSL will be configured by certbot
    # ssl_certificate /etc/letsencrypt/live/onyx-escrow.com/fullchain.pem;
    # ssl_certificate_key /etc/letsencrypt/live/onyx-escrow.com/privkey.pem;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self' wss://$server_name;" always;

    # Gzip
    gzip on;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml;

    # Static files (frontend)
    location / {
        root /opt/nexus/static/app;
        try_files $uri $uri/ /index.html;

        # Cache static assets
        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
        }
    }

    # API proxy to Actix server
    location /api/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;
    }

    # WebSocket
    location /ws {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 3600s;
    }
}
EOF

    # Enable site
    sudo ln -sf /etc/nginx/sites-available/onyx-escrow.com /etc/nginx/sites-enabled/
    sudo rm -f /etc/nginx/sites-enabled/default

    # Test config
    sudo nginx -t

    sudo systemctl enable nginx
    sudo systemctl restart nginx

    log "Nginx configured"
}

# ============================================================================
# PHASE 10: SSL Certificate
# ============================================================================

phase10_ssl_setup() {
    log "Phase 10: SSL Certificate"

    # Get SSL certificate from Let's Encrypt
    sudo certbot --nginx -d onyx-escrow.com -d www.onyx-escrow.com --non-interactive --agree-tos --email admin@onyx-escrow.com

    # Auto-renewal
    sudo systemctl enable certbot.timer
    sudo systemctl start certbot.timer

    log "SSL certificate installed"
}

# ============================================================================
# PHASE 11: Systemd Services
# ============================================================================

phase11_systemd_services() {
    log "Phase 11: Systemd Services"

    # Monero daemon service
    sudo tee /etc/systemd/system/monerod.service << 'EOF'
[Unit]
Description=Monero Daemon
After=network.target

[Service]
Type=simple
User=nexus
ExecStart=/usr/local/bin/monerod --detach --data-dir /var/lib/monero --log-file /var/log/nexus/monerod.log --log-level 1 --non-interactive
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

    # Nexus server service
    sudo tee /etc/systemd/system/nexus.service << 'EOF'
[Unit]
Description=NEXUS Escrow Server
After=network.target redis-server.service monerod.service

[Service]
Type=simple
User=nexus
WorkingDirectory=/opt/nexus
EnvironmentFile=/opt/nexus/.env
ExecStart=/opt/nexus/server
Restart=always
RestartSec=10
StandardOutput=append:/var/log/nexus/server.log
StandardError=append:/var/log/nexus/server.log

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    sudo systemctl daemon-reload

    log "Systemd services created"
}

# ============================================================================
# PHASE 12: Deploy Application
# ============================================================================

phase12_deploy_app() {
    log "Phase 12: Deploy Application"

    # This assumes you've copied the built binary and static files
    # From local machine:
    # scp target/release/server ghost:/opt/nexus/
    # scp -r static/app ghost:/opt/nexus/static/
    # scp marketplace.db ghost:/opt/nexus/
    # scp .env.production ghost:/opt/nexus/.env

    warn "Manual steps required:"
    echo "1. Copy server binary: scp target/release/server nexus@your-vps:/opt/nexus/"
    echo "2. Copy static files: scp -r static/app nexus@your-vps:/opt/nexus/static/"
    echo "3. Copy database: scp marketplace.db nexus@your-vps:/opt/nexus/"
    echo "4. Create .env file: cp .env.mainnet.template /opt/nexus/.env"
    echo "5. Edit .env with production values"
    echo "6. Set permissions: chmod 600 /opt/nexus/.env"

    log "Application deployment instructions shown"
}

# ============================================================================
# MAIN
# ============================================================================

main() {
    echo "============================================"
    echo "  NEXUS/ONYX Production Deployment"
    echo "  Target: Ubuntu 24.04 LTS"
    echo "============================================"
    echo ""

    case "${1:-all}" in
        1|system)     phase1_system_setup ;;
        2|rust)       phase2_rust_install ;;
        3|node)       phase3_nodejs_install ;;
        4|monero)     phase4_monero_install ;;
        5|redis)      phase5_redis_install ;;
        6|tor)        phase6_tor_install ;;
        7|firewall)   phase7_firewall_setup ;;
        8|user)       phase8_create_user ;;
        9|nginx)      phase9_nginx_setup ;;
        10|ssl)       phase10_ssl_setup ;;
        11|systemd)   phase11_systemd_services ;;
        12|deploy)    phase12_deploy_app ;;
        all)
            phase1_system_setup
            phase2_rust_install
            phase3_nodejs_install
            phase4_monero_install
            phase5_redis_install
            phase6_tor_install
            phase7_firewall_setup
            phase8_create_user
            phase9_nginx_setup
            # phase10_ssl_setup  # Run manually after DNS is configured
            phase11_systemd_services
            phase12_deploy_app
            ;;
        *)
            echo "Usage: $0 [phase_number|phase_name|all]"
            echo "Phases: 1-system, 2-rust, 3-node, 4-monero, 5-redis, 6-tor, 7-firewall, 8-user, 9-nginx, 10-ssl, 11-systemd, 12-deploy"
            ;;
    esac

    echo ""
    log "Deployment script completed"
}

main "$@"
