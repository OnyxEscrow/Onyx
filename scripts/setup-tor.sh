#!/bin/bash
# Setup Tor Hidden Service for Monero Marketplace
# Usage: sudo ./scripts/setup-tor.sh

set -e

echo "🧅 Setting up Tor Hidden Service for Monero Marketplace"
echo "========================================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Error: This script must be run as root (use sudo)"
    exit 1
fi

# Install Tor if not already installed
if ! command -v tor &> /dev/null; then
    echo "📦 Installing Tor..."
    apt-get update
    apt-get install -y tor
    echo "✅ Tor installed"
else
    echo "✅ Tor already installed"
fi

# Backup existing torrc
if [ -f /etc/tor/torrc ]; then
    cp /etc/tor/torrc /etc/tor/torrc.backup.$(date +%Y%m%d_%H%M%S)
    echo "✅ Backed up existing torrc"
fi

# Create Tor configuration for hidden service
echo "📝 Configuring Tor hidden service..."

cat > /etc/tor/torrc << 'EOF'
## Tor Configuration for Monero Marketplace

# Hidden Service v3 configuration
HiddenServiceDir /var/lib/tor/monero_marketplace/
HiddenServicePort 80 127.0.0.1:8080

# Performance optimizations
NumCPUs 2
AvoidDiskWrites 1

# Security settings
CookieAuthentication 1
DataDirectory /var/lib/tor

# Logging (for debugging)
Log notice file /var/log/tor/notices.log

# Circuit settings
CircuitBuildTimeout 60
LearnCircuitBuildTimeout 0
EOF

echo "✅ Tor configuration created"

# Create hidden service directory
mkdir -p /var/lib/tor/monero_marketplace
chown -R debian-tor:debian-tor /var/lib/tor/monero_marketplace
chmod 700 /var/lib/tor/monero_marketplace

# Restart Tor service
echo "🔄 Restarting Tor service..."
systemctl restart tor
sleep 3

# Check if Tor is running
if systemctl is-active --quiet tor; then
    echo "✅ Tor service is running"
else
    echo "❌ Tor service failed to start"
    systemctl status tor
    exit 1
fi

# Display onion address
echo ""
echo "=========================================="
echo "🎉 Tor Hidden Service Setup Complete!"
echo "=========================================="

if [ -f /var/lib/tor/monero_marketplace/hostname ]; then
    ONION_ADDRESS=$(cat /var/lib/tor/monero_marketplace/hostname)
    echo ""
    echo "Your .onion address:"
    echo "  $ONION_ADDRESS"
    echo ""
    echo "Server will be accessible at:"
    echo "  http://$ONION_ADDRESS"
    echo ""
    echo "Make sure to start the Monero Marketplace server on port 8080:"
    echo "  ./scripts/start-server.sh"
else
    echo "⏳ Onion address not yet generated. Wait a few seconds and run:"
    echo "  sudo cat /var/lib/tor/monero_marketplace/hostname"
fi

echo ""
echo "📋 Useful commands:"
echo "  - Check Tor status: sudo systemctl status tor"
echo "  - View Tor logs: sudo tail -f /var/log/tor/notices.log"
echo "  - Restart Tor: sudo systemctl restart tor"
echo ""
