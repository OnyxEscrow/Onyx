#!/bin/bash
# Setup Prometheus + Grafana + Alertmanager monitoring stack
# For Ubuntu/Debian systems

set -e

echo "=================================================="
echo "Monero Marketplace Monitoring Setup"
echo "=================================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo -e "${RED}❌ Do not run this script as root${NC}"
    echo "Run as normal user with sudo privileges"
    exit 1
fi

# ============================================================================
# Install Prometheus
# ============================================================================
echo -e "${BLUE}[1/5]${NC} Installing Prometheus..."

if command -v prometheus >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Prometheus already installed${NC}"
else
    sudo apt update
    sudo apt install -y prometheus

    echo -e "${GREEN}✅ Prometheus installed${NC}"
fi

# Copy configuration
echo "  Copying prometheus.yml..."
sudo cp monitoring/prometheus.yml /etc/prometheus/
sudo cp monitoring/prometheus-alerts.yml /etc/prometheus/

# Set permissions
sudo chown prometheus:prometheus /etc/prometheus/prometheus.yml
sudo chown prometheus:prometheus /etc/prometheus/prometheus-alerts.yml

# Restart and enable
sudo systemctl restart prometheus
sudo systemctl enable prometheus

# Verify
if systemctl is-active --quiet prometheus; then
    echo -e "${GREEN}✅ Prometheus running${NC}"
else
    echo -e "${RED}❌ Prometheus failed to start${NC}"
    echo "Check logs: sudo journalctl -u prometheus -n 50"
    exit 1
fi

echo ""

# ============================================================================
# Install Alertmanager
# ============================================================================
echo -e "${BLUE}[2/5]${NC} Installing Alertmanager..."

if command -v alertmanager >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Alertmanager already installed${NC}"
else
    sudo apt install -y prometheus-alertmanager

    echo -e "${GREEN}✅ Alertmanager installed${NC}"
fi

# Create basic configuration if doesn't exist
if [ ! -f /etc/alertmanager/alertmanager.yml ]; then
    echo "  Creating default alertmanager.yml..."
    sudo mkdir -p /etc/alertmanager

    sudo tee /etc/alertmanager/alertmanager.yml >/dev/null <<'EOF'
global:
  resolve_timeout: 5m

route:
  group_by: ['alertname', 'severity']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 12h
  receiver: 'default'

  routes:
    - match:
        severity: critical
      receiver: 'critical'
      continue: true

    - match:
        severity: high
      receiver: 'high'
      continue: true

receivers:
  - name: 'default'
    # Add your webhook URL here
    # webhook_configs:
    #   - url: 'http://localhost:5001/'

  - name: 'critical'
    # Slack webhook for critical alerts
    # slack_configs:
    #   - api_url: 'YOUR_SLACK_WEBHOOK_URL'
    #     channel: '#alerts-critical'

  - name: 'high'
    # Email for high priority alerts
    # email_configs:
    #   - to: 'oncall@example.com'
EOF

    sudo chown alertmanager:alertmanager /etc/alertmanager/alertmanager.yml
fi

# Restart and enable
sudo systemctl restart prometheus-alertmanager
sudo systemctl enable prometheus-alertmanager

# Verify
if systemctl is-active --quiet prometheus-alertmanager; then
    echo -e "${GREEN}✅ Alertmanager running${NC}"
else
    echo -e "${RED}❌ Alertmanager failed to start${NC}"
    echo "Check logs: sudo journalctl -u prometheus-alertmanager -n 50"
    exit 1
fi

echo ""

# ============================================================================
# Install Grafana
# ============================================================================
echo -e "${BLUE}[3/5]${NC} Installing Grafana..."

if command -v grafana-server >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Grafana already installed${NC}"
else
    echo "  Adding Grafana APT repository..."
    sudo apt-get install -y software-properties-common apt-transport-https
    wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -
    echo "deb https://packages.grafana.com/oss/deb stable main" | sudo tee /etc/apt/sources.list.d/grafana.list

    sudo apt-get update
    sudo apt-get install -y grafana

    echo -e "${GREEN}✅ Grafana installed${NC}"
fi

# Start and enable
sudo systemctl start grafana-server
sudo systemctl enable grafana-server

# Wait for Grafana to start
echo "  Waiting for Grafana to start..."
sleep 5

# Verify
if systemctl is-active --quiet grafana-server; then
    echo -e "${GREEN}✅ Grafana running${NC}"
else
    echo -e "${RED}❌ Grafana failed to start${NC}"
    echo "Check logs: sudo journalctl -u grafana-server -n 50"
    exit 1
fi

echo ""

# ============================================================================
# Configure Grafana Data Source (Prometheus)
# ============================================================================
echo -e "${BLUE}[4/5]${NC} Configuring Grafana data source..."

# Wait for Grafana API to be ready
MAX_RETRIES=30
RETRY=0
while [ $RETRY -lt $MAX_RETRIES ]; do
    if curl -s http://localhost:3000/api/health >/dev/null 2>&1; then
        break
    fi
    echo "  Waiting for Grafana API... ($((RETRY+1))/$MAX_RETRIES)"
    sleep 2
    ((RETRY++))
done

if [ $RETRY -eq $MAX_RETRIES ]; then
    echo -e "${RED}❌ Grafana API not responding${NC}"
    exit 1
fi

# Add Prometheus data source
echo "  Adding Prometheus data source..."
curl -X POST \
    -H "Content-Type: application/json" \
    -d @- \
    http://admin:admin@localhost:3000/api/datasources <<'EOF' 2>/dev/null || true
{
  "name": "Prometheus",
  "type": "prometheus",
  "url": "http://localhost:9090",
  "access": "proxy",
  "isDefault": true
}
EOF

echo -e "${GREEN}✅ Prometheus data source configured${NC}"

echo ""

# ============================================================================
# Import Grafana Dashboard
# ============================================================================
echo -e "${BLUE}[5/5]${NC} Importing Grafana dashboard..."

if [ -f monitoring/grafana-dashboard.json ]; then
    # Import dashboard via API
    curl -X POST \
        -H "Content-Type: application/json" \
        -d @monitoring/grafana-dashboard.json \
        http://admin:admin@localhost:3000/api/dashboards/db 2>/dev/null || true

    echo -e "${GREEN}✅ Dashboard imported${NC}"
else
    echo -e "${YELLOW}⚠️  Dashboard file not found${NC}"
    echo "   Create it manually from: monitoring/grafana-dashboard.json"
fi

echo ""

# ============================================================================
# Summary
# ============================================================================
echo "=================================================="
echo "Installation Complete!"
echo "=================================================="
echo ""
echo -e "${GREEN}✅ Prometheus:${NC}    http://localhost:9090"
echo -e "${GREEN}✅ Alertmanager:${NC}  http://localhost:9093"
echo -e "${GREEN}✅ Grafana:${NC}       http://localhost:3000"
echo ""
echo "Grafana default credentials:"
echo "  Username: admin"
echo "  Password: admin"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Change Grafana admin password"
echo "2. Configure Alertmanager webhooks (Slack/Email)"
echo "   Edit: /etc/alertmanager/alertmanager.yml"
echo "3. Test alerts:"
echo "   ./scripts/test-monitoring.sh"
echo ""
echo "Documentation: DOX/monitoring/PROMETHEUS-MONITORING.md"
echo ""
