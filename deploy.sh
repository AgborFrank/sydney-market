#!/bin/bash

# Marketplace Deployment Script for Digital Ocean
# This script deploys the Flask marketplace application

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Marketplace Deployment Script ===${NC}"

# Configuration
PROJECT_DIR="/var/www/marketplace"
APP_USER="www-data"
APP_GROUP="www-data"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Update system
echo -e "${YELLOW}Updating system packages...${NC}"
apt update && apt upgrade -y

# Install required system packages
echo -e "${YELLOW}Installing system dependencies...${NC}"
apt install -y python3 python3-pip python3-venv git curl nginx supervisor redis-server
apt install -y build-essential libssl-dev libffi-dev python3-dev
apt install -y libgmp-dev  # Required for fastecdsa

# Create project directory
echo -e "${YELLOW}Setting up project directory...${NC}"
mkdir -p "$PROJECT_DIR"
chown -R $APP_USER:$APP_GROUP "$PROJECT_DIR"

# Create virtual environment
echo -e "${YELLOW}Setting up Python virtual environment...${NC}"
if [[ ! -d "$PROJECT_DIR/venv" ]]; then
    python3 -m venv "$PROJECT_DIR/venv"
fi

# Install Python dependencies
echo -e "${YELLOW}Installing Python dependencies...${NC}"
"$PROJECT_DIR/venv/bin/pip" install --upgrade pip
"$PROJECT_DIR/venv/bin/pip" install -r "$PROJECT_DIR/requirements.txt"

# Set up Redis
echo -e "${YELLOW}Configuring Redis...${NC}"
systemctl enable redis-server
systemctl start redis-server

# Create application service
echo -e "${YELLOW}Setting up application service...${NC}"
cat > /etc/systemd/system/marketplace.service << EOF
[Unit]
Description=Marketplace Flask Application
After=network.target redis-server.service

[Service]
User=$APP_USER
Group=$APP_GROUP
WorkingDirectory=$PROJECT_DIR
Environment=PATH=$PROJECT_DIR/venv/bin
Environment=FLASK_ENV=production
ExecStart=$PROJECT_DIR/venv/bin/gunicorn --workers 3 --bind 127.0.0.1:5000 app:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Configure Nginx
echo -e "${YELLOW}Configuring Nginx...${NC}"
cat > /etc/nginx/sites-available/marketplace << EOF
server {
    listen 80;
    server_name your-domain.com;  # Replace with your domain

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;

    # Static files
    location /static/ {
        alias $PROJECT_DIR/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    # Proxy to Flask app
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_redirect off;
    }

    # Webhook endpoint
    location /webhook {
        proxy_pass http://127.0.0.1:5001;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

# Enable the site
ln -sf /etc/nginx/sites-available/marketplace /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default  # Remove default site

# Test Nginx configuration
nginx -t

# Set proper permissions
echo -e "${YELLOW}Setting up permissions...${NC}"
chown -R $APP_USER:$APP_GROUP "$PROJECT_DIR"
chmod -R 755 "$PROJECT_DIR"

# Create log directories
mkdir -p /var/log/marketplace
chown -R $APP_USER:$APP_GROUP /var/log/marketplace

# Enable and start services
echo -e "${YELLOW}Starting services...${NC}"
systemctl daemon-reload
systemctl enable marketplace
systemctl start marketplace
systemctl reload nginx

# Setup firewall
echo -e "${YELLOW}Configuring firewall...${NC}"
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

echo ""
echo -e "${GREEN}=== Deployment Complete! ===${NC}"
echo ""
echo -e "${BLUE}Next Steps:${NC}"
echo "1. Replace 'your-domain.com' in /etc/nginx/sites-available/marketplace"
echo "2. Set up SSL with Let's Encrypt:"
echo "   sudo apt install certbot python3-certbot-nginx"
echo "   sudo certbot --nginx -d your-domain.com"
echo "3. Configure your domain DNS to point to this server"
echo ""
echo -e "${BLUE}Useful Commands:${NC}"
echo "Check app status: systemctl status marketplace"
echo "View app logs: journalctl -u marketplace -f"
echo "Restart app: systemctl restart marketplace"
echo "Check Nginx: systemctl status nginx"
echo ""
echo -e "${GREEN}Your marketplace is now running on http://your-server-ip${NC}" 