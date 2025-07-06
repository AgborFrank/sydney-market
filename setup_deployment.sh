#!/bin/bash

# Digital Ocean Auto-Deployment Setup Script
# This script sets up automatic deployment from GitHub to Digital Ocean

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_DIR="/var/www/marketplace"
WEBHOOK_PORT="5001"
WEBHOOK_SECRET=$(openssl rand -hex 32)
MANUAL_DEPLOY_KEY=$(openssl rand -hex 16)

echo -e "${BLUE}=== Digital Ocean Auto-Deployment Setup ===${NC}"
echo "This script will set up automatic deployment from GitHub to your Digital Ocean server."
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Update system
echo -e "${YELLOW}Updating system packages...${NC}"
apt update && apt upgrade -y

# Install required packages
echo -e "${YELLOW}Installing required packages...${NC}"
apt install -y python3-pip python3-venv git curl nginx supervisor

# Create project directory if it doesn't exist
if [[ ! -d "$PROJECT_DIR" ]]; then
    echo -e "${YELLOW}Creating project directory...${NC}"
    mkdir -p "$PROJECT_DIR"
fi

# Set proper permissions
echo -e "${YELLOW}Setting up permissions...${NC}"
chown -R www-data:www-data "$PROJECT_DIR"
chmod -R 755 "$PROJECT_DIR"

# Make deploy script executable
if [[ -f "$PROJECT_DIR/deploy.sh" ]]; then
    chmod +x "$PROJECT_DIR/deploy.sh"
fi

# Create virtual environment
echo -e "${YELLOW}Setting up Python virtual environment...${NC}"
if [[ ! -d "$PROJECT_DIR/venv" ]]; then
    python3 -m venv "$PROJECT_DIR/venv"
fi

# Install webhook handler dependencies
echo -e "${YELLOW}Installing webhook handler dependencies...${NC}"
"$PROJECT_DIR/venv/bin/pip" install flask gunicorn

# Configure sudoers for webhook handler
echo -e "${YELLOW}Configuring sudo permissions...${NC}"
cat > /etc/sudoers.d/webhook-deploy << EOF
# Allow webhook handler to run deployment script
www-data ALL=(ALL) NOPASSWD: /var/www/marketplace/deploy.sh
EOF

chmod 440 /etc/sudoers.d/webhook-deploy

# Setup systemd service for webhook handler
echo -e "${YELLOW}Setting up webhook handler service...${NC}"
cp "$PROJECT_DIR/webhook-handler.service" /etc/systemd/system/

# Update service file with generated secrets
sed -i "s/your-webhook-secret-here/$WEBHOOK_SECRET/g" /etc/systemd/system/webhook-handler.service
sed -i "s/your-manual-deploy-key/$MANUAL_DEPLOY_KEY/g" /etc/systemd/system/webhook-handler.service

# Enable and start webhook handler service
systemctl daemon-reload
systemctl enable webhook-handler
systemctl start webhook-handler

# Configure Nginx for webhook handler
echo -e "${YELLOW}Configuring Nginx for webhook handler...${NC}"
cat > /etc/nginx/sites-available/webhook-handler << EOF
server {
    listen 80;
    server_name your-domain.com;  # Replace with your domain

    location /webhook {
        proxy_pass http://127.0.0.1:$WEBHOOK_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /deploy {
        proxy_pass http://127.0.0.1:$WEBHOOK_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /health {
        proxy_pass http://127.0.0.1:$WEBHOOK_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

# Enable the site
ln -sf /etc/nginx/sites-available/webhook-handler /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx

# Create log files
echo -e "${YELLOW}Setting up log files...${NC}"
touch /var/log/webhook.log
touch /var/log/marketplace-deploy.log
chown www-data:www-data /var/log/webhook.log /var/log/marketplace-deploy.log

# Setup firewall (if ufw is available)
if command -v ufw &> /dev/null; then
    echo -e "${YELLOW}Configuring firewall...${NC}"
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 22/tcp
fi

# Display configuration information
echo ""
echo -e "${GREEN}=== Setup Complete! ===${NC}"
echo ""
echo -e "${BLUE}Configuration Details:${NC}"
echo "Webhook URL: http://your-domain.com/webhook"
echo "Manual Deploy URL: http://your-domain.com/deploy"
echo "Health Check URL: http://your-domain.com/health"
echo ""
echo -e "${BLUE}Secrets (save these securely):${NC}"
echo "Webhook Secret: $WEBHOOK_SECRET"
echo "Manual Deploy Key: $MANUAL_DEPLOY_KEY"
echo ""
echo -e "${BLUE}Next Steps:${NC}"
echo "1. Replace 'your-domain.com' in the Nginx config with your actual domain"
echo "2. Configure GitHub webhook:"
echo "   - URL: http://your-domain.com/webhook"
echo "   - Content type: application/json"
echo "   - Secret: $WEBHOOK_SECRET"
echo "   - Events: Just the push event"
echo "3. Test the webhook by pushing to your main branch"
echo ""
echo -e "${BLUE}Useful Commands:${NC}"
echo "Check webhook handler status: systemctl status webhook-handler"
echo "View webhook logs: tail -f /var/log/webhook.log"
echo "View deployment logs: tail -f /var/log/marketplace-deploy.log"
echo "Manual deployment: curl -X POST -H 'X-API-Key: $MANUAL_DEPLOY_KEY' http://your-domain.com/deploy"
echo ""

# Test webhook handler
echo -e "${YELLOW}Testing webhook handler...${NC}"
if curl -f http://localhost:$WEBHOOK_PORT/health > /dev/null 2>&1; then
    echo -e "${GREEN}Webhook handler is running successfully!${NC}"
else
    echo -e "${RED}Webhook handler test failed. Check logs: journalctl -u webhook-handler${NC}"
fi

echo ""
echo -e "${GREEN}Setup completed successfully!${NC}" 