#!/bin/bash

# Digital Ocean Auto-Deployment Script
# This script automatically updates the marketplace site when changes are pushed to GitHub

set -e  # Exit on any error

# Configuration
PROJECT_DIR="/var/www/marketplace"
GIT_REPO="https://github.com/AgborFrank/sydney-market.git"
BRANCH="main"
VENV_PATH="/var/www/marketplace/venv"
LOG_FILE="/var/log/marketplace-deploy.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Error handling
error_exit() {
    log "${RED}ERROR: $1${NC}"
    exit 1
}

# Success message
success() {
    log "${GREEN}SUCCESS: $1${NC}"
}

# Warning message
warning() {
    log "${YELLOW}WARNING: $1${NC}"
}

# Check if running as root or with sudo
if [[ $EUID -eq 0 ]]; then
    error_exit "This script should not be run as root"
fi

# Create log file if it doesn't exist
touch "$LOG_FILE"

log "Starting deployment process..."

# Navigate to project directory
if [[ ! -d "$PROJECT_DIR" ]]; then
    error_exit "Project directory $PROJECT_DIR does not exist"
fi

cd "$PROJECT_DIR" || error_exit "Failed to change to project directory"

# Backup current state
log "Creating backup of current state..."
cp -r . ../marketplace_backup_$(date +%Y%m%d_%H%M%S) 2>/dev/null || warning "Failed to create backup"

# Fetch latest changes
log "Fetching latest changes from GitHub..."
git fetch origin "$BRANCH" || error_exit "Failed to fetch from GitHub"

# Check if there are new changes
LOCAL_COMMIT=$(git rev-parse HEAD)
REMOTE_COMMIT=$(git rev-parse origin/$BRANCH)

if [[ "$LOCAL_COMMIT" == "$REMOTE_COMMIT" ]]; then
    log "No new changes detected. Deployment skipped."
    exit 0
fi

log "New changes detected. Starting deployment..."

# Pull latest changes
log "Pulling latest changes..."
git pull origin "$BRANCH" || error_exit "Failed to pull latest changes"

# Activate virtual environment
log "Activating virtual environment..."
source "$VENV_PATH/bin/activate" || error_exit "Failed to activate virtual environment"

# Install/update dependencies
log "Installing/updating Python dependencies..."
pip install -r requirements.txt || error_exit "Failed to install dependencies"

# Run database migrations
log "Running database migrations..."
python -m flask db upgrade || warning "Database migration failed or not configured"

# Collect static files (if using Flask-Assets or similar)
if [[ -f "manage.py" ]]; then
    log "Collecting static files..."
    python manage.py collectstatic --noinput || warning "Static file collection failed"
fi

# Test the application
log "Testing application..."
python -c "
import sys
sys.path.insert(0, '$PROJECT_DIR')
try:
    from app import app
    print('Application import successful')
except Exception as e:
    print(f'Application test failed: {e}')
    sys.exit(1)
" || error_exit "Application test failed"

# Restart the application service
log "Restarting application service..."
if systemctl is-active --quiet marketplace; then
    sudo systemctl restart marketplace || error_exit "Failed to restart marketplace service"
    success "Marketplace service restarted successfully"
elif systemctl is-active --quiet gunicorn; then
    sudo systemctl restart gunicorn || error_exit "Failed to restart gunicorn service"
    success "Gunicorn service restarted successfully"
else
    warning "No known service found. Please restart your application manually"
fi

# Clear cache (if using Redis)
if command -v redis-cli &> /dev/null; then
    log "Clearing Redis cache..."
    redis-cli FLUSHDB || warning "Failed to clear Redis cache"
fi

# Health check
log "Performing health check..."
sleep 5
if curl -f http://localhost:5000/health > /dev/null 2>&1; then
    success "Health check passed"
else
    warning "Health check failed - application may not be responding"
fi

# Cleanup old backups (keep last 5)
log "Cleaning up old backups..."
cd ..
ls -t marketplace_backup_* | tail -n +6 | xargs -r rm -rf

success "Deployment completed successfully!"
log "Deployment process finished"

# Send notification (optional - uncomment and configure)
# curl -X POST -H 'Content-type: application/json' \
#     --data '{"text":"Marketplace deployment completed successfully!"}' \
#     https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK

exit 0 