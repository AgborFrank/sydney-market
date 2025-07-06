# 🚀 Digital Ocean Deployment Guide

This guide will help you deploy your Flask marketplace application on Digital Ocean.

## 📋 Prerequisites

- Digital Ocean account
- Domain name (optional but recommended)
- SSH key (recommended for security)

## 🔧 Step-by-Step Deployment

### Step 1: Create Digital Ocean Droplet

1. **Log into Digital Ocean**
2. **Click "Create" → "Droplets"**
3. **Configure your droplet:**
   - **Choose an image:** Ubuntu 22.04 LTS
   - **Choose a plan:** Basic (2GB RAM, 1 CPU, 50GB SSD) - $12/month
   - **Choose a datacenter region:** Choose closest to your target users
   - **Authentication:** SSH key (recommended) or password
   - **Finalize and create**

### Step 2: Connect to Your Server

```bash
# Replace YOUR_SERVER_IP with your droplet's IP address
ssh root@YOUR_SERVER_IP
```

### Step 3: Upload Your Code

You have several options to get your code on the server:

#### Option A: Git Clone (Recommended)
```bash
# On your server
cd /var/www
git clone https://github.com/yourusername/marketplace.git
cd marketplace
```

#### Option B: SCP Upload
```bash
# From your local machine
scp -r /path/to/your/marketplace root@YOUR_SERVER_IP:/var/www/
```

#### Option C: Manual Upload
Use Digital Ocean's file manager or SFTP to upload your files.

### Step 4: Run the Deployment Script

```bash
# Make the script executable
chmod +x deploy.sh

# Run the deployment script
sudo ./deploy.sh
```

### Step 5: Configure Environment Variables

```bash
# Copy the example environment file
cp env.example .env

# Edit the environment file
nano .env
```

**Important variables to configure:**
- `SECRET_KEY`: Generate a secure random key
- `WEBHOOK_URL`: Your domain or server IP
- `RECAPTCHA_SITE_KEY` and `RECAPTCHA_SECRET_KEY`: Get from Google reCAPTCHA
- `BLOCKCYPHER_TOKEN`: Get from BlockCypher API
- `ESCROW_PRIVATE_KEY`: Your Bitcoin private key for escrow

### Step 6: Set Up Domain and SSL (Optional)

If you have a domain:

1. **Point your domain to your server IP**
2. **Update Nginx configuration:**
   ```bash
   nano /etc/nginx/sites-available/marketplace
   # Replace 'your-domain.com' with your actual domain
   ```

3. **Install SSL certificate:**
   ```bash
   apt install certbot python3-certbot-nginx
   certbot --nginx -d your-domain.com
   ```

### Step 7: Initialize Database

```bash
# Navigate to your project directory
cd /var/www/marketplace

# Initialize the database
python3 -c "
from utils.database import init_db
init_db()
print('Database initialized successfully!')
"
```

### Step 8: Create Admin User

```bash
# Create an admin user (you'll need to implement this in your app)
# For now, you can manually insert into the database or use your app's registration
```

## 🔍 Testing Your Deployment

### Check Services Status
```bash
# Check if all services are running
systemctl status marketplace
systemctl status nginx
systemctl status redis-server
```

### Test the Application
```bash
# Test if the app is responding
curl http://localhost:5000
curl http://YOUR_SERVER_IP
```

### View Logs
```bash
# Application logs
journalctl -u marketplace -f

# Nginx logs
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log
```

## 🔧 Configuration Details

### Nginx Configuration
The deployment script creates an Nginx configuration at `/etc/nginx/sites-available/marketplace` that:
- Serves static files efficiently
- Proxies requests to your Flask app
- Includes security headers
- Handles webhook endpoints

### Systemd Service
Your app runs as a systemd service called `marketplace` that:
- Automatically starts on boot
- Restarts on failure
- Runs with proper permissions
- Uses Gunicorn for production

### Redis Configuration
Redis is configured for:
- Session storage
- Caching
- Rate limiting
- Background job queues

## 🛡️ Security Considerations

### Firewall
The deployment script configures UFW firewall to allow:
- SSH (port 22)
- HTTP (port 80)
- HTTPS (port 443)

### Security Headers
Nginx is configured with security headers:
- X-Frame-Options
- X-XSS-Protection
- X-Content-Type-Options
- Content-Security-Policy

### File Permissions
- Application runs as `www-data` user
- Proper file permissions set
- Sensitive files protected

## 🔄 Updating Your Application

### Manual Update
```bash
cd /var/www/marketplace
git pull origin main
systemctl restart marketplace
```

### Automatic Updates (Optional)
If you set up the webhook handler:
1. Configure GitHub webhook
2. Push changes to trigger automatic deployment

## 🚨 Troubleshooting

### Common Issues

1. **Application not starting:**
   ```bash
   journalctl -u marketplace -f
   # Check for Python import errors or missing dependencies
   ```

2. **Nginx errors:**
   ```bash
   nginx -t
   systemctl status nginx
   ```

3. **Redis connection issues:**
   ```bash
   systemctl status redis-server
   redis-cli ping
   ```

4. **Permission issues:**
   ```bash
   chown -R www-data:www-data /var/www/marketplace
   chmod -R 755 /var/www/marketplace
   ```

### Performance Optimization

1. **Enable Gzip compression:**
   ```bash
   # Add to Nginx config
   gzip on;
   gzip_types text/plain text/css application/json application/javascript;
   ```

2. **Configure caching:**
   ```bash
   # Static files are already cached for 30 days
   # Consider adding Redis caching for database queries
   ```

3. **Monitor resources:**
   ```bash
   htop
   df -h
   free -h
   ```

## 📊 Monitoring

### Basic Monitoring
```bash
# Check system resources
htop
df -h
free -h

# Check application status
systemctl status marketplace
curl -f http://localhost:5000/health
```

### Log Monitoring
```bash
# Real-time log monitoring
tail -f /var/log/marketplace/app.log
journalctl -u marketplace -f
```

## 🎉 Success!

Your marketplace is now deployed and running on Digital Ocean! 

**Next steps:**
1. Configure your domain DNS
2. Set up SSL certificate
3. Create admin user
4. Test all functionality
5. Set up monitoring and backups

**Your marketplace URL:** `http://YOUR_SERVER_IP` or `https://your-domain.com` 