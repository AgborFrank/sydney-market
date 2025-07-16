# 🚀 Digital Ocean Deployment Guide - Tor Hidden Service (.onion)

This guide will help you deploy your Flask marketplace application on Digital Ocean as a Tor hidden service with a custom "sydney" prefix onion address.

## 📋 Prerequisites

- Digital Ocean account
- SSH key (recommended for security)
- Tor Browser (for testing)
- Basic understanding of Tor network

## 🔧 Step-by-Step Deployment

### Step 1: Create Digital Ocean Droplet

1. **Log into Digital Ocean**
2. **Click "Create" → "Droplets"**
3. **Configure your droplet:**
   - **Choose an image:** Ubuntu 22.04 LTS
   - **Choose a plan:** Basic (2GB RAM, 1 CPU, 50GB SSD) - $12/month
   - **Choose a datacenter region:** Choose a privacy-friendly location (Netherlands, Germany, Switzerland)
   - **Authentication:** SSH key (recommended) or password
   - **Finalize and create**

**⚠️ Privacy Note:** Choose a datacenter in a privacy-friendly jurisdiction for better anonymity.

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

### Step 6: Install and Configure Tor

```bash
# Install Tor
apt update
apt install -y tor

# Stop Tor service to configure it
systemctl stop tor

# Backup original config
cp /etc/tor/torrc /etc/tor/torrc.backup

# Configure Tor for hidden service
cat > /etc/tor/torrc << 'EOF'
# Tor configuration for hidden service
SocksPort 0
RunAsDaemon 1
DataDirectory /var/lib/tor
PidFile /var/run/tor/tor.pid

# Hidden service configuration
HiddenServiceDir /var/lib/tor/marketplace/
HiddenServicePort 80 127.0.0.1:5000

# Security settings
HiddenServiceMaxStreams 0
HiddenServiceMaxStreamsCloseCircuit 0

# Performance settings
MaxCircuitDirtiness 600
MaxClientCircuitsPending 48
EOF

# Create hidden service directory
mkdir -p /var/lib/tor/marketplace
chown -R debian-tor:debian-tor /var/lib/tor/marketplace
chmod 700 /var/lib/tor/marketplace

# Start Tor service
systemctl start tor
systemctl enable tor

# Wait for Tor to generate the onion address
echo "Waiting for Tor to generate onion address..."
sleep 30

# Display the onion address
echo "Your onion address:"
cat /var/lib/tor/marketplace/hostname
```

### Step 7: Generate Custom "sydney" Onion Address (Optional)

To get an onion address starting with "sydney", you'll need to generate vanity addresses:

```bash
# Install required tools
apt install -y python3-pip
pip3 install stem

# Create vanity address generator
cat > /root/generate_vanity.py << 'EOF'
#!/usr/bin/env python3
import os
import sys
import time
from stem import Signal
from stem.control import Controller

def generate_vanity_address(prefix="sydney"):
    print(f"Generating onion address starting with '{prefix}'...")
    print("This may take several hours or days depending on your luck.")

    attempts = 0
    start_time = time.time()

    while True:
        attempts += 1

        # Restart Tor to get new address
        os.system("systemctl restart tor")
        time.sleep(30)

        try:
            with open('/var/lib/tor/marketplace/hostname', 'r') as f:
                onion_address = f.read().strip()

            if onion_address.startswith(prefix):
                elapsed = time.time() - start_time
                print(f"\n🎉 Success! Found address: {onion_address}")
                print(f"Attempts: {attempts}")
                print(f"Time elapsed: {elapsed/3600:.2f} hours")
                break
            else:
                if attempts % 100 == 0:
                    elapsed = time.time() - start_time
                    print(f"Attempts: {attempts}, Current: {onion_address}, Time: {elapsed/3600:.2f}h")

        except Exception as e:
            print(f"Error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    prefix = sys.argv[1] if len(sys.argv) > 1 else "sydney"
    generate_vanity_address(prefix)
EOF

# Make it executable
chmod +x /root/generate_vanity.py

# Run the generator (this will take time)
# python3 /root/generate_vanity.py sydney
```

**⚠️ Note:** Generating a vanity address can take hours or days. You can run this in the background or use the default onion address for now.

### Step 8: Initialize Database

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

### Step 9: Create Admin User

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
systemctl status tor
```

### Test the Application

```bash
# Test if the app is responding locally
curl http://localhost:5000

# Get your onion address
echo "Your onion address:"
cat /var/lib/tor/marketplace/hostname

# Test Tor hidden service (from another machine with Tor)
# curl --socks5 localhost:9050 http://YOUR_ONION_ADDRESS.onion
```

### View Logs

```bash
# Application logs
journalctl -u marketplace -f

# Nginx logs
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log

# Tor logs
journalctl -u tor -f
tail -f /var/log/tor/log
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

**⚠️ Tor Security:** For maximum privacy, consider blocking all incoming traffic except SSH and letting Tor handle all web traffic.

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

5. **Tor hidden service issues:**

   ```bash
   # Check Tor service
   systemctl status tor

   # Restart Tor service
   systemctl restart tor

   # Check hidden service directory permissions
   ls -la /var/lib/tor/marketplace/
   chown -R debian-tor:debian-tor /var/lib/tor/marketplace
   chmod 700 /var/lib/tor/marketplace

   # Regenerate onion address
   rm -rf /var/lib/tor/marketplace/*
   systemctl restart tor
   sleep 30
   cat /var/lib/tor/marketplace/hostname
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

# Tor-specific monitoring
tail -f /var/log/tor/log
journalctl -u tor -f
```

### Tor Security Monitoring

```bash
# Check Tor service status
systemctl status tor

# View Tor configuration
cat /etc/tor/torrc

# Check hidden service status
ls -la /var/lib/tor/marketplace/

# Monitor Tor connections
tail -f /var/log/tor/log | grep "Hidden service"

# Check for Tor circuit status
echo "AUTHENTICATE \"\"" | nc 127.0.0.1 9051
echo "GETINFO version" | nc 127.0.0.1 9051
```

## 🎉 Success!

Your marketplace is now deployed and running on Digital Ocean as a Tor hidden service!

**Next steps:**

1. Get your onion address: `cat /var/lib/tor/marketplace/hostname`
2. Test access through Tor Browser
3. Create admin user
4. Test all functionality
5. Set up monitoring and backups
6. (Optional) Generate vanity "sydney" onion address

**Your marketplace URL:** `http://YOUR_ONION_ADDRESS.onion`

**🔒 Privacy Features:**

- All traffic routed through Tor network
- No IP address exposure
- Encrypted communications
- Anonymous access
