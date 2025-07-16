# Deploying Flask Marketplace on DigitalOcean with Tor Hidden Service

This guide outlines the steps to deploy a Flask marketplace on a DigitalOcean Ubuntu droplet and configure a Tor hidden service with a vanity onion address starting with "syd". It assumes a Flask app structure similar to `sydney-market` (https://github.com/AgborFrank/sydney-market.git) with dependencies like Redis.

## Prerequisites

- DigitalOcean droplet (Ubuntu 22.04 or later) with root access.
- GitHub repository with the Flask app (e.g., `https://github.com/AgborFrank/sydney-market.git`).
- Local machine with SSH client and Tor Browser installed (https://www.torproject.org/download/).

## Step 1: Set Up SSH and Non-Root User

1. **SSH into the droplet as root**:

   ```bash
   ssh root@<droplet-ip>
   ```
2. **Create a non-root user** (e.g., `deployer`):

   ```bash
   adduser deployer
   usermod -aG sudo deployer
   ```
3. **Set up SSH key-based authentication**:
   - On your local machine, generate an SSH key if needed:

     ```bash
     ssh-keygen -t rsa -b 4096
     ssh-copy-id deployer@<droplet-ip>
     ```
   - Disable root login for security:

     ```bash
     sudo nano /etc/ssh/sshd_config
     # Set: PermitRootLogin no
     sudo systemctl reload sshd
     ```
4. **Update the system**:

   ```bash
   sudo apt update && sudo apt upgrade -y
   ```
5. **Log in as** `deployer`:

   ```bash
   ssh deployer@<droplet-ip>
   ```

## Step 2: Clone Repository and Set Up Flask Environment

1. **Install dependencies**:

   ```bash
   sudo apt install -y git python3 python3-pip python3-venv redis-server
   
   
   
   
   ```

   **Clone the repository**:

   ```bash
   mkdir ~/marketplace
   cd ~/marketplace
   git clone <repository-url> .
   ```
2. **Set up a virtual environment**:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   pip install redis gunicorn
   ```
3. **Verify Redis**:

   ```bash
   sudo systemctl start redis-server
   sudo systemctl enable redis-server
   redis-cli ping  # Should return PONG
   ```
4. **Test the Flask app**:

   ```bash
   export FLASK_APP=app.py
   flask run --host=0.0.0.0 --port=5000
   ```
   - Test from your local machine: `curl http://<droplet-ip>:5000`
   - Allow port 5000 temporarily: `sudo ufw allow 5000`
   - Stop with `Ctrl+C` and deactivate: `deactivate`

## Step 3: Configure Gunicorn and Nginx

1. **Test Gunicorn**:

   ```bash
   source ~/marketplace/venv/bin/activate
   gunicorn --bind 0.0.0.0:5000 app:app
   ```
   - Test: `curl http://<droplet-ip>:5000`
   - Stop with `Ctrl+C` and deactivate.
2. **Install Nginx**:

   ```bash
   sudo apt install -y nginx
   sudo systemctl start nginx
   sudo systemctl enable nginx
   ```
3. **Set up Gunicorn systemd service**:

   ```bash
   sudo nano /etc/systemd/system/marketplace.service
   ```

   Add:

   ```ini
   [Unit]
   Description=Gunicorn instance for Marketplace
   After=network.target
   
   [Service]
   User=deployer
   Group=www-data
   WorkingDirectory=/home/deployer/marketplace
   Environment="PATH=/home/deployer/marketplace/venv/bin"
   ExecStart=/home/deployer/marketplace/venv/bin/gunicorn --workers 3 --bind 127.0.0.1:5000 app:app
   
   [Install]
   WantedBy=multi-user.target
   ```

   Enable and start:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl start marketplace
   sudo systemctl enable marketplace
   ```
4. **Configure Nginx**:

   ```bash
   sudo nano /etc/nginx/sites-available/marketplace
   ```

   Add:

   ```nginx
   server {
       listen 80 default_server;
       location / {
           proxy_pass http://127.0.0.1:5000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```

   Enable and reload:

   ```bash
   sudo rm /etc/nginx/sites-enabled/default
   sudo ln -s /etc/nginx/sites-available/marketplace /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl reload nginx
   ```
5. **Configure firewall**:

   ```bash
   sudo ufw allow 80
   sudo ufw deny 5000
   sudo ufw enable
   ```
6. **Test the app**:
   - Access: `curl http://<droplet-ip>` or open `http://<droplet-ip>` in a browser.

## Step 4: Set Up Tor Hidden Service with Vanity Address

1. **Install Tor**:

   ```bash
   sudo apt install -y tor
   sudo systemctl start tor
   sudo systemctl enable tor
   ```
2. **Configure Tor hidden service**:

   ```bash
   sudo nano /etc/tor/torrc
   ```

   Add:

   ```torrc
   HiddenServiceDir /var/lib/tor/marketplace/
   HiddenServicePort 80 127.0.0.1:80
   ```

   Save and restart:

   ```bash
   sudo systemctl restart tor
   ```
3. **Install** `mkp224o` **for vanity address**:

   ```bash
   sudo apt install -y autoconf automake build-essential libssl-dev libsodium-dev
   cd ~
   git clone https://github.com/cathugger/mkp224o.git
   cd mkp224o
   ./autogen.sh
   ./configure
   make
   ```
4. **Generate vanity address starting with "syd"**:

   ```bash
   ./mkp224o syd
   ```
   - This creates a `syd*` directory with `hostname`, etc.
5. **Back up existing hidden service**:

   ```bash
   sudo cp -r /var/lib/tor/marketplace ~/marketplace-backup
   ```
6. **Copy vanity address files**:

   ```bash
   sudo cp -r ./syd*/* /var/lib/tor/marketplace/
   sudo chown -R debian-tor:debian-tor /var/lib/tor/marketplace
   sudo chmod -R 700 /var/lib/tor/marketplace
   ```
7. **Restart Tor and verify**:

   ```bash
   sudo systemctl restart tor
   sudo cat /var/lib/tor/marketplace/hostname  # Should start with syd
   sudo systemctl status tor
   ```
8. **Test the onion address**:
   - In Tor Browser, navigate to the onion address (e.g., `http://sydxxxxxxxxxxxxxx.onion`).
   - Verify the Flask app loads.

## Troubleshooting Tips

- **Redis errors**: Ensure `redis-server` is running (`sudo systemctl status redis-server`) and the `redis` Python package is installed (`pip install redis`).
- **Nginx 502 errors**: Check Gunicorn service (`sudo systemctl status marketplace`) and Nginx logs (`sudo cat /var/log/nginx/error.log`).
- **Tor issues**: Verify `torrc` config and logs (`sudo journalctl -u tor`).
- **mkp224o build failures**: Ensure all dependencies (`libsodium-dev`, `autoconf`, etc.) are installed and check build output.

## Notes

- Store the onion private key (`/var/lib/tor/marketplace/private_key`) securely.
- For clearnet HTTPS, consider Let’s Encrypt after Tor setup.
- Regularly back up the app and hidden service directories.