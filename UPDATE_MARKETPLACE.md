# Updating Flask Marketplace Files on DigitalOcean Droplet

This guide explains how to update the Flask marketplace files in `/home/deployer/marketplace` with changes from the GitHub repository (e.g., https://github.com/AgborFrank/sydney-market.git) without disrupting existing configurations (Gunicorn, Nginx, Tor, Redis). It assumes the setup from the previous deployment instructions and an Ubuntu-based DigitalOcean droplet.

## Prerequisites

- Access to the `deployer` user on the droplet (`ssh deployer@<droplet-ip>`).
- Updated GitHub repository with new code.
- Tor Browser to verify the onion address after updates.

## Steps to Update Repository Files

1. **Back Up Current Files and Configurations**:
   - Back up the marketplace directory and Tor hidden service:
     ```bash
     sudo cp -r /home/deployer/marketplace ~/marketplace-backup-$(date +%F)
     sudo cp -r /var/lib/tor/marketplace ~/tor-backup-$(date +%F)
     ```
   - Verify backups:
     ```bash
     ls ~ | grep backup
     ```

2. **Pull Updates from GitHub**:
   - Navigate to the marketplace directory and activate the virtual environment:
     ```bash
     cd ~/marketplace
     source venv/bin/activate
     ```
   - Stash any local changes (if applicable) and pull updates:
     ```bash
     git stash
     git pull origin main
     ```
     - Replace `main` with the appropriate branch if different.
     - Resolve any merge conflicts manually if prompted (e.g., edit conflicting files, then `git add` and `git commit`).

3. **Update Dependencies**:
   - Install any new or updated dependencies from `requirements.txt`:
     ```bash
     pip install -r requirements.txt
     ```
   - Ensure `redis` and `gunicorn` are installed:
     ```bash
     pip install redis gunicorn
     ```

4. **Test the Updated Application Locally**:
   - Verify Redis is running:
     ```bash
     sudo systemctl status redis-server
     redis-cli ping  # Should return PONG
     ```
   - Test the Flask app:
     ```bash
     export FLASK_APP=app.py
     flask run --host=127.0.0.1 --port=5001
     ```
     - Use port 5001 to avoid conflicting with Gunicorn on 5000.
     - Test locally on the droplet: `curl http://127.0.0.1:5001`
     - Stop with `Ctrl+C`.

5. **Apply Database Migrations (if applicable)**:
   - If the app uses a database (e.g., SQLAlchemy), apply migrations:
     ```bash
     # Example for Flask-Migrate
     flask db upgrade
     ```
     - Adjust the command based on your app’s migration tool (check `README.md` or `app.py`).

6. **Restart Gunicorn with Zero Downtime**:
   - Reload Gunicorn without stopping the service:
     ```bash
     sudo systemctl reload marketplace
     ```
     - If reload isn’t supported, gracefully restart:
       ```bash
       sudo systemctl restart marketplace
       ```
   - Verify Gunicorn is running:
     ```bash
     sudo systemctl status marketplace
     ```

7. **Verify Nginx and Tor Configurations**:
   - Ensure Nginx is serving the app:
     ```bash
     sudo nginx -t
     sudo systemctl status nginx
     curl http://<droplet-ip>
     ```
   - Check the Tor hidden service:
     ```bash
     sudo cat /var/lib/tor/marketplace/hostname  # Should start with syd
     sudo systemctl status tor
     ```
   - Test the onion address in Tor Browser (e.g., `http://sydxxxxxxxxxxxxxx.onion`).

8. **Clean Up**:
   - Deactivate the virtual environment:
     ```bash
     deactivate
     ```
   - Remove old backups if disk space is limited (keep at least one recent backup):
     ```bash
     ls ~/ | grep backup
     # Example: sudo rm -r ~/marketplace-backup-old-date
     ```

## Troubleshooting

- **Git pull conflicts**: Manually resolve conflicts or consult the repository’s `README.md`.
- **Dependency errors**: Check `pip install` output or logs in `app.py` for missing packages.
- **Gunicorn failures**: View logs: `sudo journalctl -u marketplace`.
- **Nginx issues**: Check: `sudo cat /var/log/nginx/error.log`.
- **Tor issues**: Inspect: `sudo journalctl -u tor`.
- **Redis errors**: Ensure service is running: `sudo systemctl status redis-server`.

## Notes

- Preserve configurations in `/etc/nginx/sites-available/marketplace`, `/etc/systemd/system/marketplace.service`, and `/etc/tor/torrc`.
- Store backups and the Tor private key (`/var/lib/tor/marketplace/private_key`) securely.
- For HTTPS on the clearnet site (`http://<droplet-ip>`), consider Let’s Encrypt post-update.