# ✅ Digital Ocean Deployment Checklist

## Pre-Deployment
- [ ] Digital Ocean account created
- [ ] Domain name purchased (optional)
- [ ] SSH key generated (recommended)
- [ ] Code committed to Git repository

## Server Setup
- [ ] Digital Ocean droplet created (Ubuntu 22.04 LTS)
- [ ] SSH connection established to server
- [ ] Code uploaded to `/var/www/marketplace/`
- [ ] `deploy.sh` script made executable
- [ ] Deployment script run successfully

## Environment Configuration
- [ ] `.env` file created from `env.example`
- [ ] `SECRET_KEY` generated and configured
- [ ] `WEBHOOK_URL` set to server IP/domain
- [ ] `RECAPTCHA_SITE_KEY` and `RECAPTCHA_SECRET_KEY` configured
- [ ] `BLOCKCYPHER_TOKEN` obtained and configured
- [ ] `ESCROW_PRIVATE_KEY` configured (if using escrow)
- [ ] Database configuration set

## Services Verification
- [ ] Python virtual environment created
- [ ] All dependencies installed successfully
- [ ] Redis server running
- [ ] Nginx configured and running
- [ ] Marketplace service running
- [ ] Firewall configured (UFW)

## Application Setup
- [ ] Database initialized
- [ ] Admin user created
- [ ] Application accessible via HTTP
- [ ] Static files serving correctly
- [ ] All routes working properly

## Security & SSL (Optional)
- [ ] Domain DNS configured
- [ ] Nginx configuration updated with domain
- [ ] SSL certificate installed (Let's Encrypt)
- [ ] HTTPS redirect configured
- [ ] Security headers verified

## Testing
- [ ] Homepage loads correctly
- [ ] User registration works
- [ ] User login works
- [ ] Vendor registration works
- [ ] Product creation works
- [ ] Payment system works
- [ ] Messaging system works
- [ ] Admin panel accessible

## Monitoring
- [ ] Log files configured
- [ ] System monitoring set up
- [ ] Backup strategy implemented
- [ ] Performance monitoring enabled

## Final Steps
- [ ] Documentation updated
- [ ] Team access configured
- [ ] Monitoring alerts set up
- [ ] Backup verification completed

## Post-Deployment
- [ ] Performance testing completed
- [ ] Security audit performed
- [ ] Load testing (if needed)
- [ ] User acceptance testing completed

---

## Quick Commands Reference

```bash
# Check service status
systemctl status marketplace nginx redis-server

# View logs
journalctl -u marketplace -f
tail -f /var/log/nginx/access.log

# Restart services
systemctl restart marketplace
systemctl reload nginx

# Test application
curl http://localhost:5000
curl http://YOUR_SERVER_IP

# Update application
cd /var/www/marketplace
git pull origin main
systemctl restart marketplace
```

## Emergency Contacts
- Digital Ocean Support: https://www.digitalocean.com/support/
- Application Logs: `journalctl -u marketplace -f`
- Nginx Logs: `/var/log/nginx/`
- System Resources: `htop`, `df -h`, `free -h` 