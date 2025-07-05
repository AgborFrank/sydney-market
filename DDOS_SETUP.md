# DDoS Protection and reCAPTCHA Setup Guide

This guide explains how to set up and configure the DDoS protection and reCAPTCHA features in your Sydney Marketplace.

## Features Implemented

### 1. DDoS Protection System
- **Rate Limiting**: Configurable limits per minute, hour, and day
- **Burst Protection**: Prevents rapid-fire requests
- **IP Blocking**: Automatic blocking of suspicious IPs
- **User Agent Filtering**: Blocks known bot and scanner user agents
- **IP Reputation**: Checks IP reputation against external APIs
- **Whitelist Support**: Allow trusted IPs to bypass restrictions

### 2. reCAPTCHA Integration
- **Google reCAPTCHA v2**: Invisible captcha for better UX
- **Form Protection**: Applied to login and registration forms
- **Configurable**: Can be enabled/disabled via admin panel

## Environment Variables

Create a `.env` file in your project root with the following variables:

```bash
# Flask Configuration
SECRET_KEY=your-super-secret-key-here
FLASK_ENV=production
FLASK_DEBUG=False

# Database Configuration
DB_NAME=marketplace
DB_USER=marketplace_user
DB_PASSWORD=secure_password
DB_HOST=localhost

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# DDoS Protection Configuration
DDOS_ENABLED=true
DDOS_MAX_REQUESTS_PER_MINUTE=60
DDOS_MAX_REQUESTS_PER_HOUR=1000
DDOS_MAX_REQUESTS_PER_DAY=10000
DDOS_BURST_LIMIT=10
DDOS_BURST_WINDOW=5
DDOS_BLOCK_DURATION=3600
DDOS_WHITELIST_IPS=127.0.0.1,::1

# reCAPTCHA Configuration
RECAPTCHA_ENABLED=true
RECAPTCHA_SITE_KEY=your-recaptcha-site-key
RECAPTCHA_SECRET_KEY=your-recaptcha-secret-key

# Rate Limiting Configuration
RATE_LIMIT_ENABLED=true
RATE_LIMIT_DEFAULT=100 per day, 50 per hour
RATE_LIMIT_LOGIN=5 per minute
RATE_LIMIT_REGISTER=3 per hour
RATE_LIMIT_API=1000 per hour

# User Agent Filtering
BLOCK_SUSPICIOUS_USER_AGENTS=true

# IP Reputation
ENABLE_IP_REPUTATION=true
IP_REPUTATION_API_KEY=your-ip-reputation-api-key
IP_REPUTATION_THRESHOLD=0.7
```

## Setup Instructions

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Set up Redis

Install and start Redis server:

```bash
# Ubuntu/Debian
sudo apt-get install redis-server
sudo systemctl start redis-server

# macOS
brew install redis
brew services start redis

# Windows
# Download Redis for Windows and start the server
```

### 3. Configure reCAPTCHA

1. Go to [Google reCAPTCHA Admin Console](https://www.google.com/recaptcha/admin)
2. Create a new site
3. Choose reCAPTCHA v2 "I'm not a robot" Checkbox
4. Add your domain(s)
5. Copy the Site Key and Secret Key to your `.env` file

### 4. Start the Application

```bash
python app.py
```

## Admin Panel Configuration

Access the DDoS protection settings at `/admin/ddos_protection`:

- **DDoS Protection Settings**: Enable/disable and configure limits
- **reCAPTCHA Settings**: Configure site and secret keys
- **IP Whitelist**: Add trusted IP addresses
- **Statistics**: View blocked IPs and recent activity

## Security Features

### Rate Limiting
- **Per-minute limit**: 60 requests (configurable)
- **Per-hour limit**: 1000 requests (configurable)
- **Per-day limit**: 10000 requests (configurable)
- **Burst protection**: 10 requests per 5 seconds (configurable)

### User Agent Filtering
Blocks requests from known suspicious user agents:
- Bots and crawlers
- Security scanners (nmap, sqlmap, etc.)
- Automated tools (curl, wget, etc.)

### IP Reputation
- Checks IP reputation using external APIs
- Blocks IPs from known hosting providers/VPNs
- Configurable reputation threshold

### Automatic Blocking
- IPs exceeding rate limits are automatically blocked
- Block duration: 1 hour (configurable)
- Blocked IPs are logged with timestamps and reasons

## Monitoring and Logs

### DDoS Statistics
- Number of blocked IPs
- Recent blocked requests
- Total requests per day
- Whitelisted IPs

### Log Files
- Application logs: `app.log`
- DDoS protection logs: Integrated with main application logs
- Redis stores real-time statistics and blocked IPs

## Customization

### Adjusting Rate Limits
Modify the environment variables to adjust limits based on your needs:

```bash
# More restrictive
DDOS_MAX_REQUESTS_PER_MINUTE=30
DDOS_MAX_REQUESTS_PER_HOUR=500

# Less restrictive
DDOS_MAX_REQUESTS_PER_MINUTE=120
DDOS_MAX_REQUESTS_PER_HOUR=2000
```

### Adding Custom User Agents
Edit the `SUSPICIOUS_USER_AGENTS` list in `config.py`:

```python
SUSPICIOUS_USER_AGENTS = [
    'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python-requests',
    'masscan', 'nmap', 'sqlmap', 'nikto', 'dirb', 'gobuster', 'wfuzz',
    'your-custom-bot-name'  # Add custom patterns
]
```

### IP Whitelist
Add trusted IPs to bypass all restrictions:

```bash
DDOS_WHITELIST_IPS=127.0.0.1,::1,192.168.1.100,10.0.0.50
```

## Troubleshooting

### Common Issues

1. **Redis Connection Error**
   - Ensure Redis server is running
   - Check Redis host/port configuration
   - Verify Redis password if set

2. **reCAPTCHA Not Working**
   - Verify site key and secret key are correct
   - Check domain configuration in reCAPTCHA admin
   - Ensure HTTPS is used in production

3. **Too Many False Positives**
   - Increase rate limits
   - Add legitimate IPs to whitelist
   - Adjust user agent filtering

4. **Performance Issues**
   - Monitor Redis memory usage
   - Adjust rate limit windows
   - Consider Redis clustering for high traffic

### Debug Mode
Enable debug logging by setting:

```bash
FLASK_DEBUG=true
```

This will show detailed DDoS protection logs in the console.

## Security Best Practices

1. **Regular Monitoring**: Check DDoS statistics regularly
2. **Whitelist Management**: Keep IP whitelist updated
3. **Rate Limit Tuning**: Adjust limits based on legitimate traffic patterns
4. **Log Analysis**: Monitor logs for attack patterns
5. **Backup Configuration**: Keep configuration backups
6. **Redis Security**: Secure Redis with authentication and firewall rules

## Support

For issues or questions:
1. Check the application logs
2. Review Redis statistics
3. Test with debug mode enabled
4. Contact the development team

## License

This DDoS protection system is part of the Sydney Marketplace project and follows the same licensing terms. 