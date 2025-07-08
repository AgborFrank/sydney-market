import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', os.urandom(32))
    
    DB_NAME = os.getenv('DB_NAME', 'marketplace')
    DB_USER = os.getenv('DB_USER', 'marketplace_user')
    DB_PASSWORD = os.getenv('DB_PASSWORD', 'secure_password')
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'  
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    UPLOAD_FOLDER = 'static/uploads'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'avif', 'webp'}
    GPG_HOME = os.getenv('GPG_HOME', os.path.expanduser('~/.gnupg_marketplace'))
    GPG_BINARY = os.getenv('GPG_BINARY', r"C:\Program Files (x86)\GnuPG\bin\gpg.exe") 
    BLOCKCYPHER_API = "https://api.blockcypher.com/v1/btc/main"  # Switched to mainnet
    ESCROW_PRIVATE_KEY = os.getenv('ESCROW_PRIVATE_KEY')
    BLOCKCYPHER_TOKEN = os.getenv('BLOCKCYPHER_TOKEN')
    WEBHOOK_URL = os.getenv('WEBHOOK_URL', 'http://your-public-url.com/webhook') 
    MONERO_RPC_HOST = os.getenv('MONERO_RPC_HOST', 'localhost')
    MONERO_RPC_PORT = int(os.getenv('MONERO_RPC_PORT', '18081'))
    MONERO_RPC_USER = os.getenv('MONERO_RPC_USER', '')
    MONERO_RPC_PASSWORD = os.getenv('MONERO_RPC_PASSWORD', '')
    ADMIN_BTC_ADDRESS = "your-admin-btc-address"  # Add this
    
    # DDoS Protection Configuration
    DDOS_ENABLED = True
    DDOS_MAX_REQUESTS_PER_MINUTE = int(os.getenv('DDOS_MAX_REQUESTS_PER_MINUTE', '6000'))
    DDOS_MAX_REQUESTS_PER_HOUR = int(os.getenv('DDOS_MAX_REQUESTS_PER_HOUR', '1000'))
    DDOS_MAX_REQUESTS_PER_DAY = int(os.getenv('DDOS_MAX_REQUESTS_PER_DAY', '10000'))
    DDOS_BURST_LIMIT = int(os.getenv('DDOS_BURST_LIMIT', '10000'))
    DDOS_BURST_WINDOW = int(os.getenv('DDOS_BURST_WINDOW', '5'))  # seconds
    DDOS_BLOCK_DURATION = int(os.getenv('DDOS_BLOCK_DURATION', '3600'))  # 1 hour
    DDOS_WHITELIST_IPS = os.getenv('DDOS_WHITELIST_IPS', '').split(',') if os.getenv('DDOS_WHITELIST_IPS') else []
    
    # reCAPTCHA Configuration
    RECAPTCHA_ENABLED = os.getenv('RECAPTCHA_ENABLED', 'true').lower() == 'true'
    RECAPTCHA_SITE_KEY = os.getenv('RECAPTCHA_SITE_KEY', '')
    RECAPTCHA_SECRET_KEY = os.getenv('RECAPTCHA_SECRET_KEY', '')
    RECAPTCHA_VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify'
    
    # Security Headers
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/; frame-src 'self' https://www.google.com/recaptcha/; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'",
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
    }
    
    # Rate Limiting Configuration
    RATE_LIMIT_ENABLED = os.getenv('RATE_LIMIT_ENABLED', 'true').lower() == 'true'
    RATE_LIMIT_DEFAULT = os.getenv('RATE_LIMIT_DEFAULT', '100 per day, 50 per hour')
    RATE_LIMIT_LOGIN = os.getenv('RATE_LIMIT_LOGIN', '5 per minute')
    RATE_LIMIT_REGISTER = os.getenv('RATE_LIMIT_REGISTER', '3 per hour')
    RATE_LIMIT_API = os.getenv('RATE_LIMIT_API', '1000 per hour')
    
    # User Agent Filtering
    BLOCK_SUSPICIOUS_USER_AGENTS = os.getenv('BLOCK_SUSPICIOUS_USER_AGENTS', 'true').lower() == 'true'
    SUSPICIOUS_USER_AGENTS = [
        'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python-requests',
        'masscan', 'nmap', 'sqlmap', 'nikto', 'dirb', 'gobuster', 'wfuzz'
    ]
    
    # IP Reputation
    ENABLE_IP_REPUTATION = os.getenv('ENABLE_IP_REPUTATION', 'true').lower() == 'true'
    IP_REPUTATION_API_KEY = os.getenv('IP_REPUTATION_API_KEY', '')
    IP_REPUTATION_THRESHOLD = float(os.getenv('IP_REPUTATION_THRESHOLD', '0.7'))
    
    