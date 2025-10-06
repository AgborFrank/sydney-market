import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', os.urandom(32))
    
    DB_NAME = os.getenv('DB_NAME', 'marketplace')
    DB_USER = os.getenv('DB_USER', 'marketplace_user')
    DB_PASSWORD = os.getenv('DB_PASSWORD', 'secure_password')
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    
    SESSION_COOKIE_SECURE = False  # Set to False for development
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'  
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    UPLOAD_FOLDER = 'static/uploads'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'avif', 'webp'}
    BLOCKCYPHER_API = "https://api.blockcypher.com/v1/btc/main"  # Switched to mainnet
    ESCROW_PRIVATE_KEY = os.getenv('ESCROW_PRIVATE_KEY')
    BLOCKCYPHER_TOKEN = os.getenv('BLOCKCYPHER_TOKEN')
    WEBHOOK_URL = os.getenv('WEBHOOK_URL', 'http://your-public-url.com/webhook') 
    MONERO_RPC_HOST = os.getenv('MONERO_RPC_HOST', 'localhost')
    MONERO_RPC_PORT = int(os.getenv('MONERO_RPC_PORT', '18081'))
    MONERO_RPC_USER = os.getenv('MONERO_RPC_USER', '')
    MONERO_RPC_PASSWORD = os.getenv('MONERO_RPC_PASSWORD', '')
    
    ADMIN_BTC_ADDRESS = "37Ho9fkeiQNmH2jukknEWktsb3wYPS8vnS"  # Add this
    ADMIN_XMR_ADDRESS = "8Aw2oND3Hhg55cMxpdfZKGYVfscKudxhbT6hWteZvuBVXx8LBrBmhv6btogMzhVCvXUg5cZgD1X5k7My3fFEW5F48Crg4Pr"  # Add this
    ESCROW_BTC_ADDRESS = "bc1qc0kdv94stkx3egspk3afnr4jwxwvqssucp8xk7"  # Add this
    ESCROW_XMR_ADDRESS = "44CL16duABCA3CSiXJzuuZEmyy74tLjR5JdBMkwec5AFWDmV8ERL5zkJrY2K2uQtZqdfxJBBRMLn54xcVqeHB5VBDGmiDaZ"  # Add this
    
    # Tor and Offline Mode Configuration
    TOR_ENABLED = os.getenv('TOR_ENABLED', 'false').lower() == 'true'
    TOR_PROXY_PORT = int(os.getenv('TOR_PROXY_PORT', '5000'))
    OFFLINE_MODE = os.getenv('OFFLINE_MODE', 'false').lower() == 'true'
    FALLBACK_BTC_PRICE = float(os.getenv('FALLBACK_BTC_PRICE', '110000'))
    FALLBACK_XMR_PRICE = float(os.getenv('FALLBACK_XMR_PRICE', '150'))
    
    # GPG Configuration for Tor compatibility
    GPG_HOME = os.getenv('GPG_HOME', os.path.expanduser('~/.gnupg_marketplace'))
    GPG_BINARY = os.getenv('GPG_BINARY', r"C:\Program Files (x86)\GnuPG\bin\gpg.exe")
    GPG_TIMEOUT = int(os.getenv('GPG_TIMEOUT', '30'))  # Increased timeout for Tor
    GPG_FALLBACK_ENABLED = os.getenv('GPG_FALLBACK_ENABLED', 'true').lower() == 'true'
    
    # Tor-specific session settings
    TOR_SESSION_TIMEOUT = int(os.getenv('TOR_SESSION_TIMEOUT', '3600'))  # 1 hour for Tor
    TOR_DB_TIMEOUT = int(os.getenv('TOR_DB_TIMEOUT', '30'))  # Database timeout for Tor
    
    # DDoS Protection Configuration - TEMPORARILY DISABLED FOR TESTING
    DDOS_ENABLED = False
    DDOS_MAX_REQUESTS_PER_MINUTE = int(os.getenv('DDOS_MAX_REQUESTS_PER_MINUTE', '100000'))
    DDOS_MAX_REQUESTS_PER_HOUR = int(os.getenv('DDOS_MAX_REQUESTS_PER_HOUR', '1000000'))
    DDOS_MAX_REQUESTS_PER_DAY = int(os.getenv('DDOS_MAX_REQUESTS_PER_DAY', '10000000'))
    DDOS_BURST_LIMIT = int(os.getenv('DDOS_BURST_LIMIT', '100000'))
    DDOS_BURST_WINDOW = int(os.getenv('DDOS_BURST_WINDOW', '5'))  # seconds
    DDOS_BLOCK_DURATION = int(os.getenv('DDOS_BLOCK_DURATION', '3600'))  # 1 hour
    DDOS_WHITELIST_IPS = ['127.0.0.1', '::1', 'localhost']  # Whitelist localhost for testing
    
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
    
    # CSRF Configuration
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour
    WTF_CSRF_SSL_STRICT = False  # Allow HTTP for development
    
    # Tor-specific CSRF settings
    TOR_CSRF_DISABLED = os.getenv('TOR_CSRF_DISABLED', 'false').lower() == 'true'
    TOR_CSRF_LENIENT = os.getenv('TOR_CSRF_LENIENT', 'true').lower() == 'true'
    
    # Rate Limiting Configuration - TEMPORARILY DISABLED FOR TESTING
    RATE_LIMIT_ENABLED = False
    RATE_LIMIT_DEFAULT = os.getenv('RATE_LIMIT_DEFAULT', '100000 per day, 50000 per hour')
    RATE_LIMIT_LOGIN = os.getenv('RATE_LIMIT_LOGIN', '1000 per minute')
    RATE_LIMIT_REGISTER = os.getenv('RATE_LIMIT_REGISTER', '1000 per hour')
    RATE_LIMIT_API = os.getenv('RATE_LIMIT_API', '100000 per hour')
    
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
    
    