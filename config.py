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
    GPG_HOME = os.path.expanduser('~/.gnupg_marketplace')
    GPG_BINARY = os.getenv('GPG_BINARY', r"C:\Program Files (x86)\GnuPG\bin\gpg.exe") 
    BLOCKCYPHER_API = "https://api.blockcypher.com/v1/btc/test3"  # Adjusted to testnet
    ESCROW_PRIVATE_KEY = os.getenv('ESCROW_PRIVATE_KEY')
    BLOCKCYPHER_TOKEN = os.getenv('BLOCKCYPHER_TOKEN')
    WEBHOOK_URL = os.getenv('WEBHOOK_URL', 'http://your-public-url.com/webhook') 
    MONERO_RPC_HOST = os.getenv('MONERO_RPC_HOST', 'localhost')
    MONERO_RPC_PORT = os.getenv('MONERO_RPC_PORT', '18081')
    MONERO_RPC_USER = os.getenv('MONERO_RPC_USER', '')
    MONERO_RPC_PASSWORD = os.getenv('MONERO_RPC_PASSWORD', '')
    ADMIN_BTC_ADDRESS = "your-admin-btc-address"  # Add this