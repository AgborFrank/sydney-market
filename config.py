import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', os.urandom(32)) 
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'  
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    UPLOAD_FOLDER = 'static/uploads'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'avif', 'webp'}
    GPG_HOME = os.path.expanduser('~/.gnupg_marketplace')
    GPG_BINARY = os.getenv('GPG_BINARY', r"C:\Program Files (x86)\GnuPG\bin\gpg.exe") 
    BLOCKCYPHER_TOKEN = os.getenv('BLOCKCYPHER_TOKEN', "58c3bc03de534a57929a7a4ff8c2c54c")  
    BLOCKCYPHER_API = "https://api.blockcypher.com/v1/btc/test3"  # Adjusted to testnet
    ESCROW_PRIVATE_KEY = os.getenv('ESCROW_PRIVATE_KEY', "KyCPisNQcrNefkD3R4QbCkGFPV83pXDXfs2oiqV6L3ACsKedm5kz")  # Optional: Env var
    WEBHOOK_URL = os.getenv('WEBHOOK_URL', 'http://your-public-url.com/webhook') 
    ADMIN_BTC_ADDRESS = "your-admin-btc-address"  # Add this