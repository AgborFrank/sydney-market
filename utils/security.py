import secrets
from flask import session
import pgpy
import hashlib
import logging
from config import Config
from datetime import datetime
import smtplib
import socks
import socket
import os

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def regenerate_session():
    """Regenerate the session ID while preserving user_id and role."""
    user_id = session.get('user_id')
    role = session.get('role')
    session.clear()
    if user_id:
        session['user_id'] = user_id
        session['role'] = role
    session.modified = True
    logger.debug("Session regenerated, user_id: %s, role: %s", user_id, role)

def encrypt_message(pgp_public_key, message):
    try:
        key, _ = pgpy.PGPKey.from_blob(pgp_public_key)
        msg = pgpy.PGPMessage.new(message)
        encrypted = key.encrypt(msg)
        logger.debug("Message encrypted successfully")
        return str(encrypted)
    except Exception as e:
        logger.error(f"Failed to encrypt with PGP key: {str(e)}")
        raise ValueError(f"Failed to encrypt with PGP key: {str(e)}")

def decrypt_message(private_key_blob, passphrase, encrypted_message):
    try:
        # Load the passphrase-protected private key
        key, _ = pgpy.PGPKey.from_blob(private_key_blob)
        # Unlock the private key with the passphrase
        if not key.is_unlocked:
            key.unlock(passphrase)
        # Decrypt the message
        msg = pgpy.PGPMessage.from_blob(encrypted_message)
        decrypted = key.decrypt(msg)
        logger.debug("Message decrypted successfully")
        return str(decrypted.message)
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        return None

def generate_pgp_keypair(pusername, email, passphrase):
    try:
        # Input validation
        if not isinstance(pusername, str) or not pusername:
            raise ValueError("Username must be a non-empty string")
        if not isinstance(email, str) or '@' not in email:
            raise ValueError("Email must be a valid string with '@'")
        if not isinstance(passphrase, str) or len(passphrase) < 8:
            raise ValueError("Passphrase must be a string of at least 8 characters")

        key = pgpy.PGPKey.new('RSA', 2048)
        uid = pgpy.PGPUID.new(pusername, email=email)
        key.add_uid(uid, usage={'sign', 'encrypt'}, ciphers=['AES256'], hashes=['SHA256'], compression=['ZLIB'])
        key.protect(passphrase, 'AES256', 'SHA256')
        public_key = str(key.pubkey)
        private_key = str(key)
        logger.info(f"PGP keypair generated for {pusername}")
        return public_key, private_key
    except ValueError as ve:
        logger.error(f"Input error in generate_pgp_keypair: {str(ve)}")
        return None, None
    except Exception as e:
        logger.error(f"Unexpected error in generate_pgp_keypair: {type(e).__name__}: {str(e)}")
        return None, None
    
def store_pgp_keys(user_id, pusername, email, passphrase):
    from utils.database import get_db_connection
    public_key, private_key = generate_pgp_keypair(pusername, email, passphrase)
    if public_key and private_key:
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("UPDATE users SET pgp_public_key = ?, pgp_private_key = ? WHERE id = ?",
                          (public_key, private_key, user_id))
                conn.commit()
                logger.info(f"PGP keys stored for user_id {user_id}")
                return True
        except Exception as e:
            logger.error(f"Failed to store PGP keys: {str(e)}")
            return False
    return False

def log_admin_action_encrypted(action, admin, pgp_pubkey):
    message = f"[{datetime.utcnow()}] {admin}: {action}"
    pubkey, _ = pgpy.PGPKey.from_blob(pgp_pubkey)
    msg = pgpy.PGPMessage.new(message)
    encrypted = pubkey.encrypt(msg)
    with open('admin_action_logs.pgp', 'a') as f:
        f.write(str(encrypted) + '\n')

def send_pgp_email_over_tor(to_email, subject, message, pgp_public_key, smtp_host, smtp_port, smtp_user, smtp_password, from_email=None):
    """
    Encrypts the message with the recipient's PGP public key and sends it via SMTP over Tor.
    """
    # Encrypt message with PGP
    try:
        pubkey, _ = pgpy.PGPKey.from_blob(pgp_public_key)
        msg = pgpy.PGPMessage.new(message)
        encrypted_message = str(pubkey.encrypt(msg))
    except Exception as e:
        print(f"[PGP] Encryption failed: {e}")
        return False

    # Prepare email
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from email.header import Header

    from_addr = from_email or smtp_user
    mime_msg = MIMEMultipart()
    mime_msg['From'] = from_addr
    mime_msg['To'] = to_email
    mime_msg['Subject'] = Header(subject, 'utf-8')
    mime_msg.attach(MIMEText(encrypted_message, 'plain', 'utf-8'))

    # Route all sockets through Tor SOCKS5 proxy
    socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
    socket.socket = socks.socksocket

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.sendmail(from_addr, [to_email], mime_msg.as_string())
        print(f"[Email] PGP email sent to {to_email} via Tor.")
        return True
    except Exception as e:
        print(f"[Email] Failed to send email via Tor: {e}")
        return False

def init_gpg_for_tor():
    """
    Initialize GPG with Tor-specific settings and fallback mechanisms.
    """
    try:
        import gnupg
        
        # Create GPG home directory if it doesn't exist
        import os
        os.makedirs(Config.GPG_HOME, exist_ok=True)
        
        # Initialize GPG with Tor-specific settings
        gpg = gnupg.GPG(
            gnupghome=Config.GPG_HOME,
            gpgbinary=Config.GPG_BINARY
        )
        
        # Test GPG functionality
        test_result = gpg.list_keys()
        logger.info("GPG initialized successfully for Tor")
        return gpg, None
        
    except Exception as e:
        logger.error(f"GPG initialization failed: {e}")
        if Config.GPG_FALLBACK_ENABLED:
            logger.info("Using fallback encryption method")
            return None, "fallback"
        else:
            return None, str(e)

def is_tor_request(request):
    """
    Check if the request is coming from Tor network.
    """
    forwarded_for = request.headers.get('X-Forwarded-For', '')
    host = request.headers.get('Host', '')
    
    return (forwarded_for.endswith('.onion') or 
            '.onion' in host or 
            'tor' in request.headers.get('User-Agent', '').lower())