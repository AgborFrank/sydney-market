"""
PGP utilities using python-gnupg library for Python 3.13 compatibility.
This replaces pgpy functionality with a more compatible library.
"""

import os
import logging
import tempfile
from typing import Optional, Tuple
from config import Config

# Handle python-gnupg import gracefully
try:
    import gnupg
    GNUPG_AVAILABLE = True
except ImportError as e:
    print(f"Warning: python-gnupg not available: {e}")
    GNUPG_AVAILABLE = False
    gnupg = None

logger = logging.getLogger(__name__)

class PGPUtils:
    """PGP utilities using python-gnupg for Python 3.13 compatibility."""
    
    def __init__(self):
        self.gpg = None
        if GNUPG_AVAILABLE:
            try:
                # Create temporary directory for GPG operations
                self.gpg_home = tempfile.mkdtemp()
                self.gpg = gnupg.GPG(gnupghome=self.gpg_home)
                logger.info("PGP utilities initialized with python-gnupg")
            except Exception as e:
                logger.error(f"Failed to initialize GPG: {e}")
                self.gpg = None
    
    def encrypt_message(self, pgp_public_key: str, message: str) -> Optional[str]:
        """Encrypt a message using a PGP public key."""
        if not GNUPG_AVAILABLE or not self.gpg:
            logger.error("PGP encryption not available")
            return message  # Return unencrypted as fallback
        
        try:
            # Import the public key
            import_result = self.gpg.import_keys(pgp_public_key)
            if not import_result.fingerprints:
                logger.error("Failed to import PGP public key")
                return message
            
            # Encrypt the message
            encrypted = self.gpg.encrypt(message, import_result.fingerprints[0])
            if encrypted.ok:
                return str(encrypted)
            else:
                logger.error(f"Encryption failed: {encrypted.status}")
                return message
                
        except Exception as e:
            logger.error(f"Failed to encrypt message: {e}")
            return message
    
    def decrypt_message(self, private_key_blob: str, passphrase: str, encrypted_message: str) -> Optional[str]:
        """Decrypt a message using a private key."""
        if not GNUPG_AVAILABLE or not self.gpg:
            logger.error("PGP decryption not available")
            return encrypted_message  # Return as-is as fallback
        
        try:
            # Import the private key
            import_result = self.gpg.import_keys(private_key_blob)
            if not import_result.fingerprints:
                logger.error("Failed to import PGP private key")
                return None
            
            # Decrypt the message
            decrypted = self.gpg.decrypt(encrypted_message, passphrase=passphrase)
            if decrypted.ok:
                return str(decrypted)
            else:
                logger.error(f"Decryption failed: {decrypted.status}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to decrypt message: {e}")
            return None
    
    def generate_keypair(self, username: str, email: str, passphrase: str) -> Tuple[Optional[str], Optional[str]]:
        """Generate a new PGP keypair."""
        if not GNUPG_AVAILABLE or not self.gpg:
            logger.error("PGP keypair generation not available")
            return None, None
        
        try:
            # Generate key input data
            input_data = self.gpg.gen_key_input(
                key_type="RSA",
                key_length=2048,
                name_real=username,
                name_email=email,
                passphrase=passphrase,
                expire_date='2y'  # Expire in 2 years
            )
            
            # Generate the key
            key = self.gpg.gen_key(input_data)
            if key.fingerprint:
                # Export public key
                public_key = str(self.gpg.export_keys(key.fingerprint))
                # Export private key
                private_key = str(self.gpg.export_keys(key.fingerprint, True, passphrase=passphrase))
                
                logger.info(f"PGP keypair generated for {username}")
                return public_key, private_key
            else:
                logger.error("Failed to generate PGP keypair")
                return None, None
                
        except Exception as e:
            logger.error(f"Failed to generate PGP keypair: {e}")
            return None, None
    
    def get_key_fingerprint(self, pgp_public_key: str) -> Optional[str]:
        """Get the fingerprint of a PGP public key."""
        if not GNUPG_AVAILABLE or not self.gpg:
            logger.error("PGP fingerprint not available")
            return None
        
        try:
            # Import the public key
            import_result = self.gpg.import_keys(pgp_public_key)
            if import_result.fingerprints:
                return import_result.fingerprints[0]
            else:
                logger.error("Failed to import PGP public key for fingerprint")
                return None
                
        except Exception as e:
            logger.error(f"Failed to get PGP fingerprint: {e}")
            return None
    
    def cleanup(self):
        """Clean up temporary files."""
        if hasattr(self, 'gpg_home') and os.path.exists(self.gpg_home):
            import shutil
            shutil.rmtree(self.gpg_home, ignore_errors=True)

# Global instance
pgp_utils = PGPUtils()
