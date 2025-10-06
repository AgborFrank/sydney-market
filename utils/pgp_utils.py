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
                
                # Try different GPG binary paths
                gpg_paths = ['/usr/local/bin/gpg', '/usr/bin/gpg', 'gpg']
                gpg_binary = None
                
                for path in gpg_paths:
                    try:
                        # Test if the binary exists and works
                        import subprocess
                        result = subprocess.run([path, '--version'], 
                                              capture_output=True, text=True, timeout=5)
                        if result.returncode == 0:
                            gpg_binary = path
                            break
                    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                        continue
                
                if not gpg_binary:
                    raise RuntimeError("GPG binary not found in any of the expected locations")
                
                self.gpg = gnupg.GPG(homedir=self.gpg_home, binary=gpg_binary)
                logger.info(f"PGP utilities initialized with python-gnupg using {gpg_binary}")
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
                # Export private key (python-gnupg doesn't support passphrase parameter in export_keys)
                private_key = str(self.gpg.export_keys(key.fingerprint, True))
                
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
    
    def sign_message(self, private_key_blob: str, passphrase: str, message: str) -> Optional[str]:
        """Sign a message using a private key."""
        if not GNUPG_AVAILABLE or not self.gpg:
            logger.error("PGP signing not available")
            return self._create_fallback_signature(message)
        
        try:
            # Import the private key
            import_result = self.gpg.import_keys(private_key_blob)
            if not import_result.fingerprints:
                logger.error("Failed to import PGP private key for signing")
                return self._create_fallback_signature(message)
            
            # Sign the message
            signed = self.gpg.sign(message, keyid=import_result.fingerprints[0], passphrase=passphrase)
            if signed:
                return str(signed)
            else:
                logger.error("Failed to sign message")
                return self._create_fallback_signature(message)
                
        except Exception as e:
            logger.error(f"Failed to sign message: {e}")
            return self._create_fallback_signature(message)
    
    def create_detached_signature(self, private_key_blob: str, passphrase: str, message: str) -> Optional[str]:
        """Create a detached PGP signature."""
        if not GNUPG_AVAILABLE or not self.gpg:
            logger.error("PGP detached signature not available")
            return None
        
        try:
            # Import the private key
            import_result = self.gpg.import_keys(private_key_blob)
            if not import_result.fingerprints:
                logger.error("Failed to import PGP private key for detached signature")
                return None
            
            # Create detached signature
            signed = self.gpg.sign(message, keyid=import_result.fingerprints[0], 
                                 passphrase=passphrase, detach=True)
            if signed:
                return str(signed)
            else:
                logger.error("Failed to create detached signature")
                return None
                
        except Exception as e:
            logger.error(f"Failed to create detached signature: {e}")
            return None
    
    def verify_signature(self, public_key: str, signature: str, message: str = None) -> bool:
        """Verify a PGP signature."""
        # Check if this is a fallback signature
        if 'MARKETPLACE SIGNATURE' in signature:
            return self._verify_fallback_signature(signature)
        
        if not GNUPG_AVAILABLE or not self.gpg:
            logger.error("PGP signature verification not available")
            return False
        
        try:
            # Import the public key
            import_result = self.gpg.import_keys(public_key)
            if not import_result.fingerprints:
                logger.error("Failed to import PGP public key for verification")
                return False
            
            # Verify the signature
            if message:
                # Verify with message content
                verified = self.gpg.verify(signature, message)
            else:
                # Verify detached signature
                verified = self.gpg.verify(signature)
            
            return verified.valid if verified else False
                
        except Exception as e:
            logger.error(f"Failed to verify signature: {e}")
            return False

    def _create_fallback_signature(self, message: str) -> str:
        """Create a fallback signature when PGP is not available."""
        import hashlib
        import base64
        from datetime import datetime
        
        # Create a simple hash-based signature
        timestamp = datetime.utcnow().isoformat()
        signature_data = f"{message}|{timestamp}|MARKETPLACE_VERIFICATION"
        signature_hash = hashlib.sha256(signature_data.encode()).digest()
        signature_b64 = base64.b64encode(signature_hash).decode()
        
        fallback_signature = f"""-----BEGIN MARKETPLACE SIGNATURE-----
Version: Fallback 1.0
Timestamp: {timestamp}
Signature: {signature_b64}
Message: {message}
-----END MARKETPLACE SIGNATURE-----"""
        
        logger.warning("Using fallback signature due to PGP unavailability")
        return fallback_signature

    def _verify_fallback_signature(self, signature: str) -> bool:
        """Verify a fallback signature."""
        try:
            import hashlib
            import base64
            from datetime import datetime, timedelta
            
            # Parse the signature
            lines = signature.strip().split('\n')
            if len(lines) < 6 or 'MARKETPLACE SIGNATURE' not in signature:
                return False
            
            # Extract components
            timestamp = None
            signature_hash = None
            message = None
            
            for line in lines:
                if line.startswith('Timestamp:'):
                    timestamp = line.split(':', 1)[1].strip()
                elif line.startswith('Signature:'):
                    signature_hash = line.split(':', 1)[1].strip()
                elif line.startswith('Message:'):
                    message = line.split(':', 1)[1].strip()
            
            if not all([timestamp, signature_hash, message]):
                return False
            
            # Check timestamp (should be within 24 hours)
            try:
                sig_time = datetime.fromisoformat(timestamp)
                now = datetime.utcnow()
                if abs((now - sig_time).total_seconds()) > 86400:  # 24 hours
                    logger.warning("Fallback signature is too old")
                    return False
            except ValueError:
                return False
            
            # Verify the signature
            signature_data = f"{message}|{timestamp}|MARKETPLACE_VERIFICATION"
            expected_hash = hashlib.sha256(signature_data.encode()).digest()
            expected_hash_b64 = base64.b64encode(expected_hash).decode()
            
            return signature_hash == expected_hash_b64
            
        except Exception as e:
            logger.error(f"Failed to verify fallback signature: {e}")
            return False

    def cleanup(self):
        """Clean up temporary files."""
        if hasattr(self, 'gpg_home') and os.path.exists(self.gpg_home):
            import shutil
            shutil.rmtree(self.gpg_home, ignore_errors=True)

# Global instance
pgp_utils = PGPUtils()
