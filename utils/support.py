import secrets
import hashlib
import base64
import logging
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pgpy
from utils.database import get_db_connection, get_settings

logger = logging.getLogger(__name__)

class SecureSupportTicket:
    """Handles secure support ticket creation and communication for both buyers and vendors."""
    
    def __init__(self):
        self.settings = get_settings()
    
    def generate_ticket_key(self, ticket_id, user_id):
        """Generate a unique encryption key for a ticket."""
        # Create a deterministic but unique key based on ticket and user
        salt = f"ticket_{ticket_id}_user_{user_id}".encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(str(ticket_id).encode()))
        return key
    
    def encrypt_ticket_content(self, content, ticket_id, user_id):
        """Encrypt ticket content using Fernet symmetric encryption."""
        try:
            key = self.generate_ticket_key(ticket_id, user_id)
            fernet = Fernet(key)
            encrypted_content = fernet.encrypt(content.encode())
            return base64.b64encode(encrypted_content).decode()
        except Exception as e:
            logger.error(f"Failed to encrypt ticket content: {str(e)}")
            return None
    
    def decrypt_ticket_content(self, encrypted_content, ticket_id, user_id):
        """Decrypt ticket content using Fernet symmetric encryption."""
        try:
            key = self.generate_ticket_key(ticket_id, user_id)
            fernet = Fernet(key)
            encrypted_bytes = base64.b64decode(encrypted_content.encode())
            decrypted_content = fernet.decrypt(encrypted_bytes)
            return decrypted_content.decode()
        except Exception as e:
            logger.error(f"Failed to decrypt ticket content: {str(e)}")
            return None
    
    def encrypt_with_pgp(self, content, recipient_pgp_key):
        """Encrypt content with recipient's PGP public key."""
        try:
            if not recipient_pgp_key or not recipient_pgp_key.strip():
                logger.debug("No PGP key provided for encryption")
                return None
            
            # Validate PGP key format
            if not recipient_pgp_key.startswith('-----BEGIN PGP PUBLIC KEY BLOCK-----'):
                logger.warning("Invalid PGP key format")
                return None
            
            key, _ = pgpy.PGPKey.from_blob(recipient_pgp_key)
            message = pgpy.PGPMessage.new(content)
            encrypted = key.encrypt(message)
            return str(encrypted)
        except Exception as e:
            logger.error(f"Failed to encrypt with PGP: {str(e)}")
            return None
    
    def create_secure_ticket(self, user_id, subject, description, category, priority, user_role='user'):
        """Create a new secure support ticket with encrypted content."""
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                
                # Create the ticket
                c.execute("""
                    INSERT INTO tickets (user_id, subject, category, priority, description, status, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (user_id, subject, category, priority, description, 'open', datetime.utcnow(), datetime.utcnow()))
                
                ticket_id = c.lastrowid
                
                # Encrypt the description
                encrypted_description = self.encrypt_ticket_content(description, ticket_id, user_id)
                if not encrypted_description:
                    logger.warning(f"Failed to encrypt description for ticket {ticket_id}, using plain text")
                    encrypted_description = description
                
                # Update ticket with encrypted description
                c.execute("""
                    UPDATE tickets SET description = ? WHERE id = ?
                """, (encrypted_description, ticket_id))
                
                # Store encryption key hash for verification
                try:
                    key_hash = hashlib.sha256(
                        self.generate_ticket_key(ticket_id, user_id)
                    ).hexdigest()
                    
                    c.execute("""
                        INSERT INTO ticket_encryption_keys (ticket_id, user_id, encryption_key_hash)
                        VALUES (?, ?, ?)
                    """, (ticket_id, user_id, key_hash))
                except Exception as key_error:
                    logger.error(f"Failed to store encryption key for ticket {ticket_id}: {str(key_error)}")
                    # Continue without key storage
                
                conn.commit()
                
                # Log ticket creation
                logger.info(f"Secure ticket #{ticket_id} created by {user_role} {user_id}")
                
                return ticket_id
                
        except Exception as e:
            logger.error(f"Failed to create secure ticket: {str(e)}")
            return None
    
    def add_secure_response(self, ticket_id, sender_id, response_body, sender_role='user'):
        """Add a secure response to a ticket with optional PGP encryption."""
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                
                # Get ticket details
                c.execute("""
                    SELECT t.user_id, t.description, u.pgp_public_key, u.role
                    FROM tickets t
                    JOIN users u ON t.user_id = u.id
                    WHERE t.id = ?
                """, (ticket_id,))
                
                ticket_data = c.fetchone()
                if not ticket_data:
                    return False
                
                ticket_user_id, encrypted_description, user_pgp_key, user_role = ticket_data
                
                # Encrypt response content
                encrypted_response = self.encrypt_ticket_content(response_body, ticket_id, sender_id)
                
                # If sender is admin and user has PGP key, also encrypt with PGP
                pgp_encrypted = None
                is_encrypted = False
                
                if sender_role == 'admin' and user_pgp_key and user_pgp_key.strip():
                    try:
                        pgp_encrypted = self.encrypt_with_pgp(response_body, user_pgp_key)
                        is_encrypted = pgp_encrypted is not None
                    except Exception as pgp_error:
                        logger.error(f"PGP encryption failed for ticket {ticket_id}: {str(pgp_error)}")
                        # Continue without PGP encryption
                        pgp_encrypted = None
                        is_encrypted = False
                
                # Store response
                c.execute("""
                    INSERT INTO ticket_responses (ticket_id, sender_id, body, encrypted_body, is_encrypted, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (ticket_id, sender_id, encrypted_response, pgp_encrypted, is_encrypted, datetime.utcnow()))
                
                # Update ticket status and timestamp
                c.execute("""
                    UPDATE tickets SET updated_at = ?, status = ?
                    WHERE id = ?
                """, (datetime.utcnow(), 'in-progress', ticket_id))
                
                conn.commit()
                
                logger.info(f"Secure response added to ticket #{ticket_id} by {sender_role} {sender_id}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to add secure response: {str(e)}")
            return False
    
    def get_ticket_with_responses(self, ticket_id, user_id, user_role):
        """Get ticket details and responses with proper decryption."""
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                
                # Get ticket details
                c.execute("""
                    SELECT t.*, u.pusername, u.role as user_role, u.pgp_public_key
                    FROM tickets t
                    JOIN users u ON t.user_id = u.id
                    WHERE t.id = ?
                """, (ticket_id,))
                
                ticket = c.fetchone()
                if not ticket:
                    return None, []
                
                ticket = dict(ticket)
                
                # Decrypt description if user is ticket owner or admin
                if user_role == 'admin' or ticket['user_id'] == user_id:
                    try:
                        decrypted_description = self.decrypt_ticket_content(
                            ticket['description'], ticket_id, ticket['user_id']
                        )
                        ticket['description'] = decrypted_description or ticket['description']
                    except Exception as decrypt_error:
                        logger.error(f"Failed to decrypt description for ticket {ticket_id}: {str(decrypt_error)}")
                        # Keep original description if decryption fails
                
                # Get responses
                c.execute("""
                    SELECT tr.*, u.pusername, u.role as sender_role, u.pgp_public_key
                    FROM ticket_responses tr
                    JOIN users u ON tr.sender_id = u.id
                    WHERE tr.ticket_id = ?
                    ORDER BY tr.created_at
                """, (ticket_id,))
                
                responses = []
                for row in c.fetchall():
                    response = dict(row)
                    
                    # Decrypt response body
                    try:
                        decrypted_body = self.decrypt_ticket_content(
                            response['body'], ticket_id, response['sender_id']
                        )
                        response['body'] = decrypted_body or response['body']
                    except Exception as decrypt_error:
                        logger.error(f"Failed to decrypt response body: {str(decrypt_error)}")
                        # Keep original body if decryption fails
                    
                    # If PGP encrypted and user has private key, decrypt
                    if response['is_encrypted'] and response['encrypted_body']:
                        # This would require user's private key - implement based on your PGP setup
                        # For now, we'll just indicate it's PGP encrypted
                        pass
                    
                    responses.append(response)
                
                return ticket, responses
                
        except Exception as e:
            logger.error(f"Failed to get ticket with responses: {str(e)}")
            return None, []
    
    def get_user_tickets(self, user_id, user_role):
        """Get all tickets for a user with proper decryption."""
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                
                if user_role == 'admin':
                    # Admin can see all tickets
                    c.execute("""
                        SELECT t.*, u.pusername, u.role as user_role
                        FROM tickets t
                        JOIN users u ON t.user_id = u.id
                        ORDER BY t.updated_at DESC
                    """)
                else:
                    # Regular users see only their tickets
                    c.execute("""
                        SELECT t.*, u.pusername, u.role as user_role
                        FROM tickets t
                        JOIN users u ON t.user_id = u.id
                        WHERE t.user_id = ?
                        ORDER BY t.updated_at DESC
                    """, (user_id,))
                
                tickets = []
                for row in c.fetchall():
                    ticket = dict(row)
                    
                    # Decrypt description for ticket owner or admin
                    if user_role == 'admin' or ticket['user_id'] == user_id:
                        decrypted_description = self.decrypt_ticket_content(
                            ticket['description'], ticket['id'], ticket['user_id']
                        )
                        ticket['description'] = decrypted_description or ticket['description']
                    
                    tickets.append(ticket)
                
                return tickets
                
        except Exception as e:
            logger.error(f"Failed to get user tickets: {str(e)}")
            return []
    
    def cleanup_expired_tickets(self, days=30):
        """Clean up old tickets and their encryption keys."""
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                
                cutoff_date = datetime.utcnow() - timedelta(days=days)
                
                # Get tickets to delete
                c.execute("""
                    SELECT id FROM tickets 
                    WHERE status = 'closed' AND updated_at < ?
                """, (cutoff_date,))
                
                ticket_ids = [row[0] for row in c.fetchall()]
                
                if ticket_ids:
                    # Delete responses
                    c.execute("""
                        DELETE FROM ticket_responses 
                        WHERE ticket_id IN ({})
                    """.format(','.join('?' * len(ticket_ids))), ticket_ids)
                    
                    # Delete encryption keys
                    c.execute("""
                        DELETE FROM ticket_encryption_keys 
                        WHERE ticket_id IN ({})
                    """.format(','.join('?' * len(ticket_ids))), ticket_ids)
                    
                    # Delete tickets
                    c.execute("""
                        DELETE FROM tickets 
                        WHERE id IN ({})
                    """.format(','.join('?' * len(ticket_ids))), ticket_ids)
                    
                    conn.commit()
                    logger.info(f"Cleaned up {len(ticket_ids)} expired tickets")
                
        except Exception as e:
            logger.error(f"Failed to cleanup expired tickets: {str(e)}")

# Global instance
secure_support = SecureSupportTicket()

def schedule_ticket_cleanup():
    """Schedule ticket cleanup task."""
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        from apscheduler.triggers.cron import CronTrigger
        
        scheduler = BackgroundScheduler()
        scheduler.add_job(
            func=secure_support.cleanup_expired_tickets,
            trigger=CronTrigger(hour=2, minute=0),  # Run at 2 AM daily
            id='ticket_cleanup',
            name='Clean up expired support tickets',
            replace_existing=True
        )
        scheduler.start()
        logger.info("Scheduled ticket cleanup task")
    except Exception as e:
        logger.error(f"Failed to schedule ticket cleanup: {str(e)}") 