from flask import Blueprint, render_template, request, session, redirect, url_for, flash
from utils.database import get_db_connection, get_settings
from utils.security import validate_csrf_token, regenerate_session, encrypt_message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bcrypt
import sqlite3
import os
import logging
import pgpy
import secrets  
import gnupg
from cryptography.fernet import Fernet  
import base64

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

user_bp = Blueprint('user', __name__)
limiter = Limiter(get_remote_address, app=None)  # Attach in app.py

FERNET_KEY = Fernet.generate_key()  # Replace with a static key in config
cipher = Fernet(FERNET_KEY)

WORD_LIST = [
    "apple"
]  

UPLOAD_FOLDER_PRODUCTS = 'static/uploads/products'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

if not os.path.exists(UPLOAD_FOLDER_PRODUCTS):
    os.makedirs(UPLOAD_FOLDER_PRODUCTS)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



def is_vendor():
    return session.get('role') == 'vendor'

@user_bp.route('/login', methods=['GET', 'POST'])
def login():
    logger.debug("Entering /login")
    if request.method == 'POST':
        validate_csrf_token()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').encode('utf-8')
        
        if not username or not password:
            flash("Username and password are required.", 'error')
            return render_template('login.html', form_data=request.form.to_dict())
        
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = c.fetchone()
        
        if user and bcrypt.checkpw(password, user['password']):
            session['temp_user_id'] = user['id']
            session['temp_username'] = user['username']
            session['temp_role'] = user['role']
            logger.debug(f"Session set after login: temp_user_id={session['temp_user_id']}")
            return redirect(url_for('user.two_factor_auth'))
        flash("Invalid username or password.", 'error')
        return render_template('login.html', form_data=request.form.to_dict())
    return render_template('login.html', form_data={})

@user_bp.route('/two_factor_auth', methods=['GET', 'POST'])
def two_factor_auth():
    if 'temp_user_id' not in session:
        logger.warning("Access to two_factor_auth without temp_user_id in session")
        flash("Please log in first.", 'error')
        return redirect(url_for('user.login'))

    logger.debug(f"Entering two_factor_auth with temp_user_id: {session['temp_user_id']}")

    if request.method == 'POST':
        validate_csrf_token()
        pin = request.form.get('pin', '').strip()
        decrypted_message = request.form.get('decrypted_message', '').strip()

        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT pin, pgp_public_key FROM users WHERE id = ?", (session['temp_user_id'],))
            user = c.fetchone()

        if not user:
            logger.error(f"No user found for temp_user_id: {session['temp_user_id']}")
            flash("User not found. Please log in again.", 'error')
            session.clear()
            return redirect(url_for('user.login'))

        logger.debug(f"Retrieved PIN: {user['pin']}, PGP Key: {user['pgp_public_key']}")

        if str(user['pin']) != pin:
            flash("Invalid PIN.", 'error')
            return render_template('two_factor_auth.html', encrypted_message=session.get('encrypted_message', ''))

        original_message = session.get('original_message', '')
        if not original_message or decrypted_message != original_message:
            flash("Invalid decrypted message.", 'error')
            return render_template('two_factor_auth.html', encrypted_message=session.get('encrypted_message', ''))

        # Successful 2FA, finalize login
        user_id = session.pop('temp_user_id')
        username = session.pop('temp_username')
        role = session.pop('temp_role')
        regenerate_session()  # Clear and reset session first
        session['user_id'] = user_id  # Set after regeneration
        session['username'] = username
        session['role'] = role
        logger.debug(f"2FA successful, new session: user_id={session['user_id']}, role={session['role']}")
        flash("Login successful!", 'success')
        
        # Redirect based on role
        if role == 'vendor':
            return redirect(url_for('vendor.vendor_dashboard'))
        return redirect(url_for('user.dashboard'))

    # GET request
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT pgp_public_key FROM users WHERE id = ?", (session['temp_user_id'],))
        user = c.fetchone()

    if not user or not user['pgp_public_key']:
        logger.error(f"No PGP key found for temp_user_id: {session['temp_user_id']}")
        flash("No PGP key found. Contact support.", 'error')
        session.clear()
        return redirect(url_for('user.login'))

    logger.debug(f"PGP Key for encryption: {user['pgp_public_key']}")
    unique_word = secrets.choice(WORD_LIST)
    session['original_message'] = unique_word

    try:
        encrypted_message = encrypt_message(user['pgp_public_key'], unique_word)
        session['encrypted_message'] = encrypted_message
    except ValueError as e:
        logger.error(f"Encryption failed: {str(e)}")
        flash(str(e), 'error')
        return redirect(url_for('user.login'))

    return render_template('two_factor_auth.html', encrypted_message=encrypted_message)

@user_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        validate_csrf_token()
        username = request.form.get('username', '').strip()
        pusername = request.form.get('pusername', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        pin = request.form.get('pin', '').strip()

        if not all([username, pusername, password, confirm_password, pin]):
            flash("All fields are required.", 'error')
            return render_template('register.html', form_data=request.form.to_dict())

        if password != confirm_password:
            flash("Passwords do not match.", 'error')
            return render_template('register.html', form_data=request.form.to_dict())

        if len(pin) != 6 or not pin.isdigit():
            flash("PIN must be exactly 6 digits.", 'error')
            return render_template('register.html', form_data=request.form.to_dict())

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        with get_db_connection() as conn:
            c = conn.cursor()
            try:
                c.execute("INSERT INTO users (username, pusername, password, pin, role) VALUES (?, ?, ?, ?, ?)",
                          (username, pusername, hashed_password, pin, 'user'))
                user_id = c.lastrowid
                conn.commit()
                session['temp_user_id'] = user_id
                logger.debug(f"User registered, temp_user_id set: {user_id}")
                flash("Please add your PGP public key.", 'info')
                return redirect(url_for('user.add_pgp_key'))
            except sqlite3.IntegrityError:
                flash("Username or public username already exists.", 'error')
                return render_template('register.html', form_data=request.form.to_dict())
    return render_template('register.html', form_data={})

@user_bp.route('/add_pgp_key', methods=['GET', 'POST'])
def add_pgp_key():
    if 'temp_user_id' not in session:
        logger.warning("Access to add_pgp_key without temp_user_id in session")
        flash("Please register first.", 'error')
        return redirect(url_for('user.register'))

    if request.method == 'POST':
        validate_csrf_token()
        pgp_public_key = request.form.get('pgp_public_key', '').strip()

        if not pgp_public_key:
            flash("PGP public key is required.", 'error')
            return render_template('user/add_pgp_key.html', form_data=request.form.to_dict())

        if not (pgp_public_key.startswith('-----BEGIN PGP PUBLIC KEY BLOCK-----') and 
                pgp_public_key.endswith('-----END PGP PUBLIC KEY BLOCK-----')):
            flash("Invalid PGP public key format. Must start with '-----BEGIN PGP PUBLIC KEY BLOCK-----' and end with '-----END PGP PUBLIC KEY BLOCK-----'.", 'error')
            return render_template('user/add_pgp_key.html', form_data=request.form.to_dict())

        try:
            key, _ = pgpy.PGPKey.from_blob(pgp_public_key)
            logger.debug(f"PGP Key validated successfully: {pgp_public_key}")
        except Exception as e:
            logger.error(f"PGP Key validation failed: {str(e)}")
            flash(f"Invalid PGP public key: {str(e)}", 'error')
            return render_template('user/add_pgp_key.html', form_data=request.form.to_dict())

        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("UPDATE users SET pgp_public_key = ? WHERE id = ?", (pgp_public_key, session['temp_user_id']))
            conn.commit()

        flash("Registration completed! Please log in.", 'success')
        session.pop('temp_user_id', None)
        logger.debug("PGP key added, temp_user_id cleared from session")
        return redirect(url_for('user.login'))

    return render_template('user/add_pgp_key.html', form_data={})

@user_bp.route('/orders')
def orders():
    if 'user_id' not in session:
        flash("Please log in to view your orders.", 'error')
        return redirect(url_for('user.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT o.*, p.title, u.pusername as vendor_username
            FROM orders o
            JOIN products p ON o.product_id = p.id
            JOIN users u ON o.vendor_id = u.id
            WHERE o.user_id = ?
            ORDER BY o.created_at DESC
        """, (session['user_id'],))
        orders = [dict(row) for row in c.fetchall()]
    
    return render_template('user/orders.html', orders=orders, title="Your Orders - DarkVault")

@user_bp.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please log in to access your dashboard.", 'error')
        return redirect(url_for('user.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        # User info
        c.execute("SELECT username, pusername, created_at FROM users WHERE id = ?", (session['user_id'],))
        user_row = c.fetchone()
        if not user_row:
            logger.error(f"No user found for user_id: {session['user_id']}")
            flash("User not found. Please log in again.", 'error')
            session.clear()
            return redirect(url_for('user.login'))
        user = dict(user_row)
        
        # Recent orders
        c.execute("""
            SELECT o.*, p.title, u.pusername as vendor_username
            FROM orders o
            JOIN products p ON o.product_id = p.id
            JOIN users u ON o.vendor_id = u.id
            WHERE o.user_id = ?
            ORDER BY o.created_at DESC LIMIT 5
        """, (session['user_id'],))
        orders = [dict(row) for row in c.fetchall()]
        
        # Recent reports
        c.execute("""
            SELECT r.*, u.pusername as vendor_username
            FROM reports r
            LEFT JOIN users u ON r.vendor_id = u.id
            WHERE r.user_id = ?
            ORDER BY r.created_at DESC LIMIT 5
        """, (session['user_id'],))
        reports = [dict(row) for row in c.fetchall()]
    
    return render_template('user/dashboard.html', user=user, orders=orders, reports=reports, title="Dashboard - DarkVault")

@user_bp.route('/become_vendor', methods=['GET', 'POST'])
def become_vendor():
    if 'user_id' not in session:
        flash("Please log in to apply.", 'error')
        return redirect(url_for('user.login'))
    
    if request.method == 'POST':
        validate_csrf_token()
        pgp_key = request.form.get('pgp_public_key', '').strip()
        signed_message = request.form.get('signed_message', '').strip()
        
        # Initialize GPG
        gpg = gnupg.GPG()
        import_result = gpg.import_keys(pgp_key)
        if not import_result.count:
            flash("Invalid PGP key provided.", 'error')
            return render_template('user/become_vendor.html')
        
        # Verify signed message
        verification = gpg.verify(signed_message)
        if not verification.valid:
            flash("Failed to verify your signed message.", 'error')
            return render_template('user/become_vendor.html')
        
        # Manual step: Admin checks fingerprint against other markets
        fingerprint = import_result.fingerprints[0]
        flash(f"Application received. Fingerprint {fingerprint} under review.", 'success')
        # TODO: Admin process to search fingerprint and approve
        
        return redirect(url_for('user.dashboard'))
    
    return render_template('user/become_vendor.html')

@user_bp.route('/messages', methods=['GET', 'POST'])
def messages():
    if 'user_id' not in session:
        flash("Please log in to view messages.", 'error')
        return redirect(url_for('user.login'))
    
    gpg = gnupg.GPG()
    selected_recipient_id = request.args.get('recipient_id', type=int)
    
    with get_db_connection() as conn:
        c = conn.cursor()
        # Check if user has uploaded private key
        c.execute("SELECT pgp_private_key FROM users WHERE id = ?", (session['user_id'],))
        private_key_encrypted = c.fetchone()['pgp_private_key']
        has_private_key = bool(private_key_encrypted)
        
        # Handle private key upload
        if request.method == 'POST' and request.form.get('action') == 'upload_private_key':
            validate_csrf_token()
            private_key = request.form.get('private_key', '').strip()
            passphrase = request.form.get('passphrase', '').strip()
            if not private_key or not passphrase:
                flash("Private key and passphrase are required.", 'error')
            else:
                # Verify key by importing
                import_result = gpg.import_keys(private_key)
                if not import_result.count:
                    flash("Invalid PGP private key.", 'error')
                else:
                    # Encrypt private key with Fernet and store
                    encrypted_key = cipher.encrypt(f"{private_key}||{passphrase}".encode())
                    c.execute("UPDATE users SET pgp_private_key = ? WHERE id = ?",
                              (encrypted_key, session['user_id']))
                    conn.commit()
                    flash("Private key uploaded successfully.", 'success')
                    return redirect(url_for('user.messages'))
        
        # If no private key, show upload form only
        if not has_private_key:
            return render_template('user/messages.html', has_private_key=False)
        
        # Decrypt user's private key
        encrypted_key = private_key_encrypted
        decrypted_data = cipher.decrypt(encrypted_key).decode().split('||')
        private_key, passphrase = decrypted_data[0], decrypted_data[1]
        gpg.import_keys(private_key)
        
        # Handle sending a message
        if request.method == 'POST' and request.form.get('action') == 'send_message':
            validate_csrf_token()
            message = request.form.get('message', '').strip()
            if not message:
                flash("Message cannot be empty.", 'error')
            elif not selected_recipient_id:
                flash("No recipient selected.", 'error')
            else:
                c.execute("SELECT pgp_public_key FROM users WHERE id = ?", (selected_recipient_id,))
                recipient_key = c.fetchone()['pgp_public_key']
                if not recipient_key:
                    flash("Recipient has no PGP key.", 'error')
                else:
                    encrypted_msg = str(gpg.encrypt(message, recipients=[recipient_key], always_trust=True))
                    c.execute("""
                        INSERT INTO messages (sender_id, recipient_id, content, created_at)
                        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                    """, (session['user_id'], selected_recipient_id, encrypted_msg))
                    conn.commit()
                    flash("Message sent securely.", 'success')
                    return redirect(url_for('user.messages', recipient_id=selected_recipient_id))
        
        # Fetch conversations
        c.execute("""
            SELECT DISTINCT 
                CASE WHEN sender_id = ? THEN recipient_id ELSE sender_id END as recipient_id,
                CASE WHEN sender_id = ? THEN r.pusername ELSE s.pusername END as recipient_name,
                MAX(created_at) as last_message_time,
                (SELECT content FROM messages m2 
                 WHERE (m2.sender_id = m.sender_id AND m2.recipient_id = m.recipient_id) 
                    OR (m2.sender_id = m.recipient_id AND m2.recipient_id = m.sender_id)
                 ORDER BY m2.created_at DESC LIMIT 1) as last_message_encrypted
            FROM messages m
            LEFT JOIN users s ON s.id = m.sender_id
            LEFT JOIN users r ON r.id = m.recipient_id
            WHERE ? IN (m.sender_id, m.recipient_id)
            GROUP BY recipient_id, recipient_name
            ORDER BY last_message_time DESC
        """, (session['user_id'], session['user_id'], session['user_id']))
        conversations_raw = [dict(row) for row in c.fetchall()]
        
        # Decrypt last messages for display
        conversations = []
        for convo in conversations_raw:
            decrypted = gpg.decrypt(convo['last_message_encrypted'], passphrase=passphrase) if convo['last_message_encrypted'] else None
            convo['last_message'] = str(decrypted) if decrypted.ok else "[Decryption Failed]"
            conversations.append(convo)
        
        # Fetch messages for selected conversation
        messages = []
        selected_recipient_name = None
        if selected_recipient_id:
            c.execute("""
                SELECT m.*, s.pusername as sender_name, r.pusername as recipient_name
                FROM messages m
                LEFT JOIN users s ON s.id = m.sender_id
                LEFT JOIN users r ON r.id = m.recipient_id
                WHERE (m.sender_id = ? AND m.recipient_id = ?) OR (m.sender_id = ? AND m.recipient_id = ?)
                ORDER BY m.created_at ASC
            """, (session['user_id'], selected_recipient_id, selected_recipient_id, session['user_id']))
            messages_raw = [dict(row) for row in c.fetchall()]
            
            for msg in messages_raw:
                decrypted = gpg.decrypt(msg['content'], passphrase=passphrase)
                msg['content'] = str(decrypted) if decrypted.ok else "[Decryption Failed]"
                messages.append(msg)
            
            c.execute("SELECT pusername FROM users WHERE id = ?", (selected_recipient_id,))
            recipient = c.fetchone()
            selected_recipient_name = recipient['pusername'] if recipient else "Unknown"
    
    return render_template('user/messages.html', 
                          has_private_key=True,
                          conversations=conversations, 
                          messages=messages, 
                          selected_recipient_id=selected_recipient_id, 
                          selected_recipient_name=selected_recipient_name)

@user_bp.route('/wallet')
def wallet():
    if 'user_id' not in session:
        flash("Please log in to view your wallet.", 'error')
        return redirect(url_for('user.login'))
    # Placeholder: Fetch BTC balance (integrate bitcoin.py later)
    balance = 0.0  # Replace with real BTC balance
    return render_template('user/wallet.html', balance=balance)

@user_bp.route('/disputes')
def disputes():
    if 'user_id' not in session:
        flash("Please log in to view disputes.", 'error')
        return redirect(url_for('user.login'))
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT d.*, o.id as order_id, p.title, v.username as vendor_username
            FROM disputes d
            JOIN orders o ON d.order_id = o.id
            JOIN products p ON o.product_id = p.id
            JOIN vendors v ON o.vendor_id = v.id
            WHERE o.user_id = ?
        """, (session['user_id'],))
        disputes = [dict(row) for row in c.fetchall()]
    return render_template('user/disputes.html', disputes=disputes)

@user_bp.route('/favorites')
def favorites():
    if 'user_id' not in session:
        flash("Please log in to view favorites.", 'error')
        return redirect(url_for('user.login'))
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT p.*
            FROM favorites f
            JOIN products p ON f.product_id = p.id
            WHERE f.user_id = ?
        """, (session['user_id'],))
        favorites = [dict(row) for row in c.fetchall()]
    return render_template('user/favorites.html', favorites=favorites)

@user_bp.route('/profile')
def profile():
    if 'user_id' not in session:
        flash("Please log in to view your profile.", 'error')
        return redirect(url_for('user.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        # User details
        c.execute("""
            SELECT username, pusername, pgp_public_key, role, profile_visibility, created_at
            FROM users WHERE id = ?
        """, (session['user_id'],))
        user = dict(c.fetchone())
        
        # Activity stats
        c.execute("SELECT COUNT(*) as order_count FROM orders WHERE user_id = ?", (session['user_id'],))
        order_count = c.fetchone()['order_count']
        
        c.execute("SELECT COUNT(*) as dispute_count FROM disputes WHERE order_id IN (SELECT id FROM orders WHERE user_id = ?)", (session['user_id'],))
        dispute_count = c.fetchone()['dispute_count']
        
        c.execute("SELECT COUNT(*) as favorite_count FROM favorites WHERE user_id = ?", (session['user_id'],))
        favorite_count = c.fetchone()['favorite_count']
        
        user.update({
            'order_count': order_count,
            'dispute_count': dispute_count,
            'favorite_count': favorite_count
        })
    
    return render_template('user/profile.html', user=user)

@user_bp.route('/support', methods=['GET', 'POST'])
def support():
    if 'user_id' not in session:
        flash("Please log in to access support.", 'error')
        return redirect(url_for('user.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        
        # Fetch user's tickets
        c.execute("""
            SELECT t.*, 
                   (SELECT COUNT(*) FROM ticket_responses WHERE ticket_id = t.id) as response_count
            FROM tickets t 
            WHERE t.user_id = ? 
            ORDER BY t.updated_at DESC
        """, (session['user_id'],))
        tickets = [dict(row) for row in c.fetchall()]
        
        if request.method == 'POST':
            action = request.form.get('action')
            
            if action == 'create':
                subject = request.form.get('subject', '').strip()
                description = request.form.get('description', '').strip()
                category = request.form.get('category', 'General')
                priority = request.form.get('priority', 'Medium')
                
                if not subject or not description:
                    flash("Subject and description are required.", 'error')
                    return render_template('user/support.html', tickets=tickets, settings=get_settings())
                
                c.execute("""
                    INSERT INTO tickets (user_id, subject, description, category, priority)
                    VALUES (?, ?, ?, ?, ?)
                """, (session['user_id'], subject, description, category, priority))
                ticket_id = c.lastrowid
                
                # Notify admin
                c.execute("""
                    INSERT INTO messages (sender_id, recipient_type, subject, body)
                    VALUES (?, ?, ?, ?)
                """, (session['user_id'], 'vendor', f"New Support Ticket #{ticket_id}", f"User {session['user_id']} created a ticket: {subject}"))
                conn.commit()
                flash("Support ticket created successfully.", 'success')
                return redirect(url_for('user.support'))
            
            elif action == 'reply':
                ticket_id = request.form.get('ticket_id', type=int)
                body = request.form.get('body', '').strip()
                
                c.execute("SELECT * FROM tickets WHERE id = ? AND user_id = ?", (ticket_id, session['user_id']))
                ticket = c.fetchone()
                if not ticket or ticket['status'] in ['resolved', 'closed']:
                    flash("Ticket not found or closed.", 'error')
                    return redirect(url_for('user.support'))
                
                if not body:
                    flash("Response cannot be empty.", 'error')
                    return redirect(url_for('user.support'))
                
                # PGP Encryption if user has a key
                c.execute("SELECT pgp_key FROM users WHERE id = ?", (session['user_id'],))
                user_pgp_key = c.fetchone()['pgp_key']
                encrypted_body = None
                plaintext_body = body
                
                if user_pgp_key:
                    try:
                        public_key, _ = pgpy.PGPKey.from_blob(user_pgp_key)
                        message = pgpy.PGPMessage.new(body)
                        encrypted_body = str(public_key.encrypt(message))
                        plaintext_body = None
                    except Exception as e:
                        flash(f"Failed to encrypt response: {str(e)}", 'error')
                        return redirect(url_for('user.support'))
                
                c.execute("""
                    INSERT INTO ticket_responses (ticket_id, sender_id, body, encrypted_body)
                    VALUES (?, ?, ?, ?)
                """, (ticket_id, session['user_id'], plaintext_body, encrypted_body))
                c.execute("UPDATE tickets SET updated_at = CURRENT_TIMESTAMP, status = 'in_progress' WHERE id = ?", (ticket_id,))
                
                # Notify admin
                c.execute("""
                    INSERT INTO messages (sender_id, recipient_type, subject, body)
                    VALUES (?, ?, ?, ?)
                """, (session['user_id'], 'vendor', f"New Response on Ticket #{ticket_id}", f"User {session['user_id']} replied: {body[:50]}..."))
                conn.commit()
                flash("Response submitted successfully.", 'success')
                return redirect(url_for('user.support'))
        
        return render_template('user/support.html', tickets=tickets, settings=get_settings())

@user_bp.route('/support/ticket/<int:ticket_id>', methods=['GET'])

def view_ticket(ticket_id):
    if 'user_id' not in session:
        flash("Please log in to view tickets.", 'error')
        return redirect(url_for('user.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM tickets WHERE id = ? AND user_id = ?", (ticket_id, session['user_id']))
        ticket = c.fetchone()
        if not ticket:
            flash("Ticket not found or you don’t have access.", 'error')
            return redirect(url_for('user.support'))
        
        c.execute("SELECT * FROM ticket_responses WHERE ticket_id = ? ORDER BY created_at", (ticket_id,))
        responses = [dict(row) for row in c.fetchall()]
        
        return render_template('user/support.html', ticket=dict(ticket), responses=responses, settings=get_settings())
    
@user_bp.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user_id' not in session:
        flash("Please log in to update settings.", 'error')
        return redirect(url_for('user.login'))
    
    if request.method == 'POST':
        validate_csrf_token()
        pin = request.form.get('pin', '').strip()
        pgp_public_key = request.form.get('pgp_public_key', '').strip()
        login_phrase = request.form.get('login_phrase', '').strip()
        session_timeout = request.form.get('session_timeout', '30')
        pusername = request.form.get('pusername', '').strip()
        profile_visibility = request.form.get('profile_visibility', 'public')
        btc_address = request.form.get('btc_address', '').strip()
        notify_messages = 'notify_messages' in request.form
        notify_orders = 'notify_orders' in request.form
        
        if len(pin) != 6 or not pin.isdigit():
            flash("PIN must be 6 digits.", 'error')
        else:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("""
                    UPDATE users SET pin = ?, pgp_public_key = ?, login_phrase = ?, 
                    session_timeout = ?, pusername = ?, profile_visibility = ?, 
                    btc_address = ?, notify_messages = ?, notify_orders = ?
                    WHERE id = ?
                """, (pin, pgp_public_key, login_phrase, session_timeout, pusername, 
                      profile_visibility, btc_address, notify_messages, notify_orders, 
                      session['user_id']))
                conn.commit()
            flash("Settings updated successfully.", 'success')
        return redirect(url_for('user.settings'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT pin, pgp_public_key, login_phrase, session_timeout, pusername, 
            profile_visibility, btc_address, notify_messages, notify_orders 
            FROM users WHERE id = ?
        """, (session['user_id'],))
        user = dict(c.fetchone() or {
            'pin': '', 'pgp_public_key': '', 'login_phrase': '', 'session_timeout': '30',
            'pusername': '', 'profile_visibility': 'public', 'btc_address': '', 
            'notify_messages': True, 'notify_orders': True
        })
    return render_template('user/settings.html', user=user)
    if 'user_id' not in session:
        flash("Please log in to update settings.", 'error')
        return redirect(url_for('user.login'))
    if request.method == 'POST':
        validate_csrf_token()
        new_pin = request.form.get('pin', '').strip()
        new_pgp = request.form.get('pgp_public_key', '').strip()
        if len(new_pin) != 6 or not new_pin.isdigit():
            flash("PIN must be 6 digits.", 'error')
        else:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("UPDATE users SET pin = ?, pgp_public_key = ? WHERE id = ?",
                          (new_pin, new_pgp, session['user_id']))
                conn.commit()
            flash("Settings updated successfully.", 'success')
        return redirect(url_for('user.settings'))
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT pin, pgp_public_key FROM users WHERE id = ?", (session['user_id'],))
        user = dict(c.fetchone())
    return render_template('user/settings.html', user=user)

