from flask import Blueprint, render_template, request, session, redirect, url_for, flash, g, jsonify
from utils.database import get_db_connection, get_settings, get_user_profile_data, get_bond_amounts, get_pending_payment, get_user_notifications, mark_notification_read
from utils.security import regenerate_session, encrypt_message, init_gpg_for_tor, is_tor_request
from utils.crypto import get_exchange_rates
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from utils.support import secure_support
from flask_wtf import FlaskForm
from flask_login import login_required, current_user, login_user
from wtforms import StringField, PasswordField, SelectField, TextAreaField, FileField, BooleanField, IntegerField
from wtforms.validators import DataRequired, Length, EqualTo, Regexp, Optional
import bcrypt
import sqlite3
import os
import uuid
import logging
import pgpy
import secrets
import gnupg
from routes import require_role
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash
from dataclasses import dataclass
from datetime import datetime, timedelta
import base64
import time
from utils.ddos_protection import recaptcha
from utils.bitcoin import generate_btc_address
from utils.monero import generate_monero_address
import qrcode
import io
from utils.captcha import serve_captcha_image, validate_captcha, is_captcha_required, mark_captcha_verified, reset_captcha_verification, generate_captcha_code, set_captcha_code
from functools import wraps
from flask_wtf.csrf import generate_csrf
#from app import User  # Import User from app.py

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
user_bp = Blueprint('user', __name__)
limiter = Limiter(get_remote_address, app=None)  # Attach in app.py

# Use a static key for development - in production, this should be stored securely
FERNET_KEY = b'xESD56d8W_2sAxJvPJ3GYk3DyJPXV_RGPmAgNCxy0GU='
cipher = Fernet(FERNET_KEY)

WORD_LIST = ["apple"]

UPLOAD_FOLDER_PRODUCTS = 'static/uploads/products'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER = 'static/uploads/avatar'

# Vendor Subscription
BOND_AMOUNT_BTC = 0.0018
BOND_AMOUNT_XMR = 0.49

if not os.path.exists(UPLOAD_FOLDER_PRODUCTS):
    os.makedirs(UPLOAD_FOLDER_PRODUCTS)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_authenticated():
    """Check if a user is logged in."""
    return 'user_id' in session and session.get('role') in ['user', 'vendor']

def validate_pgp_key(pgp_key):
    """Validate that the PGP key is in a valid format."""
    if not pgp_key or pgp_key.strip() == '':
        return False
    return pgp_key.strip().startswith('-----BEGIN PGP PUBLIC KEY BLOCK-----') and '-----END PGP PUBLIC KEY BLOCK-----' in pgp_key

def is_two_factor_enabled(val):
	"""Return True if the stored 2FA flag indicates 2FA is enabled."""
	try:
		flag = str(val).strip().lower()
	except Exception:
		flag = ''
	return flag in ('1', 'true', 'enabled', 'yes')

@dataclass
class Order:
    id: int
    vendor_id: int
    vendor_username: str
    created_at: datetime

@dataclass
class Feedback:
    id: int
    vendor_id: int
    vendor_username: str
    rating: int
    comment: str
    created_at: datetime
    avg_rating: float

def get_user(user_id):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT id, username, pgp_public_key, is_vendor, two_factor_secret, pin, mnemonic_hash,
                   avatar, login_phrase, session_timeout, profile_visibility, notify_messages, notify_orders
            FROM users WHERE id = ?
        """, (user_id,))
        row = c.fetchone()
        if row:
            return {
                'id': row[0], 'username': row[1], 'pgp_public_key': row[2] or '', 'is_vendor': bool(row[3]),
                'two_factor_secret': row[4] or '', 'pin': row[5] or '', 'mnemonic_hash': row[6] or '',
                'avatar': row[7] or '', 'login_phrase': row[8] or '', 'session_timeout': row[9] or '30',
                'profile_visibility': row[10] or 'public', 'notify_messages': bool(row[11]), 'notify_orders': bool(row[12])
            }
    return None

def get_user_orders(user_id):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT o.id, o.vendor_id, u.username, o.created_at
            FROM orders o
            JOIN users u ON o.vendor_id = u.id
            WHERE o.user_id = ? AND o.status = 'completed'
            AND NOT EXISTS (
                SELECT 1 FROM feedback f WHERE f.order_id = o.id
            )
        """, (user_id,))
        return [Order(row[0], row[1], row[2], row[3]) for row in c.fetchall()]

def get_recent_feedback():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT f.id, f.vendor_id, u.username, f.rating, f.comment, f.created_at,
                   (SELECT AVG(rating) FROM feedback WHERE vendor_id = f.vendor_id AND status = 'active') as avg_rating
            FROM feedback f
            JOIN users u ON f.vendor_id = u.id
            WHERE f.status = 'active'
            ORDER BY f.created_at DESC
            LIMIT 10
        """)
        return [Feedback(row[0], row[1], row[2], row[3], row[4], row[5], row[6] or 0.0) for row in c.fetchall()]

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(max=255)])
    password = PasswordField('Password', validators=[DataRequired()])

class TwoFactorForm(FlaskForm):
    pin = PasswordField('PIN', validators=[DataRequired(), Length(min=6, max=6)])
    decrypted_message = StringField('Decrypted Message', validators=[DataRequired()])

class EditProfileForm(FlaskForm):
    da_jabber = StringField('Jabber', validators=[Optional(), Length(max=255)])
    da_description = TextAreaField('Description', validators=[Optional(), Length(max=2000)])
    da_passphrase = StringField('Login Phrase', validators=[Optional(), Length(max=100)])
    da_currencyid = SelectField('Currency', choices=[
        ('USD', 'USD'), ('AUD', 'AUD'), ('NZD', 'NZD'), ('CAD', 'CAD'), ('CHF', 'CHF'),
        ('CNY', 'CNY'), ('DKK', 'DKK'), ('EUR', 'EUR'), ('GBP', 'GBP'), ('HKD', 'HKD'),
        ('INR', 'INR'), ('JPY', 'JPY'), ('PLN', 'PLN'), ('RUB', 'RUB'), ('SEK', 'SEK'),
        ('NOK', 'NOK'), ('RON', 'RON'), ('BRL', 'BRL'), ('TRY', 'TRY'), ('HUF', 'HUF'),
        ('CZK', 'CZK'), ('MXN', 'MXN'), ('IDR', 'IDR')
    ], validators=[DataRequired()])
    da_stealth = SelectField('Stealth Mode', choices=[('0', 'No'), ('1', 'Yes')], validators=[DataRequired()])
    da_image = FileField('Avatar', validators=[Optional()])
    da_multisig = TextAreaField('Multisig Public Key', validators=[Optional(), Length(max=2000)])
    da_refund = TextAreaField('Refund Address', validators=[Optional(), Length(max=2000)])
    da_pincb = PasswordField('Current PIN (Security)', validators=[Optional(), Length(min=6, max=6)])
    da_pgp = TextAreaField('PGP Public Key', validators=[Optional(), Length(max=5000)])
    da_pgp_decrypted = StringField('PGP Decrypted Message', validators=[Optional(), Length(max=5000)])
    da_factor = SelectField('2FA', choices=[('0', 'Disabled'), ('1', 'Enabled')], validators=[DataRequired()])
    da_canbuy = SelectField('Allow Purchases', choices=[('1', 'Allow'), ('0', 'Do not allow')], validators=[DataRequired()])
    da_pinbuy = SelectField('Require PIN on Purchases', choices=[('0', 'Not require'), ('1', 'Require')], validators=[DataRequired()])
    da_phis = SelectField('Phishing Protection', choices=[('0', 'No'), ('1', 'Yes')], validators=[DataRequired()])
    da_passac = PasswordField('Current Password', validators=[Optional()])
    da_passwd = PasswordField('New Password', validators=[Optional(), Length(min=8, max=128), Regexp(r'^(?=.*[A-Za-z])(?=.*\d).+$', message='Password must contain at least one letter and one number')])
    da_passcf = PasswordField('Confirm Password', validators=[Optional(), EqualTo('da_passwd', message='Passwords must match')])
    da_pinac = PasswordField('Current PIN', validators=[Optional(), Length(min=6, max=6)])
    da_pinwd = PasswordField('New PIN', validators=[Optional(), Length(min=6, max=6), Regexp(r'^\d{6}$', message='PIN must be 6 digits')])
    da_pincf = PasswordField('Confirm PIN', validators=[Optional(), EqualTo('da_pinwd', message='PINs must match')])
    da_menu_follow = SelectField('Menu Follow on Scroll', choices=[('0', 'No'), ('1', 'Yes')], validators=[DataRequired()])
    da_feedback = SelectField('Feedback System', choices=[('0', 'Stars'), ('1', 'Numbers')], validators=[DataRequired()])
    sd_tocountryid = SelectField('Default Ship-to', choices=[
        ('-1', 'Any'), ('331', 'Australia'), ('227', 'United States'), ('209', 'Canada'),
        ('285', 'United Kingdom'), ('257', 'Germany'), ('255', 'France'), ('301', 'Japan'),
        ('230', 'Brazil'), ('296', 'India'), ('388', 'South Africa')
    ], validators=[DataRequired()])
    sd_countryid = SelectField('Default Origin', choices=[
        ('-1', 'Any'), ('331', 'Australia'), ('227', 'United States'), ('209', 'Canada'),
        ('285', 'United Kingdom'), ('257', 'Germany'), ('255', 'France'), ('301', 'Japan'),
        ('230', 'Brazil'), ('296', 'India'), ('388', 'South Africa')
    ], validators=[DataRequired()])
    sd_discardww = BooleanField('Discard Worldwide Shipping', validators=[Optional()])

def filter_user_data(user_dict):
    """Filter user data to match app.User class parameters (40 parameters)."""
    required_keys = {
        'id', 'username', 'pusername', 'pin', 'password', 'role', 'active', 'registered_at',
        'btc_address', 'avatar', 'login_phrase', 'status', 'session_timeout', 'profile_visibility',
        'is_vendor', 'notify_messages', 'notify_orders', 'pgp_public_key', 'pgp_private_key',
        'vendor_status', 'two_factor_secret', 'mnemonic_hash', 'created_at', 'last_login',
        'jabber', 'description', 'currencyid', 'stealth', 'multisig', 'refund', 'canbuy',
        'pinbuy', 'phis', 'menu_follow', 'feedback', 'tocountryid', 'countryid', 'discardww'
    }  # 40 keys
    defaults = {
        'active': 1, 'registered_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'btc_address': '', 'avatar': '', 'login_phrase': '', 'status': 'active',
        'session_timeout': '30', 'profile_visibility': 'public', 'is_vendor': 0,
        'notify_messages': 1, 'notify_orders': 1, 'pgp_public_key': '', 'pgp_private_key': '',
        'vendor_status': '', 'two_factor_secret': '', 'mnemonic_hash': '',
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'last_login': None,
        'jabber': '', 'description': '', 'currencyid': 'USD', 'stealth': 0, 'multisig': '',
        'refund': '', 'canbuy': 1, 'pinbuy': 0, 'phis': 0, 'menu_follow': 0, 'feedback': 0,
        'tocountryid': -1, 'countryid': -1, 'discardww': 0
    }
    filtered = {k: user_dict.get(k, defaults.get(k, '')) for k in required_keys}
    logger.debug(f"filter_user_data keys: {filtered.keys()}, count: {len(filtered)}")
    return filtered

def is_vendor():
    return session.get('role') == 'vendor'
# Context processor to inject profile_data
@user_bp.context_processor
def inject_profile_data():
    """Inject profile_data into all templates for authenticated users."""
    if current_user.is_authenticated and not hasattr(g, 'profile_data'):
        profile_data, error = get_user_profile_data(current_user.id)
        g.profile_data = profile_data if profile_data else {}
        if error:
            logger.error(f"Failed to fetch profile_data for user {current_user.id}: {error}")
    return {'profile_data': g.get('profile_data', {})}

@user_bp.context_processor
def inject_csrf_token():
    return {'csrf_token': generate_csrf}

def require_captcha_challenge(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if is_captcha_required():
            return redirect(url_for('user.captcha_challenge', next=request.path))
        return f(*args, **kwargs)
    return decorated_function

@user_bp.route('/captcha_challenge', methods=['GET', 'POST'])
def captcha_challenge():
    logger.warning(f"CAPTCHA challenge route called - Method: {request.method}")
    if request.method == 'POST':
        captcha_input = request.form.get('captcha', '').strip()
        logger.warning(f"CAPTCHA challenge POST - captcha_input: '{captcha_input}'")
        if validate_captcha(captcha_input):
            mark_captcha_verified()
            next_url = request.args.get('next') or request.form.get('next') or url_for('user.login')
            logger.warning(f"CAPTCHA challenge successful - redirecting to: {next_url}")
            return redirect(next_url)
        else:
            logger.warning("CAPTCHA challenge failed")
            flash('CAPTCHA incorrect. Please try again.', 'error')
    next_url = request.args.get('next') or request.form.get('next') or url_for('user.login')
    logger.warning(f"CAPTCHA challenge GET - next_url: {next_url}")
    return render_template('captcha_challenge.html', next=next_url)

# Login route
@user_bp.route('/login', methods=['GET', 'POST'])
@require_captcha_challenge
def login():
    from app import User  # Import here to avoid circular import
    logger.debug("Entering /login")
    logger.warning(f"Login route called - Method: {request.method}")
    
    # Debug CSRF token
    from flask_wtf.csrf import generate_csrf
    try:
        csrf_token = generate_csrf()
        logger.debug(f"CSRF token generated: {csrf_token[:20]}...")
    except Exception as e:
        logger.error(f"Error generating CSRF token: {e}")
    
    next_url = request.args.get('next') or request.form.get('next')
    if request.method == 'POST':
        # Check if request is coming from Tor
        is_tor_request = request.headers.get('X-Forwarded-For', '').endswith('.onion') or \
                        request.headers.get('Host', '').endswith('.onion') or \
                        '.onion' in request.headers.get('Host', '')
        
        # Validate CSRF token (with Tor-specific handling)
        from flask_wtf.csrf import validate_csrf
        from config import Config
        config = Config()
        
        try:
            csrf_token = request.form.get('csrf_token')
            
            # For Tor requests, be more lenient with CSRF validation
            if is_tor_request:
                if config.TOR_CSRF_DISABLED:
                    logger.info("CSRF disabled for Tor requests")
                    pass
                elif config.TOR_CSRF_LENIENT:
                    if not csrf_token:
                        logger.warning("No CSRF token in Tor request, but allowing login attempt")
                        # For Tor requests, we'll allow the login without CSRF token
                        # This is a security trade-off for Tor compatibility
                        pass
                    else:
                        try:
                            validate_csrf(csrf_token)
                        except Exception as e:
                            logger.warning(f"CSRF validation failed for Tor request: {e}")
                            # For Tor requests, we'll allow the login even if CSRF fails
                            pass
                else:
                    # Strict CSRF validation even for Tor
                    if not csrf_token:
                        logger.error("No CSRF token found in Tor request")
                        flash("CSRF token missing. Please try refreshing the page.", 'error')
                        return render_template('login.html', form_data={'next': next_url})
                    validate_csrf(csrf_token)
            else:
                # For non-Tor requests, strict CSRF validation
                if not csrf_token:
                    logger.error("No CSRF token found in form")
                    flash("CSRF token missing. Please try refreshing the page.", 'error')
                    return render_template('login.html', form_data={'next': next_url})
                validate_csrf(csrf_token)
                
        except Exception as e:
            logger.error(f"CSRF validation failed: {e}")
            if is_tor_request:
                logger.warning("Allowing Tor request despite CSRF failure")
                # For Tor requests, we'll allow the login even if CSRF fails
                pass
            else:
                flash("CSRF token validation failed. Please try refreshing the page.", 'error')
                return render_template('login.html', form_data={'next': next_url})
        
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').encode('utf-8')
        captcha_input = request.form.get('captcha', '').strip()
        logger.warning(f"Login POST - captcha_input: '{captcha_input}'")
        # Validate CAPTCHA
        if not validate_captcha(captcha_input):
            logger.warning("Login CAPTCHA validation failed")
            flash("CAPTCHA incorrect. Please try again.", 'error')
            return render_template('login.html', form_data={'username': username, 'next': next_url})
        
        if not username or not password:
            flash("Username and password are required.", 'error')
            return render_template('login.html', form_data={'username': username, 'next': next_url})
        
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = c.fetchone()
        
        if user and bcrypt.checkpw(password, user['password'].encode('utf-8')):
            session['temp_user_id'] = user['id']
            session['temp_username'] = user['username']
            session['temp_role'] = user['role']
            if is_two_factor_enabled(user['two_factor_secret']):
                if not user['pgp_public_key']:
                    flash("2FA enabled but no PGP key set.", 'error')
                    return redirect(url_for('user.login'))
                message = f"Login attempt for {username} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                try:
                    public_key, _ = pgpy.PGPKey.from_blob(user['pgp_public_key'])
                    encrypted_message = str(public_key.encrypt(pgpy.PGPMessage.new(message)))
                    session['2fa_message'] = message
                    session['encrypted_message'] = encrypted_message
                    return redirect(url_for('user.two_factor_auth'))
                except Exception as e:
                    logger.error(f"PGP encryption failed: {e}")
                    flash("2FA setup error.", 'error')
                    return redirect(url_for('user.login'))
            user_dict = dict(user)  # Convert sqlite3.Row to dict
            user_obj = User(**filter_user_data(user_dict))
            login_user(user_obj)
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash("Logged in successfully.", 'success')
            if next_url:
                return redirect(next_url)
            return redirect(url_for('user.dashboard'))
        flash("Invalid username or password.", 'error')
        return render_template('login.html', form_data={'username': username, 'next': next_url})
    return render_template('login.html', form_data={'next': next_url})

# Two-factor auth route
@user_bp.route('/two_factor_auth', methods=['GET', 'POST'])
def two_factor_auth():
    from app import User  
    if 'temp_user_id' not in session:
        flash('Please log in first.', 'error')
        return redirect(url_for('user.login'))

    form = TwoFactorForm()
    encrypted_message = session.get('encrypted_message', '')
    if form.validate_on_submit():
        pin = form.pin.data.encode('utf-8')
        decrypted_message = form.decrypted_message.data.strip()
        
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM users WHERE id = ?', (session['temp_user_id'],))
            user_data = c.fetchone()

        if user_data and bcrypt.checkpw(pin, user_data['pin'].encode('utf-8')):
            if decrypted_message == session.get('2fa_message'):
                user_dict = dict(user_data)
                user = User(**filter_user_data(user_dict))
                login_user(user)
                session['user_id'] = user_data['id']
                session['username'] = user_data['username']
                session['role'] = user_data['role']
                session.pop('temp_user_id', None)
                session.pop('temp_username', None)
                session.pop('temp_role', None)
                session.pop('2fa_message', None)
                session.pop('encrypted_message', None)
                flash('Logged in successfully.', 'success')
                return redirect(url_for('user.dashboard'))
            else:
                flash('Invalid decrypted message.', 'error')
        else:
            flash('Invalid PIN.', 'error')
    return render_template('two_factor_auth.html', form=form, encrypted_message=encrypted_message)

# Register route
@user_bp.route('/register', methods=['GET', 'POST'])
@require_captcha_challenge
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        pusername = request.form.get('pusername', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        pin = request.form.get('pin', '').strip()
        captcha_input = request.form.get('captcha', '').strip()
        # Validate CAPTCHA
        if not validate_captcha(captcha_input):
            flash("CAPTCHA incorrect. Please try again.", 'error')
            return render_template('register.html', form_data=request.form.to_dict())
        
        if not all([username, pusername, password, confirm_password, pin]):
            flash("All fields are required.", 'error')
            return render_template('register.html', form_data=request.form.to_dict())

        # Username validation
        if len(username) < 3 or len(username) > 50:
            flash("Public username must be 3-50 characters.", 'error')
            return render_template('register.html', form_data=request.form.to_dict())
        
        if len(pusername) < 3 or len(pusername) > 50:
            flash("Private username must be 3-50 characters.", 'error')
            return render_template('register.html', form_data=request.form.to_dict())

        if password != confirm_password:
            flash("Passwords do not match.", 'error')
            return render_template('register.html', form_data=request.form.to_dict())

        if len(pin) != 6 or not pin.isdigit():
            flash("PIN must be exactly 6 digits.", 'error')
            return render_template('register.html', form_data=request.form.to_dict())

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        hashed_pin = bcrypt.hashpw(pin.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        with get_db_connection() as conn:
            c = conn.cursor()
            try:
                c.execute("INSERT INTO users (username, pusername, password, pin, role) VALUES (?, ?, ?, ?, ?)",
                          (username, pusername, hashed_password, hashed_pin, 'user'))
                user_id = c.lastrowid
                conn.commit()
                session['user_id'] = user_id
                session['username'] = username
                session['role'] = 'user'
                flash("Registration completed! Set up 2FA and PGP in settings.", 'success')
                return redirect(url_for('user.dashboard'))
            except sqlite3.IntegrityError:
                flash("Username or public username already exists.", 'error')
                return render_template('register.html', form_data=request.form.to_dict())
    return render_template('register.html', form_data={})

# Settings route
@user_bp.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user_id' not in session:
        flash("Please log in to update settings.", 'error')
        return redirect(url_for('user.login'))
    
    if request.method == 'POST':
        pin = request.form.get('pin', '').strip()
        pgp_public_key = request.form.get('pgp_public_key', '').strip()
        login_phrase = request.form.get('login_phrase', '').strip()
        session_timeout = request.form.get('session_timeout', '30')
        pusername = request.form.get('pusername', '').strip()
        profile_visibility = request.form.get('profile_visibility', 'public')
        btc_address = request.form.get('btc_address', '').strip()
        notify_messages = 'notify_messages' in request.form
        notify_orders = 'notify_orders' in request.form
        two_factor_secret = '1' if 'two_factor_secret' in request.form else '0'

        if len(pin) != 6 or not pin.isdigit():
            flash("PIN must be 6 digits.", 'error')
            return redirect(url_for('user.settings'))

        hashed_pin = bcrypt.hashpw(pin.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                UPDATE users SET pin = ?, pgp_public_key = ?, login_phrase = ?, 
                session_timeout = ?, pusername = ?, profile_visibility = ?, 
                btc_address = ?, notify_messages = ?, notify_orders = ?, two_factor_secret = ?
                WHERE id = ?
            """, (hashed_pin, pgp_public_key, login_phrase, session_timeout, pusername,
                  profile_visibility, btc_address, notify_messages, notify_orders,
                  two_factor_secret, session['user_id']))
            conn.commit()
        flash("Settings updated successfully.", 'success')
        return redirect(url_for('user.settings'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT pin, pgp_public_key, login_phrase, session_timeout, pusername, 
            profile_visibility, btc_address, notify_messages, notify_orders, two_factor_secret
            FROM users WHERE id = ?
        """, (session['user_id'],))
        user = c.fetchone()
        user_data = dict(user) if user else {
            'pin': '', 'pgp_public_key': '', 'login_phrase': '', 'session_timeout': '30',
            'pusername': '', 'profile_visibility': 'public', 'btc_address': '',
            'notify_messages': True, 'notify_orders': True, 'two_factor_secret': '0'
        }
    return render_template('user/settings.html', user=user_data)

# Remaining routes unchanged (logout, add_pgp_key, feedback, etc.)
# Include them as provided in your user.py
@user_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    logger.debug(f"Logging out user: user_id={session.get('user_id')}")
    session.clear()
    regenerate_session()
    flash("You have been logged out successfully.", 'success')
    logger.debug("Session cleared and regenerated")
    reset_captcha_verification()
    return redirect(url_for('user.login'))

@user_bp.route('/add_pgp_key', methods=['GET', 'POST'])
def add_pgp_key():
    if 'user_id' not in session:
        logger.warning("Access to add_pgp_key without user_id in session")
        flash("Please log in to add a PGP key.", 'error')
        return redirect(url_for('user.login'))

    if request.method == 'POST':
        pgp_public_key = request.form.get('pgp_public_key', '').strip()
        if not pgp_public_key:
            flash("PGP public key is required.", 'error')
            return render_template('user/add_pgp_key.html', form_data=request.form.to_dict(), settings=get_settings())

        if not validate_pgp_key(pgp_public_key):
            flash("Invalid PGP public key format.", 'error')
            return render_template('user/add_pgp_key.html', form_data=request.form.to_dict(), settings=get_settings())

        try:
            key, _ = pgpy.PGPKey.from_blob(pgp_public_key)
            logger.debug(f"PGP Key validated successfully: {pgp_public_key}")
        except Exception as e:
            logger.error(f"PGP Key validation failed: {str(e)}")
            flash(f"Invalid PGP public key: {str(e)}", 'error')
            return render_template('user/add_pgp_key.html', form_data=request.form.to_dict(), settings=get_settings())

        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("UPDATE users SET pgp_public_key = ? WHERE id = ?", (pgp_public_key, session['user_id']))
            conn.commit()

        flash("PGP key added successfully.", 'success')
        logger.debug("PGP key added for user_id: {}".format(session['user_id']))
        return redirect(url_for('user.settings'))

    return render_template('user/add_pgp_key.html', form_data={}, settings=get_settings())

@user_bp.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if 'user_id' not in session:
        flash('Please log in to submit feedback.', 'error')
        return redirect(url_for('user.login'))
    profile_data, error = get_user_profile_data(session['user_id'])
    rates = get_exchange_rates() or {"bitcoin": {}, "monero": {}}
    user = get_user(session['user_id'])
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('user.login'))

    is_vendor = user.get('is_vendor', False)
    db = get_db_connection()
    c = db.cursor()

    if is_vendor:
        # Vendor: show stats and all feedback about them
        vendor_id = session['user_id']
        # Feedback stats
        c.execute("""
            SELECT COUNT(*) FROM feedback WHERE vendor_id = ? AND status = 'active'
        """, (vendor_id,))
        total_feedback = c.fetchone()[0]
        c.execute("""
            SELECT COUNT(*) FROM feedback WHERE vendor_id = ? AND rating >= 4 AND status = 'active'
        """, (vendor_id,))
        positive_feedback = c.fetchone()[0]
        c.execute("""
            SELECT COUNT(*) FROM feedback WHERE vendor_id = ? AND rating = 3 AND status = 'active'
        """, (vendor_id,))
        neutral_feedback = c.fetchone()[0]
        c.execute("""
            SELECT COUNT(*) FROM feedback WHERE vendor_id = ? AND rating <= 2 AND status = 'active'
        """, (vendor_id,))
        negative_feedback = c.fetchone()[0]
        c.execute("""
            SELECT AVG(rating) FROM feedback WHERE vendor_id = ? AND status = 'active'
        """, (vendor_id,))
        avg_rating = c.fetchone()[0] or 0.0
        # All feedback for this vendor
        c.execute("""
            SELECT f.id, f.rating, f.comment, f.created_at, u.username as buyer_username, p.title as product_title
            FROM feedback f
            JOIN users u ON f.user_id = u.id
            LEFT JOIN products p ON f.product_id = p.id
            WHERE f.vendor_id = ? AND f.status = 'active'
            ORDER BY f.created_at DESC
        """, (vendor_id,))
        vendor_feedbacks = c.fetchall()
        db.close()
        return render_template(
            'user/feedback.html',
            is_vendor=True,
            stats={
                'total': total_feedback,
                'positive': positive_feedback,
                'neutral': neutral_feedback,
                'negative': negative_feedback,
                'avg_rating': round(avg_rating, 2)
            },
            feedback_list=vendor_feedbacks,
            profile_data=profile_data,
            rates=rates
        )
    else:
        # Buyer: show eligible orders and feedback history
        orders = get_user_orders(session['user_id'])
        # Feedbacks left by this user
        c.execute("""
            SELECT f.id, f.rating, f.comment, f.created_at, u.username as vendor_username, p.title as product_title
            FROM feedback f
            JOIN users u ON f.vendor_id = u.id
            LEFT JOIN products p ON f.product_id = p.id
            WHERE f.user_id = ?
            ORDER BY f.created_at DESC
        """, (session['user_id'],))
        feedback_history = c.fetchall()
        db.close()
        # Handle feedback submission
        if request.method == 'POST':
            order_id = request.form.get('order_id')
            rating = request.form.get('rating')
            comment = request.form.get('comment', '').strip()
            if not order_id or not any(o.id == int(order_id) for o in orders):
                flash('Invalid or ineligible order selected.', 'error')
                return redirect(url_for('user.feedback'))
            try:
                rating = int(rating)
                if rating < 1 or rating > 5:
                    raise ValueError
            except (ValueError, TypeError):
                flash('Rating must be between 1 and 5.', 'error')
                return redirect(url_for('user.feedback'))
            if not comment or len(comment) > 500:
                flash('Comment is required and must be 500 characters or less.', 'error')
                return redirect(url_for('user.feedback'))
            if re.search(r'\bhttp[s]?://|www\\.|\\.com\b', comment, re.I):
                flash('Comments cannot contain URLs or promotional content.', 'error')
                return redirect(url_for('user.feedback'))
            db = get_db_connection()
            c = db.cursor()
            c.execute("SELECT vendor_id, product_id FROM orders WHERE id = ?", (order_id,))
            row = c.fetchone()
            if not row:
                db.close()
                flash('Order not found.', 'error')
                return redirect(url_for('user.feedback'))
            vendor_id, product_id = row
            c.execute("""
                INSERT INTO feedback (order_id, user_id, vendor_id, product_id, rating, comment)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (order_id, session['user_id'], vendor_id, product_id, rating, comment))
            db.commit()
            db.close()
            flash('Feedback submitted successfully.', 'success')
            return redirect(url_for('user.feedback'))
        return render_template(
            'user/feedback.html',
            is_vendor=False,
            orders=orders,
            feedback_list=feedback_history,
            profile_data=profile_data,
            rates=rates
        )

@user_bp.route('/dashboard')
def dashboard():
    """Render user dashboard with profile, orders, reports, rates, and buyer stats. Show different content for vendors vs buyers."""
    if 'user_id' not in session:
        flash("Please log in to access your dashboard.", 'error')
        return redirect(url_for('user.login'))
    
    user_id = session['user_id']
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT is_vendor, pusername FROM users WHERE id = ?", (user_id,))
        user_row = c.fetchone()
        if not user_row:
            logger.error(f"No user found for user_id: {user_id}")
            flash("User not found. Please log in again.", 'error')
            session.clear()
            return redirect(url_for('user.login'))
        is_vendor = bool(user_row['is_vendor'])
        pusername = user_row['pusername']
    
    if is_vendor:
        # Fetch vendor stats, recent orders, reviews, messages, and published products
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT u.pusername, u.level, u.avatar, vs.logo, vs.shipping_location 
                FROM users u
                LEFT JOIN vendor_settings vs ON u.id = vs.user_id
                WHERE u.id = ?
            """, (user_id,))
            vendor_data = c.fetchone()
            if not vendor_data:
                flash("Vendor profile not found. Please contact support.", "error")
                return redirect(url_for('user.dashboard'))
            vendor_name = vendor_data['pusername']
            level = vendor_data['level']
            avatar = vendor_data['avatar'] or None
            logo = vendor_data['logo'] or None
            shipping_location = vendor_data['shipping_location'] or "Not specified"
            
            # Fetch vendor's published products
            c.execute("""
                SELECT p.id, p.title, p.price_usd, p.stock, p.status, p.created_at, p.featured_image,
                       c.name as category_name
                FROM products p
                LEFT JOIN categories c ON p.category_id = c.id
                WHERE p.vendor_id = ?
                ORDER BY p.created_at DESC
            """, (user_id,))
            published_products = [dict(row) for row in c.fetchall()]
            
            # Market Stats
            c.execute("SELECT COUNT(*) FROM orders WHERE vendor_id = ?", (user_id,))
            total_orders = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM orders WHERE vendor_id = ? AND status = 'shipped'", (user_id,))
            total_shipped = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM orders WHERE vendor_id = ? AND status = 'delivered'", (user_id,))
            total_sales = c.fetchone()[0]
            c.execute("SELECT SUM(amount_usd) FROM orders WHERE vendor_id = ? AND status = 'delivered'", (user_id,))
            revenue = c.fetchone()[0] or 0.0
            # Feedbacks
            c.execute("""
                SELECT COUNT(*) 
                FROM reviews r
                JOIN products p ON r.product_id = p.id
                WHERE p.vendor_id = ? AND r.rating >= 4
            """, (user_id,))
            positive_feedbacks = c.fetchone()[0]
            c.execute("""
                SELECT COUNT(*) 
                FROM reviews r
                JOIN products p ON r.product_id = p.id
                WHERE p.vendor_id = ? AND r.rating <= 2
            """, (user_id,))
            negative_feedbacks = c.fetchone()[0]
            # Recent Orders
            c.execute("""
                SELECT o.id, o.amount_usd, o.status, o.created_at, p.title, u.pusername as buyer_username
                FROM orders o
                JOIN products p ON o.product_id = p.id
                JOIN users u ON o.user_id = u.id
                WHERE o.vendor_id = ?
                ORDER BY o.created_at DESC LIMIT 5
            """, (user_id,))
            recent_orders = [dict(row) for row in c.fetchall()]
            # Recent Reviews
            c.execute("""
                SELECT r.id, r.rating, r.comment, r.created_at, u.pusername as reviewer, p.title
                FROM reviews r
                JOIN products p ON r.product_id = p.id
                JOIN users u ON r.user_id = u.id
                WHERE p.vendor_id = ?
                ORDER BY r.created_at DESC LIMIT 5
            """, (user_id,))
            recent_reviews = [dict(row) for row in c.fetchall()]
            # Recent Messages
            c.execute("""
                SELECT m.id, m.content, m.created_at, u.pusername as sender
                FROM messages m
                JOIN users u ON m.sender_id = u.id
                WHERE m.recipient_id = ? AND m.trashed = 0
                ORDER BY m.created_at DESC LIMIT 5
            """, (user_id,))
            recent_messages = [dict(row) for row in c.fetchall()]
            # Analytics
            # Order completion rate
            completion_rate = 0.0
            if total_orders > 0:
                c.execute("SELECT COUNT(*) FROM orders WHERE vendor_id = ? AND status = 'delivered'", (user_id,))
                completed = c.fetchone()[0]
                completion_rate = round((completed / total_orders) * 100, 2)
            # Average rating
            c.execute("""
                SELECT AVG(r.rating) as avg_rating
                FROM reviews r
                JOIN products p ON r.product_id = p.id
                WHERE p.vendor_id = ?
            """, (user_id,))
            row = c.fetchone()
            avg_rating = round(row[0], 2) if row and row[0] is not None else None
            # Revenue (30d)
            c.execute("""
                SELECT SUM(amount_usd) FROM orders WHERE vendor_id = ? AND status = 'delivered' AND created_at >= date('now', '-30 day')
            """, (user_id,))
            revenue_30d = c.fetchone()[0] or 0.0
            # Conversion rate (orders/visits) - placeholder, needs tracking
            conversion_rate = None
            stats = {
                'level': level,
                'avatar': avatar,
                'logo': logo,
                'shipping_location': shipping_location,
                'positive_feedbacks': positive_feedbacks,
                'negative_feedbacks': negative_feedbacks,
                'total_orders': total_orders,
                'total_shipped': total_shipped,
                'total_sales': total_sales,
                'revenue': revenue,
                'completion_rate': completion_rate,
                'avg_rating': avg_rating,
                'revenue_30d': revenue_30d,
                'conversion_rate': conversion_rate
            }
        return render_template('user/vendor_dashboard.html',
                              vendor_name=vendor_name,
                              stats=stats,
                              recent_orders=recent_orders,
                              recent_reviews=recent_reviews,
                              recent_messages=recent_messages,
                              published_products=published_products,
                              title="Vendor Dashboard")
    
    # Non-vendor user dashboard (buyer) - fetch purchased products
    profile_data, error = get_user_profile_data(user_id)
    if error:
        flash(error, 'error')
        session.clear()
        return redirect(url_for('user.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        user_row = c.fetchone()
        user = dict(user_row)
        
        # Fetch purchased products (completed orders)
        c.execute("""
            SELECT o.id as order_id, o.amount_usd, o.status, o.created_at as purchase_date,
                   p.id as product_id, p.title, p.featured_image, p.price_usd,
                   u.pusername as vendor_username, c.name as category_name
            FROM orders o
            JOIN products p ON o.product_id = p.id
            JOIN users u ON o.vendor_id = u.id
            LEFT JOIN categories c ON p.category_id = c.id
            WHERE o.user_id = ? AND o.status = 'completed'
            ORDER BY o.created_at DESC
        """, (user_id,))
        purchased_products = [dict(row) for row in c.fetchall()]
        
        # Recent orders (all statuses)
        c.execute("""
            SELECT o.*, p.title, u.pusername as vendor_username
            FROM orders o
            JOIN products p ON o.product_id = p.id
            JOIN users u ON o.vendor_id = u.id
            WHERE o.user_id = ?
            ORDER BY o.created_at DESC LIMIT 5
        """, (user_id,))
        orders = [dict(row) for row in c.fetchall()]
        
        # Recent reports
        c.execute("""
            SELECT r.*, u.pusername as vendor_username
            FROM reports r
            LEFT JOIN users u ON r.vendor_id = u.id
            WHERE r.user_id = ?
            ORDER BY r.created_at DESC LIMIT 5
        """, (user_id,))
        reports = [dict(row) for row in c.fetchall()]
        
        # Buyer statistics
        try:
            c.execute("""
                SELECT COALESCE(SUM(item_count), 0) as items, COALESCE(SUM(amount_usd), 0.0) as paid
                FROM orders WHERE user_id = ? AND status = 'completed'
            """, (user_id,))
            result = c.fetchone()
            items_bought = result['items']
            paid_usd = result['paid']
            c.execute("""
                SELECT COALESCE(SUM(amount_usd), 0.0) as total
                FROM orders WHERE user_id = ?
            """, (user_id,))
            total_purchases_usd = c.fetchone()['total']
            in_escrow_usd = 0.0
        except Exception as e:
            logger.error("Failed to fetch buyer stats: %s", str(e))
            flash("Unable to fetch buyer statistics.", 'error')
            items_bought = 0
            paid_usd = 0.0
            in_escrow_usd = 0.0
            total_purchases_usd = 0.0
    
    rates = get_exchange_rates()
    if not rates:
        flash("Unable to fetch exchange rates.", 'error')
        rates = {"bitcoin": {}, "monero": {}}
    
    stats = {
        "items_bought": items_bought,
        "paid_usd": paid_usd,
        "in_escrow_usd": in_escrow_usd,
        "total_purchases_usd": total_purchases_usd
    }
    logger.debug("Buyer stats: %s", stats)
    
    return render_template('user/dashboard.html',
                         user=user,
                         orders=orders,
                         rates=rates,
                         reports=reports,
                         profile_data=profile_data,
                         stats=stats,
                         purchased_products=purchased_products,
                         title="Dashboard - Sydney")

def get_bond_amounts():
    return {
        'btc': f'{BOND_AMOUNT_BTC:.8f}',
        'xmr': f'{BOND_AMOUNT_XMR:.8f}'
    }

def has_purchases(user_id):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM orders WHERE user_id = ?", (user_id,))
        return c.fetchone()[0] > 0

def get_pending_payment(user_id):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT id, crypto_type, address, amount, txid, status FROM vendor_payments WHERE user_id = ? AND status IN ('pending', 'confirmed') ORDER BY created_at DESC LIMIT 1", (user_id,))
        row = c.fetchone()
        if row:
            return {
                'id': row[0],
                'crypto_type': row[1],
                'address': row[2],
                'amount': row[3],
                'txid': row[4],
                'status': row[5],
                'qr_path': f'qr_codes/{user_id}_{row[1]}.png'
            }
    return None

def generate_qr_code(address, crypto_type, user_id):
    qr_dir = 'static/qr_codes'
    os.makedirs(qr_dir, exist_ok=True)
    qr_path = f'{qr_dir}/{user_id}_{crypto_type}.png'
    qr = qrcode.QRCode(version=1, box_size=5, border=2)
    qr.add_data(f'{crypto_type}:{address}')
    qr.make(fit=True)
    qr.make_image(fill_color="black", back_color="white").save(qr_path)
    return f'qr_codes/{user_id}_{crypto_type}.png'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_pgp_key(pgp_key):
    return pgp_key.strip().startswith('-----BEGIN PGP PUBLIC KEY BLOCK-----') and '-----END PGP PUBLIC KEY BLOCK-----' in pgp_key

@user_bp.route('/become_vendor', methods=['GET', 'POST'])
@login_required
def become_vendor():
    """Page for non-vendor users to view and subscribe to vendor packages"""
    if 'user_id' not in session:
        flash("Please log in to access this page.", 'error')
        return redirect(url_for('user.login'))

    user_id = session['user_id']
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT role FROM users WHERE id = ?", (user_id,))
        user = c.fetchone()
        
        if not user:
            flash("User not found.", 'error')
            return redirect(url_for('public.index'))
        
        # If user is already a vendor, redirect to vendor dashboard
        if user['role'] == 'vendor':
            flash("You are already a vendor.", 'info')
            return redirect(url_for('vendor.products_index'))
        
        # Check if user already has a pending or active subscription
        c.execute("""
            SELECT vs.*, p.title as package_title, p.price_usd, p.features, p.product_limit
            FROM vendor_subscriptions vs
            JOIN packages p ON vs.package_id = p.id
            WHERE vs.vendor_id = ? AND vs.status IN ('pending', 'active')
        """, (user_id,))
        existing_subscription = c.fetchone()
        
        if request.method == 'POST':
            package_id = request.form.get('package_id', type=int)
            if not package_id:
                flash("Please select a package.", 'error')
                return redirect(url_for('user.become_vendor'))
            
            # Get package details
            c.execute("SELECT * FROM packages WHERE id = ?", (package_id,))
            package = c.fetchone()
            if not package:
                flash("Package not found.", 'error')
                return redirect(url_for('user.become_vendor'))
            
            package = dict(package)
            
            # Handle free package
            if package.get('free', 0) == 1:
                # Update user role to vendor and create subscription
                expires_at = datetime.now() + timedelta(days=30)
                c.execute("UPDATE users SET role = 'vendor' WHERE id = ?", (user_id,))
                c.execute("""
                    INSERT INTO vendor_subscriptions (vendor_id, package_id, status, expires_at, payment_txid)
                    VALUES (?, ?, 'active', ?, NULL)
                """, (user_id, package_id, expires_at))
                conn.commit()
                
                # Update session role
                session['role'] = 'vendor'
                
                flash("Congratulations! You are now a vendor with an active subscription.", 'success')
                return redirect(url_for('vendor.products_index'))
            
            # Handle paid package
            crypto_currency = request.form.get('crypto_currency')
            if crypto_currency not in ['BTC', 'XMR']:
                flash("Please select a valid cryptocurrency.", 'error')
                return redirect(url_for('user.become_vendor'))
            
            # Get crypto price and calculate amount
            from routes.vendor import get_crypto_price
            crypto_price = get_crypto_price(crypto_currency)
            if not crypto_price:
                flash("Unable to fetch cryptocurrency price. Please try again later.", 'error')
                return redirect(url_for('user.become_vendor'))
            
            crypto_amount = package['price_usd'] / crypto_price
            wallet_address = "YOUR_BTC_ADDRESS" if crypto_currency == "BTC" else "YOUR_XMR_ADDRESS"
            
            # Create pending subscription
            expires_at = datetime.now() + timedelta(days=30)
            c.execute("""
                INSERT INTO vendor_subscriptions (vendor_id, package_id, status, expires_at, payment_txid)
                VALUES (?, ?, 'pending', ?, NULL)
            """, (user_id, package_id, expires_at))
            conn.commit()
            
            flash(f"Please send {crypto_amount:.6f} {crypto_currency} to {wallet_address} and provide the transaction ID to complete your subscription.", 'info')
            return redirect(url_for('vendor.confirm_payment', package_id=package_id, crypto_currency=crypto_currency))
        
        # Get all available packages
        c.execute("SELECT * FROM packages ORDER BY price_usd ASC")
        packages = [dict(row) for row in c.fetchall()]
        
        # Get crypto prices for display
        from routes.vendor import get_crypto_price
        btc_price = get_crypto_price("BTC")
        xmr_price = get_crypto_price("XMR")
        
        return render_template('user/become_vendor.html', 
                             packages=packages, 
                             existing_subscription=existing_subscription,
                             btc_price=btc_price, 
                             xmr_price=xmr_price,
                             title="Become a Vendor - Sydney")

# GET route to render form
@user_bp.route('/edit_profile')
@login_required
def edit_profile():
    form = EditProfileForm(obj=current_user)
    profile_data, error = get_user_profile_data(session['user_id'])
    rates = get_exchange_rates()
    if not rates:
        flash("Unable to fetch exchange rates.", 'error')
        rates = {"bitcoin": {}, "monero": {}}
    return render_template('user/edit_profile.html', form=form, profile_data=profile_data, rates=rates, pgp_encrypted_challenge=session.get('pgp_verify_encrypted'))

# POST route to handle form submission
@user_bp.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    form = EditProfileForm()
    profile_data, error = get_user_profile_data(session['user_id'])
    rates = get_exchange_rates()
    if not rates:
        flash("Unable to fetch exchange rates.", 'error')
        rates = {"bitcoin": {}, "monero": {}}
    if not form.validate_on_submit():
        flash('Please correct the errors in the form.', 'error')
        return render_template('user/edit_profile.html', form=form, profile_data=profile_data, rates=rates)

    # Use existing database connection
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Fetch current user data
        cursor.execute('SELECT password, pin FROM users WHERE id = ?', (current_user.id,))
        user_data = cursor.fetchone()
        if not user_data:
            flash('User not found.', 'error')
            return redirect(url_for('user.edit_profile'))

        current_password_hash, current_pin_hash = user_data

        # Initialize updates dictionary
        updates = {}
        params = []

        # Profile settings
        updates['jabber'] = form.da_jabber.data
        updates['description'] = form.da_description.data
        updates['login_phrase'] = form.da_passphrase.data
        updates['currencyid'] = form.da_currencyid.data
        updates['stealth'] = int(form.da_stealth.data)

        # Avatar upload
        if form.da_image.data:
            file = form.da_image.data
            if file and file.filename:
                ext = os.path.splitext(file.filename)[1].lower()
                if ext not in ('.png', '.jpg', '.jpeg'):
                    flash('Invalid file type. Use PNG, JPG, or JPEG.', 'error')
                    return render_template('user/edit_profile.html', form=form)
                if file.content_length > 2 * 1024 * 1024:  # 2MB
                    flash('File too large. Maximum size is 2MB.', 'error')
                    return render_template('user/edit_profile.html', form=form, profile_data=profile_data, rates=rates)
                filename = f"{uuid.uuid4().hex}{ext}"
                upload_path = os.path.join(UPLOAD_FOLDER, filename)
                os.makedirs(UPLOAD_FOLDER, exist_ok=True)
                file.save(upload_path)
                updates['avatar'] = filename

        # Multisig
        updates['multisig'] = form.da_multisig.data
        updates['refund'] = form.da_refund.data

        # Security settings (require PIN)
        security_fields = ['pgp_public_key', 'two_factor_secret', 'canbuy', 'pinbuy', 'phis']
        if any([form.da_pgp.data, form.da_factor.data, form.da_canbuy.data, form.da_pinbuy.data, form.da_phis.data]) or session.get('pgp_verify_challenge'):
            if not form.da_pincb.data or not bcrypt.checkpw(form.da_pincb.data.encode('utf-8'), current_pin_hash.encode('utf-8')):
                flash('Invalid current PIN for security settings.', 'error')
                return render_template('user/edit_profile.html', form=form, profile_data=profile_data, rates=rates)

            # Handle PGP verification handshake
            submitted_pgp = (form.da_pgp.data or '').strip()
            pending_pgp = session.get('pgp_verify_pending_public_key', '').strip() if session.get('pgp_verify_pending_public_key') else ''
            request_enable_2fa = (form.da_factor.data == '1')

            # If a PGP key is submitted or a challenge is pending, process the handshake flow
            if submitted_pgp or session.get('pgp_verify_challenge'):
                # Step 1: new key submitted → generate challenge and ask user to decrypt
                if submitted_pgp and not session.get('pgp_verify_challenge'):
                    # Validate basic format
                    if not validate_pgp_key(submitted_pgp):
                        flash('Invalid PGP public key format.', 'error')
                        return render_template('user/edit_profile.html', form=form, profile_data=profile_data, rates=rates)
                    try:
                        pubkey, _ = pgpy.PGPKey.from_blob(submitted_pgp)
                        challenge = f"PGP-VERIFY:{current_user.username}:{int(time.time())}:{secrets.token_hex(8)}"
                        encrypted = str(pubkey.encrypt(pgpy.PGPMessage.new(challenge)))
                        session['pgp_verify_challenge'] = challenge
                        # store minimal fingerprint marker to bind session to the key
                        session['pgp_verify_key_fingerprint'] = submitted_pgp[:64]
                        session['pgp_verify_encrypted'] = encrypted
                        session['pgp_verify_pending_public_key'] = submitted_pgp
                        flash('Step 1: Decrypt the PGP message shown in the Security Settings section and paste the plaintext in the PGP Decrypted Message field, then save again with your PIN.', 'info')
                        return render_template('user/edit_profile.html', form=form, profile_data=profile_data, rates=rates, pgp_encrypted_challenge=encrypted)
                    except Exception as e:
                        logger.error(f"PGP challenge encryption failed: {e}")
                        flash('Could not encrypt with provided PGP key. Please verify your key.', 'error')
                        return render_template('user/edit_profile.html', form=form, profile_data=profile_data, rates=rates)
                else:
                    # Step 2: expect the decrypted message back
                    decrypted_response = (form.da_pgp_decrypted.data or '').strip()
                    if not decrypted_response:
                        flash('Please paste the decrypted PGP challenge into the PGP Decrypted Message field and save again.', 'error')
                        return render_template('user/edit_profile.html', form=form, profile_data=profile_data, rates=rates, pgp_encrypted_challenge=session.get('pgp_verify_encrypted'))
                    if decrypted_response != session.get('pgp_verify_challenge'):
                        flash('Decrypted PGP challenge does not match. Ensure you decrypted the latest message.', 'error')
                        return render_template('user/edit_profile.html', form=form, profile_data=profile_data, rates=rates, pgp_encrypted_challenge=session.get('pgp_verify_encrypted'))
                    # Success → persist PGP key from submitted value or pending session
                    final_pgp = submitted_pgp or pending_pgp
                    if not final_pgp:
                        flash('Internal error: missing PGP key for verification.', 'error')
                        return render_template('user/edit_profile.html', form=form, profile_data=profile_data, rates=rates)
                    updates['pgp_public_key'] = final_pgp
                    # Clear challenge state
                    session.pop('pgp_verify_challenge', None)
                    session.pop('pgp_verify_key_fingerprint', None)
                    session.pop('pgp_verify_encrypted', None)
                    session.pop('pgp_verify_pending_public_key', None)
                    flash('PGP key verified and saved.', 'success')

            # Guard enabling 2FA: require a saved PGP key
            if request_enable_2fa:
                # Confirm the user has a stored PGP key at this point
                cursor.execute('SELECT pgp_public_key FROM users WHERE id = ?', (current_user.id,))
                row = cursor.fetchone()
                effective_pgp = updates.get('pgp_public_key') or (row['pgp_public_key'] if row else None)
                if not effective_pgp:
                    flash('You must add and verify a PGP public key before enabling 2FA.', 'error')
                    return render_template('user/edit_profile.html', form=form, profile_data=profile_data, rates=rates, pgp_encrypted_challenge=session.get('pgp_verify_encrypted'))
                updates['two_factor_secret'] = '1'
            else:
                updates['two_factor_secret'] = '0'

            updates['canbuy'] = int(form.da_canbuy.data)
            updates['pinbuy'] = int(form.da_pinbuy.data)
            updates['phis'] = int(form.da_phis.data)

        # Password change
        if form.da_passwd.data:
            if not form.da_passac.data or not bcrypt.checkpw(form.da_passac.data.encode('utf-8'), current_password_hash.encode('utf-8')):
                flash('Invalid current password.', 'error')
                return render_template('user/edit_profile.html', form=form, profile_data=profile_data, rates=rates)
            updates['password'] = bcrypt.hashpw(form.da_passwd.data.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # PIN change
        if form.da_pinwd.data:
            if not form.da_pinac.data or not bcrypt.checkpw(form.da_pinac.data.encode('utf-8'), current_pin_hash.encode('utf-8')):
                flash('Invalid current PIN.', 'error')
                return render_template('user/edit_profile.html', form=form, profile_data=profile_data, rates=rates)
            updates['pin'] = bcrypt.hashpw(form.da_pinwd.data.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Theme settings
        updates['menu_follow'] = int(form.da_menu_follow.data)
        updates['feedback'] = int(form.da_feedback.data)

        # Search settings
        updates['tocountryid'] = int(form.sd_tocountryid.data)
        updates['countryid'] = int(form.sd_countryid.data)
        updates['discardww'] = 1 if form.sd_discardww.data else 0

        # Build SQL query
        set_clause = ', '.join([f'{key} = ?' for key in updates])
        params = list(updates.values()) + [current_user.id]
        query = f'UPDATE users SET {set_clause} WHERE id = ?'

        try:
            cursor.execute(query, params)
            conn.commit()
            # Refresh current_user fields for immediate UI consistency
            try:
                cursor.execute("SELECT id, username, pusername, pin, password, role, active, registered_at, btc_address, avatar, login_phrase, status, session_timeout, profile_visibility, is_vendor, notify_messages, notify_orders, pgp_public_key, pgp_private_key, vendor_status, two_factor_secret, mnemonic_hash, created_at, last_login, jabber, description, currencyid, stealth, multisig, refund, canbuy, pinbuy, phis, menu_follow, feedback, tocountryid, countryid, discardww FROM users WHERE id = ?", (current_user.id,))
                row = cursor.fetchone()
                if row:
                    from app import User as AppUser
                    user_obj = AppUser(*row)
                    login_user(user_obj)
            except Exception as e:
                logger.warning(f"Could not refresh current_user: {e}")
            flash('Profile updated successfully.', 'success')
        except sqlite3.Error as e:
            conn.rollback()
            flash(f'Database error: {str(e)}', 'error')

    return redirect(url_for('user.edit_profile'))

@user_bp.route('/messages', methods=['GET', 'POST'])
def messages():
    if 'user_id' not in session:
        flash("Please log in to view messages.", 'error')
        return redirect(url_for('user.login'))
    
    try:
        # Check if this is a Tor request
        is_tor = is_tor_request(request)
        if is_tor:
            logger.info("Messages route accessed via Tor")
        
        # Initialize GPG with Tor-specific settings
        gpg, gpg_error = init_gpg_for_tor()
        
        if gpg_error and gpg_error != "fallback":
            logger.error(f"GPG initialization failed: {gpg_error}")
            flash("Encryption service temporarily unavailable. Please try again later.", 'error')
            return render_template('user/messages.html', has_private_key=False, gpg_error=True)
        
        selected_recipient_id = request.args.get('recipient_id', type=int)
        
        with get_db_connection() as conn:
            c = conn.cursor()
            # Check if user has uploaded private key
            c.execute("SELECT pgp_private_key FROM users WHERE id = ?", (session['user_id'],))
            result = c.fetchone()
            private_key_encrypted = result['pgp_private_key'] if result else None
            has_private_key = bool(private_key_encrypted)
            
            # Handle private key upload
            if request.method == 'POST' and request.form.get('action') == 'upload_private_key':
                #validate_csrf_token()
                private_key = request.form.get('private_key', '').strip()
                passphrase = request.form.get('passphrase', '').strip()
                if not private_key or not passphrase:
                    flash("Private key and passphrase are required.", 'error')
                else:
                    try:
                        if gpg:
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
                        else:
                            flash("Encryption service unavailable. Please try again later.", 'error')
                    except Exception as e:
                        logger.error(f"Error uploading private key: {e}")
                        flash("Error uploading private key. Please try again.", 'error')
            
            # If no private key, show upload form only
            if not has_private_key:
                return render_template('user/messages.html', has_private_key=False)
            
            # Decrypt user's private key
            try:
                encrypted_key = private_key_encrypted
                decrypted_data = cipher.decrypt(encrypted_key).decode().split('||')
                private_key, passphrase = decrypted_data[0], decrypted_data[1]
                if gpg:
                    gpg.import_keys(private_key)
            except Exception as e:
                logger.error(f"Failed to decrypt private key: {e}")
                flash("Error accessing your private key. Please re-upload it.", 'error')
                return render_template('user/messages.html', has_private_key=False)
            
            # Handle sending a message
            if request.method == 'POST' and request.form.get('action') == 'send_message':
                #validate_csrf_token()
                message = request.form.get('message', '').strip()
                if not message:
                    flash("Message cannot be empty.", 'error')
                elif not selected_recipient_id:
                    flash("No recipient selected.", 'error')
                else:
                    try:
                        c.execute("SELECT pgp_public_key FROM users WHERE id = ?", (selected_recipient_id,))
                        recipient_result = c.fetchone()
                        if not recipient_result or not recipient_result['pgp_public_key']:
                            flash("Recipient has no PGP key.", 'error')
                        else:
                            recipient_key = recipient_result['pgp_public_key']
                            if gpg:
                                encrypted_msg = str(gpg.encrypt(message, recipients=[recipient_key], always_trust=True))
                            else:
                                # Fallback: store message without encryption (not recommended for production)
                                encrypted_msg = f"[UNENCRYPTED] {message}"
                            
                            c.execute("""
                                INSERT INTO messages (sender_id, recipient_id, content, created_at)
                                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                            """, (session['user_id'], selected_recipient_id, encrypted_msg))
                            conn.commit()
                            flash("Message sent securely.", 'success')
                            return redirect(url_for('user.messages', recipient_id=selected_recipient_id))
                    except Exception as e:
                        logger.error(f"Error sending message: {e}")
                        flash("Error sending message. Please try again.", 'error')
            
            # Fetch conversations
            try:
                c.execute("""
                    SELECT DISTINCT 
                        CASE WHEN m.sender_id = ? THEN m.recipient_id ELSE m.sender_id END as recipient_id,
                        CASE WHEN m.sender_id = ? THEN r.pusername ELSE s.pusername END as recipient_name,
                        MAX(m.created_at) as last_message_time,
                        (SELECT content FROM messages m2 
                         WHERE (m2.sender_id = m.sender_id AND m2.recipient_id = m.recipient_id) 
                            OR (m2.sender_id = m.recipient_id AND m2.recipient_id = m.sender_id)
                         ORDER BY m2.created_at DESC LIMIT 1) as last_message_encrypted
                    FROM messages m
                    LEFT JOIN users s ON s.id = m.sender_id
                    LEFT JOIN users r ON r.id = m.recipient_id
                    WHERE ? IN (m.sender_id, m.recipient_id)
                    GROUP BY recipient_id, recipient_name, s.pusername, r.pusername
                    ORDER BY last_message_time DESC
                """, (session['user_id'], session['user_id'], session['user_id']))
                conversations_raw = [dict(row) for row in c.fetchall()]
                
                # Decrypt last messages for display
                conversations = []
                for convo in conversations_raw:
                    try:
                        if convo['last_message_encrypted']:
                            if gpg:
                                decrypted = gpg.decrypt(convo['last_message_encrypted'], passphrase=passphrase)
                                convo['last_message'] = str(decrypted) if decrypted and decrypted.ok else "[Decryption Failed]"
                            else:
                                # Fallback: show encrypted message as-is
                                convo['last_message'] = "[Encrypted - GPG Unavailable]"
                        else:
                            convo['last_message'] = "Start a conversation"
                    except Exception as e:
                        logger.error(f"Failed to decrypt message: {e}")
                        convo['last_message'] = "[Decryption Failed]"
                    conversations.append(convo)
            except Exception as e:
                logger.error(f"Error fetching conversations: {e}")
                conversations = []
                flash("Error loading conversations. Please try again.", 'error')
            
            # Fetch messages for selected conversation
            messages = []
            selected_recipient_name = None
            if selected_recipient_id:
                try:
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
                        try:
                            if gpg:
                                decrypted = gpg.decrypt(msg['content'], passphrase=passphrase)
                                msg['content'] = str(decrypted) if decrypted and decrypted.ok else "[Decryption Failed]"
                            else:
                                # Fallback: show encrypted message as-is
                                msg['content'] = "[Encrypted - GPG Unavailable]"
                        except Exception as e:
                            logger.error(f"Failed to decrypt message: {e}")
                            msg['content'] = "[Decryption Failed]"
                        messages.append(msg)
                    
                    c.execute("SELECT pusername FROM users WHERE id = ?", (selected_recipient_id,))
                    recipient = c.fetchone()
                    selected_recipient_name = recipient['pusername'] if recipient else "Unknown User"
                except Exception as e:
                    logger.error(f"Error fetching messages: {e}")
                    flash("Error loading messages. Please try again.", 'error')
        
        return render_template('user/messages.html', 
                              has_private_key=True,
                              conversations=conversations, 
                              messages=messages, 
                              selected_recipient_id=selected_recipient_id, 
                              selected_recipient_name=selected_recipient_name,
                              is_tor=is_tor)
    
    except Exception as e:
        logger.error(f"Unexpected error in messages route: {e}")
        flash("An unexpected error occurred. Please try again later.", 'error')
        return render_template('user/messages.html', has_private_key=False, error=True)

@user_bp.route('/balance', methods=['GET'])
@limiter.limit("20 per minute; 200 per hour; 1000 per day", key_func=get_remote_address)
def balance():
    """Display user balance and deposit address for BTC or XMR."""
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to view your balance.", 'error')
        return redirect(url_for('user.login'))
    
    crypto = request.args.get('crypto', 'btc').lower()
    if crypto not in ['btc', 'xmr']:
        flash("Invalid cryptocurrency selected.", 'error')
        return redirect(url_for('user.balance'))
    
    # Fetch balance from balances table
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT balance_btc, balance_xmr FROM balances WHERE user_id = ?", (user_id,))
            balance_row = c.fetchone()
            if not balance_row:
                # Initialize balance if not exists
                c.execute("INSERT INTO balances (user_id, balance_btc, balance_xmr) VALUES (?, 0.0, 0.0)", (user_id,))
                conn.commit()
                balance = 0.0
            else:
                balance = balance_row['balance_btc'] if crypto == 'btc' else balance_row['balance_xmr']
    except Exception as e:
        logger.error("Failed to fetch balance: %s", str(e))
        flash("Unable to fetch balance.", 'error')
        return redirect(url_for('user.balance'))
    
    # Generate deposit address (simplified; use secure wallet in production)
    try:
        if crypto == 'btc':
            wallet = BitcoinWallet(wallet_id=f"user_{user_id}_btc")
            deposit_address = wallet.get_new_address()
        else:
            wallet = Wallet()  # Configure Monero wallet appropriately
            deposit_address = wallet.new_address()
        
        # Encrypt and store deposit address
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT pgp_public_key FROM users WHERE id = ?", (user_id,))
            public_key = c.fetchone()['pgp_public_key']
            if public_key:
                encrypted_address = encrypt_message(public_key, deposit_address)
                c.execute("UPDATE balances SET deposit_address = ? WHERE user_id = ?", (encrypted_address, user_id))
                conn.commit()
    except Exception as e:
        logger.error("Failed to generate or store deposit address: %s", str(e))
        flash("Unable to generate deposit address.", 'error')
        return redirect(url_for('user.balance'))
    
    return render_template('user/balance.html', crypto=crypto, balance=balance, deposit_address=deposit_address)

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

@user_bp.route('/favorites', methods=['GET'])
def favorites():
    if 'user_id' not in session:
        flash("Please log in to view your favorites.", 'error')
        return redirect(url_for('user.login'))
    
    user_id = session['user_id']
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Fetch favorite products
            c.execute("""
                SELECT p.id, p.title, p.price_usd, p.stock, p.status, p.featured_image, u.pusername as vendor_name,
                       p.created_at, 'product' as type
                FROM favorites f
                JOIN products p ON f.product_id = p.id
                JOIN users u ON p.vendor_id = u.id
                WHERE f.user_id = ? AND p.status = 'active'
                ORDER BY f.created_at DESC
            """, (user_id,))
            favorite_products = [dict(row) for row in c.fetchall()]
            
            # Fetch favorite vendors
            c.execute("""
                SELECT v.id, v.pusername as username, v.avatar, v.level,
                       (SELECT COUNT(*) FROM products WHERE vendor_id = v.id AND status = 'active') as products_count,
                       (SELECT COUNT(*) FROM orders WHERE vendor_id = v.id AND status = 'completed') as sales_count,
                       fv.created_at, 'vendor' as type
                FROM favorite_vendors fv
                JOIN users v ON fv.vendor_id = v.id
                WHERE fv.user_id = ? AND v.role = 'vendor'
                ORDER BY fv.created_at DESC
            """, (user_id,))
            favorite_vendors = [dict(row) for row in c.fetchall()]
            
            # Add avatar URLs for vendors
            for vendor in favorite_vendors:
                if vendor.get('avatar'):
                    vendor['avatar_url'] = url_for('static', filename=f"uploads/avatar/{vendor['avatar']}")
                else:
                    vendor['avatar_url'] = url_for('static', filename='avatars/default.png')
        
        return render_template('user/favorites.html', 
                             favorite_products=favorite_products, 
                             favorite_vendors=favorite_vendors)
    except Exception as e:
        logger.error(f"Favorites error: {str(e)}")
        flash("An error occurred while loading favorites.", 'error')
        return redirect(url_for('user.dashboard'))

@user_bp.route('/favorites/add/<int:product_id>', methods=['POST'])
def add_favorite(product_id):
    if 'user_id' not in session:
        flash("Please log in to add favorites.", 'error')
        return redirect(url_for('user.login'))
    
    user_id = session['user_id']
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            # Check if product exists and is active
            c.execute("SELECT id FROM products WHERE id = ? AND status = 'active'", (product_id,))
            if not c.fetchone():
                flash("Product not found or not available.", 'error')
                return redirect(url_for('main.index'))
            
            # Add favorite
            try:
                c.execute("""
                    INSERT INTO favorites (user_id, product_id)
                    VALUES (?, ?)
                """, (user_id, product_id))
                conn.commit()
                flash("Product added to favorites.", 'success')
            except sqlite3.IntegrityError:
                flash("Product is already in your favorites.", 'error')
        
        return redirect(request.referrer or url_for('main.index'))
    except Exception as e:
        logger.error(f"Add favorite error: {str(e)}")
        flash("An error occurred while adding to favorites.", 'error')
        return redirect(url_for('user.dashboard'))

@user_bp.route('/favorites/remove/<int:product_id>', methods=['POST'])
def remove_favorite(product_id):
    if 'user_id' not in session:
        flash("Please log in to remove favorites.", 'error')
        return redirect(url_for('user.login'))
    
    user_id = session['user_id']
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                DELETE FROM favorites
                WHERE user_id = ? AND product_id = ?
            """, (user_id, product_id))
            conn.commit()
            if c.rowcount > 0:
                flash("Product removed from favorites.", 'success')
            else:
                flash("Product not found in your favorites.", 'error')
        
        return redirect(url_for('user.favorites'))
    except Exception as e:
        logger.error(f"Remove favorite error: {str(e)}")
        flash("An error occurred while removing from favorites.", 'error')
        return redirect(url_for('user.favorites'))

@user_bp.route('/favorites/remove_vendor/<int:vendor_id>', methods=['POST'])
def remove_favorite_vendor(vendor_id):
    if 'user_id' not in session:
        flash("Please log in to remove favorites.", 'error')
        return redirect(url_for('user.login'))
    
    user_id = session['user_id']
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                DELETE FROM favorite_vendors
                WHERE user_id = ? AND vendor_id = ?
            """, (user_id, vendor_id))
            conn.commit()
            if c.rowcount > 0:
                flash("Vendor removed from favorites.", 'success')
            else:
                flash("Vendor not found in your favorites.", 'error')
        
        return redirect(url_for('user.favorites'))
    except Exception as e:
        logger.error(f"Remove favorite vendor error: {str(e)}")
        flash("An error occurred while removing vendor from favorites.", 'error')
        return redirect(url_for('user.favorites'))

@user_bp.route('/wallet', methods=['GET', 'POST'])
def wallet():
    if 'user_id' not in session:
        flash("Please log in to view your profile.", 'error')
        return redirect(url_for('user.login', next=request.url))
    
    user_id = session['user_id']
    withdrawal_fee = 2.47  # USD equivalent for BTC/XMR

    def generate_qr_code(data):
        img = qrcode.make(data)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        buf.seek(0)
        img_b64 = base64.b64encode(buf.read()).decode('utf-8')
        return img_b64
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            # Fetch user details
            c.execute("""
                SELECT id, pusername, btc_balance, xmr_balance, two_factor_secret, pgp_public_key
                FROM users WHERE id = ?
            """, (user_id,))
            user = c.fetchone()
            if not user:
                flash("User not found.", 'error')
                return redirect(url_for('user.dashboard'))
            
            # Fetch or generate BTC deposit address
            c.execute("SELECT btc_address, xmr_subaddress FROM user_crypto_addresses WHERE user_id = ?", (user_id,))
            row = c.fetchone()
            if row and row['btc_address']:
                btc_deposit_address = row['btc_address']
            else:
                btc_deposit_address = generate_btc_address(user_id)
                c.execute("INSERT OR REPLACE INTO user_crypto_addresses (user_id, btc_address) VALUES (?, ?)", (user_id, btc_deposit_address))
                conn.commit()
            # Fetch or generate XMR subaddress
            if row and row['xmr_subaddress']:
                xmr_deposit_address = row['xmr_subaddress']
            else:
                xmr_deposit_address = generate_monero_address(user_id)
                if xmr_deposit_address:
                    c.execute("INSERT OR REPLACE INTO user_crypto_addresses (user_id, xmr_subaddress) VALUES (?, ?)", (user_id, xmr_deposit_address))
                    conn.commit()
                else:
                    xmr_deposit_address = 'Monero wallet unavailable. Please try again later.'
            
            # Generate QR codes for deposit addresses
            btc_qr = generate_qr_code(btc_deposit_address) if btc_deposit_address else None
            xmr_qr = generate_qr_code(xmr_deposit_address) if xmr_deposit_address and 'unavailable' not in xmr_deposit_address.lower() else None

            print(f"BTC Address: {btc_deposit_address}")
            print(f"BTC QR (first 100): {btc_qr[:100] if btc_qr else None}")
            print(f"XMR Address: {xmr_deposit_address}")
            print(f"XMR QR (first 100): {xmr_qr[:100] if xmr_qr else None}")
            
            # Fetch transaction history
            c.execute("""
                SELECT id, currency, type, amount, address, tx_id, status, created_at
                FROM transactions
                WHERE user_id = ?
                ORDER BY created_at DESC
                LIMIT 50
            """, (user_id,))
            transactions = [dict(row) for row in c.fetchall()]
            
            if request.method == 'POST':
                action = request.form.get('action')
                
                if action == 'withdraw':
                    currency = request.form.get('currency')
                    amount = request.form.get('amount', type=float)
                    address = request.form.get('address', '').strip()
                    two_factor_code = request.form.get('two_factor_code', '').strip()
                    pgp_signature = request.form.get('pgp_signature', '').strip()
                    
                    # Validation
                    if currency not in ['BTC', 'XMR']:
                        flash("Invalid currency.", 'error')
                    elif amount is None or amount <= 0:
                        flash("Invalid amount.", 'error')
                    elif currency == 'BTC' and not re.match(r'^(1|3|bc1)[a-zA-Z0-9]{25,34}$', address):
                        flash("Invalid Bitcoin address.", 'error')
                    elif currency == 'XMR' and not re.match(r'^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$', address):
                        flash("Invalid Monero address.", 'error')
                    elif user['two_factor_secret'] and not verify_2fa(user['two_factor_secret'], two_factor_code):
                        flash("Invalid 2FA code.", 'error')
                    elif user['pgp_public_key'] and not verify_pgp_signature(user['pgp_public_key'], pgp_signature, f"withdraw {currency} {amount}"):
                        flash("Invalid PGP signature.", 'error')
                    else:
                        balance = user['btc_balance'] if currency == 'BTC' else user['xmr_balance']
                        # Convert withdrawal fee to crypto (simplified, use real exchange rate)
                        fee_in_crypto = 0.00005 if currency == 'BTC' else 0.01
                        if amount + fee_in_crypto > balance:
                            flash("Insufficient balance.", 'error')
                        else:
                            # Update balance
                            new_balance = balance - (amount + fee_in_crypto)
                            balance_field = 'btc_balance' if currency == 'BTC' else 'xmr_balance'
                            c.execute(f"""
                                UPDATE users
                                SET {balance_field} = ?
                                WHERE id = ?
                            """, (new_balance, user_id))
                            
                            # Record transaction
                            c.execute("""
                                INSERT INTO transactions (user_id, currency, type, amount, address, status)
                                VALUES (?, ?, ?, ?, ?, ?)
                            """, (user_id, currency, 'withdrawal', amount, address, 'pending'))
                            conn.commit()
                            flash(f"Withdrawal of {amount} {currency} requested. Pending admin approval.", 'success')
                            return redirect(url_for('user.wallet'))
            
            return render_template('user/wallet.html', 
                                 user=user,
                                 transactions=transactions,
                                 btc_deposit_address=btc_deposit_address,
                                 xmr_deposit_address=xmr_deposit_address,
                                 withdrawal_fee=withdrawal_fee,
                                 btc_qr=btc_qr,
                                 xmr_qr=xmr_qr)
    except Exception as e:
        logger.error(f"Wallet error: {str(e)}")
        flash(f"An error occurred: {str(e)}", 'error')
        return redirect(url_for('user.dashboard'))

@user_bp.route('/support', methods=['GET', 'POST'])
@login_required
def support():
    """User support page to submit and view tickets."""
    if 'user_id' not in session:
        flash("Please log in to access support.", 'error')
        return redirect(url_for('user.login'))
        
    try:
       
        
        # Get user_id from session (fallback to current_user if needed)
        user_id = session.get('user_id')
        if not user_id and current_user.is_authenticated:
            user_id = current_user.id
        user_role = session.get('role', 'user')
        
        if not user_id:
            logger.warning("User not authenticated in support route")
            flash("Please log in to access support.", 'error')
            return redirect(url_for('user.login'))
        
        if request.method == 'POST':
            subject = request.form.get('subject', '').strip()
            category = request.form.get('category', '').strip()
            priority = request.form.get('priority', '').strip()
            description = request.form.get('description', '').strip()

            if not all([subject, category, priority, description]):
                flash("All fields are required.", 'error')
            elif len(subject) > 255 or len(description) > 2000:
                flash("Subject or description too long.", 'error')
            elif category not in ['General', 'Account', 'Order', 'Payment', 'Dispute', 'Vendor Support']:
                flash("Invalid category.", 'error')
            elif priority not in ['Low', 'Medium', 'High']:
                flash("Invalid priority.", 'error')
            else:
                # Create secure ticket
                ticket_id = secure_support.create_secure_ticket(
                    user_id, subject, description, category, priority, user_role
                )
                
                if ticket_id:
                    flash("Secure support ticket submitted successfully.", 'success')
                    logger.info(f"User {user_id} submitted secure ticket: {subject}")
                    return redirect(url_for('user.support'))
                else:
                    flash("Failed to create ticket. Please try again.", 'error')

        # Fetch user's tickets using secure system
        tickets = secure_support.get_user_tickets(user_id, user_role)

        # Available options for form
        support_categories = ['General', 'Account', 'Order', 'Payment', 'Dispute']
        if user_role == 'vendor':
            support_categories.append('Vendor Support')
        priorities = ['Low', 'Medium', 'High']

        logger.info(f"Support page loaded successfully for user {user_id}")
        
        return render_template('user/support.html',
                             tickets=tickets,
                             support_categories=support_categories,
                             priorities=priorities,
                             settings=get_settings())
    except sqlite3.Error as e:
        logger.error(f"Database error in support route: {str(e)}")
        flash("Database error occurred. Please try again.", 'error')
        return redirect(url_for('user.dashboard'))
   
  
@user_bp.route('/support/ticket/<int:ticket_id>', methods=['GET', 'POST'])
@login_required
def view_ticket(ticket_id):
    """View and respond to a specific support ticket."""
    if 'user_id' not in session:
        flash("Please log in to access this page.", 'error')
        return redirect(url_for('user.login'))
        
    try:
        user_id = session.get('user_id')
        if not user_id and current_user.is_authenticated:
            user_id = current_user.id
        if not user_id:
            logger.warning("User not authenticated in view_ticket route")
            flash("Please log in to access this page.", 'error')
            return redirect(url_for('user.login'))
        
        from utils.support import secure_support
        
        user_role = session.get('role', 'user')
        
        # Get ticket with responses using secure system
        ticket, responses = secure_support.get_ticket_with_responses(ticket_id, user_id, user_role)
        
        if not ticket:
            flash("Ticket not found or access denied.", 'error')
            return redirect(url_for('user.support'))
        
        # Verify user owns this ticket or is admin
        if ticket['user_id'] != user_id and user_role != 'admin':
            flash("Access denied.", 'error')
            return redirect(url_for('user.support'))

        if request.method == 'POST':
            response_body = request.form.get('response_body', '').strip()
            if not response_body:
                flash("Response body is required.", 'error')
            elif len(response_body) > 2000:
                flash("Response is too long.", 'error')
            else:
                # Add secure response
                success = secure_support.add_secure_response(
                    ticket_id, user_id, response_body, user_role
                )
                
                if success:
                    flash("Secure response submitted successfully.", 'success')
                    logger.info(f"User {user_id} responded to secure ticket #{ticket_id}")
                    return redirect(url_for('user.view_ticket', ticket_id=ticket_id))
                else:
                    flash("Failed to submit response. Please try again.", 'error')

        return render_template('user/ticket_details.html',
                             ticket=ticket,
                             responses=responses,
                             settings=get_settings())
    except Exception as e:
        logger.error(f"Error handling ticket #{ticket_id}: {str(e)}")
        flash("An error occurred. Please try again.", 'error')
        return redirect(url_for('user.support'))
    
@user_bp.route('/my-tickets', methods=['GET'])
@login_required
def my_tickets():
    """Display all support tickets for the logged-in user."""
    if 'user_id' not in session:
        flash("Please log in to view your tickets.", 'error')
        return redirect(url_for('user.login'))
        
    try:
        from utils.support import secure_support
        
        user_id = session.get('user_id')
        if not user_id and current_user.is_authenticated:
            user_id = current_user.id
        user_role = session.get('role', 'user')
        
        if not user_id:
            flash("Please log in to view your tickets.", 'error')
            return redirect(url_for('user.login'))
        
        # Get user's tickets using secure system
        tickets = secure_support.get_user_tickets(user_id, user_role)
        
        # Pagination
        page = request.args.get('page', 1, type=int)
        per_page = 10
        total = len(tickets)
        total_pages = (total + per_page - 1) // per_page
        
        # Apply pagination
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_tickets = tickets[start_idx:end_idx]

        return render_template('user/my-tickets.html',
                             tickets=paginated_tickets,
                             page=page,
                             total_pages=total_pages,
                             settings=get_settings())
    except Exception as e:
        logger.error(f"Error fetching user tickets: {str(e)}")
        flash("An error occurred. Please try again.", 'error')
        return redirect(url_for('user.support'))
      
@user_bp.route('/support/tickets/<int:ticket_id>', methods=['GET'])
@login_required
def view_tickets(ticket_id):
    """Alternative route for viewing tickets - redirects to main view_ticket route."""
    return redirect(url_for('user.view_ticket', ticket_id=ticket_id))

@user_bp.route('/orders', methods=['GET'])
def orders():
    """Display all user orders with optional status filter."""
    if 'user_id' not in session:
        flash("Please log in to view your orders.", 'error')
        return redirect(url_for('user.login'))
    
    status = request.args.get('status', '').lower()
    valid_statuses = ['pending', 'accepted', 'shipped', 'finalized', 'disputed', 'canceled', 'unpaid']
    if status and status not in valid_statuses:
        flash("Invalid order status.", 'error')
        return redirect(url_for('user.orders'))
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            query = """
                SELECT o.*, p.title, u.pusername as vendor_username
                FROM orders o
                JOIN products p ON o.product_id = p.id
                JOIN users u ON o.vendor_id = u.id
                WHERE o.user_id = ?
            """
            params = [session['user_id']]
            if status:
                query += " AND o.status = ?"
                params.append(status)
            query += " ORDER BY o.created_at DESC"
            
            c.execute(query, params)
            orders = [dict(row) for row in c.fetchall()]
    except Exception as e:
        logger.error("Failed to fetch orders: %s", str(e))
        flash("Unable to fetch orders.", 'error')
        orders = []
    rates = get_exchange_rates()
    if not rates:
        flash("Unable to fetch exchange rates.", 'error')
        rates = {"bitcoin": {}, "monero": {}}
        
    return render_template('user/orders/index.html',
                         orders=orders,
                         rates=rates,
                         current_status=status,
                         title="My Orders - Sydney")

@user_bp.route('/purchased-products', methods=['GET'])
def purchased_products():
    """Display all products purchased by the user (completed orders only)."""
    if 'user_id' not in session:
        flash("Please log in to view your purchased products.", 'error')
        return redirect(url_for('user.login'))
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Fetch purchased products (completed orders only)
            query = """
                SELECT o.id as order_id, o.amount_usd, o.status, o.created_at as purchase_date,
                       p.id as product_id, p.title, p.featured_image, p.price_usd, p.description,
                       u.pusername as vendor_username, c.name as category_name
                FROM orders o
                JOIN products p ON o.product_id = p.id
                JOIN users u ON o.vendor_id = u.id
                LEFT JOIN categories c ON p.category_id = c.id
                WHERE o.user_id = ? AND o.status = 'completed'
                ORDER BY o.created_at DESC
            """
            
            c.execute(query, [session['user_id']])
            purchased_products = [dict(row) for row in c.fetchall()]
            
    except Exception as e:
        logger.error("Failed to fetch purchased products: %s", str(e))
        flash("Unable to fetch purchased products.", 'error')
        purchased_products = []
        
    return render_template('user/purchased_products.html',
                         purchased_products=purchased_products,
                         title="My Purchased Products - Sydney")

@user_bp.route('/orders/pending')
def orders_pending():
    """Display pending orders."""
    return redirect(url_for('user.orders', status='pending'))

@user_bp.route('/orders/accepted')
def orders_accepted():
    """Display accepted orders."""
    return redirect(url_for('user.orders', status='accepted'))

@user_bp.route('/orders/shipped')
def orders_shipped():
    """Display shipped orders."""
    return redirect(url_for('user.orders', status='shipped'))

@user_bp.route('/orders/finalized')
def orders_finalized():
    """Display finalized orders."""
    return redirect(url_for('user.orders', status='finalized'))

@user_bp.route('/orders/disputed')
def orders_disputed():
    """Display disputed orders."""
    return redirect(url_for('user.orders', status='disputed'))

@user_bp.route('/orders/canceled')
def orders_canceled():
    """Display canceled orders."""
    return redirect(url_for('user.orders', status='canceled'))

@user_bp.route('/orders/unpaid')
def orders_unpaid():
    """Display unpaid orders."""
    return redirect(url_for('user.orders', status='unpaid'))

@user_bp.route('/faq')
def faq():
    with get_db_connection() as conn:
        c = conn.cursor()
        # Fetch all FAQs with categories
        c.execute("""
            SELECT f.id, f.question, f.answer, f.category_id, c.name
            FROM faqs f
            JOIN faq_categories c ON f.category_id = c.id
            ORDER BY f.created_at DESC
        """)
        faqs = [{'id': row[0], 'question': row[1], 'answer': row[2], 'category_id': row[3], 'category_name': row[4]} 
                for row in c.fetchall()]
        
        # Define icon_map before categories
        icon_map = {
            'Orders': 'copy',
            'Sales': 'shopping-cart',
            'Deposits': 'arrow-bottom-right-r',
            'Withdrawal': 'arrow-top-right-r',
            'Account': 'profile',
            'Vendor': 'shopping-bag',
            'Other': 'more-o',
            'Jobs': 'briefcase',
            'Bugs': 'debug'
        }
        
        # Fetch categories
        c.execute("SELECT id, name FROM faq_categories ORDER BY name")
        categories = [{'id': row[0], 'name': row[1], 'faqs': [], 'icon': icon_map.get(row[1], 'more-o')} 
                      for row in c.fetchall()]
        
        # Group FAQs by category
        for faq in faqs:
            for category in categories:
                if category['id'] == faq['category_id']:
                    category['faqs'].append({
                        'question': faq['question'],
                        'answer': faq['answer']
                    })
                    break
        
        # Get top 5 FAQs for popular section
        popular_faqs = faqs[:5]
        
        return render_template('user/faq.html', popular_faqs=popular_faqs, categories=categories)

@user_bp.route('/messages/conversations')
@login_required
def messages_conversations():
    user_id = session['user_id']
    is_tor = is_tor_request(request)
    gpg, gpg_error = init_gpg_for_tor()
    key_info = get_user_private_key_and_passphrase(user_id)
    if not key_info.get('has_private_key'):
        return render_template('user/messages.html', active_tab='conversations', has_private_key=False, is_tor=is_tor, gpg_error=(gpg_error and gpg_error != "fallback"))
    if gpg:
        gpg.import_keys(key_info['private_key'])
    data = fetch_conversations(user_id, gpg, key_info['passphrase'])
    return render_template('user/messages.html', active_tab='conversations', has_private_key=True, is_tor=is_tor, gpg_error=(gpg_error and gpg_error != "fallback"), **data)

@user_bp.route('/messages/order_messages')
@login_required
def messages_order_messages():
    user_id = session['user_id']
    is_tor = is_tor_request(request)
    gpg, gpg_error = init_gpg_for_tor()
    key_info = get_user_private_key_and_passphrase(user_id)
    if not key_info.get('has_private_key'):
        return render_template('user/messages.html', active_tab='order_messages', has_private_key=False, is_tor=is_tor, gpg_error=(gpg_error and gpg_error != "fallback"))
    if gpg:
        gpg.import_keys(key_info['private_key'])
    data = fetch_order_messages(user_id, gpg, key_info['passphrase'])
    return render_template('user/messages.html', active_tab='order_messages', has_private_key=True, is_tor=is_tor, gpg_error=(gpg_error and gpg_error != "fallback"), **data)

@user_bp.route('/messages/trash')
@login_required
def messages_trash():
    user_id = session['user_id']
    is_tor = is_tor_request(request)
    gpg, gpg_error = init_gpg_for_tor()
    key_info = get_user_private_key_and_passphrase(user_id)
    if not key_info.get('has_private_key'):
        return render_template('user/messages.html', active_tab='trash', has_private_key=False, is_tor=is_tor, gpg_error=(gpg_error and gpg_error != "fallback"))
    if gpg:
        gpg.import_keys(key_info['private_key'])
    data = fetch_trash(user_id, gpg, key_info['passphrase'])
    return render_template('user/messages.html', active_tab='trash', has_private_key=True, is_tor=is_tor, gpg_error=(gpg_error and gpg_error != "fallback"), **data)

@user_bp.route('/messages/invitations')
@login_required
def messages_invitations():
    user_id = session['user_id']
    # Invitations may not require PGP
    data = fetch_invitations(user_id)
    return render_template('user/messages.html', active_tab='invitations', has_private_key=True, **data)

@user_bp.route('/messages/trash/<int:message_id>', methods=['POST'])
@login_required
def move_message_to_trash(message_id):
    user_id = session['user_id']
    with get_db_connection() as conn:
        c = conn.cursor()
        # Only allow if user is sender or recipient
        c.execute("SELECT * FROM messages WHERE id = ? AND (? = sender_id OR ? = recipient_id)", (message_id, user_id, user_id))
        msg = c.fetchone()
        if not msg:
            flash("Message not found or access denied.", 'error')
            return redirect(url_for('user.trash'))
        c.execute("UPDATE messages SET trashed = 1 WHERE id = ?", (message_id,))
        conn.commit()
        flash("Message moved to trash.", 'success')
    return redirect(url_for('user.trash'))

@user_bp.route('/messages/restore/<int:message_id>', methods=['POST'])
@login_required
def restore_message(message_id):
    user_id = session['user_id']
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM messages WHERE id = ? AND (? = sender_id OR ? = recipient_id)", (message_id, user_id, user_id))
        msg = c.fetchone()
        if not msg:
            flash("Message not found or access denied.", 'error')
            return redirect(url_for('user.trash'))
        c.execute("UPDATE messages SET trashed = 0 WHERE id = ?", (message_id,))
        conn.commit()
        flash("Message restored.", 'success')
    return redirect(url_for('user.trash'))

# --- Message Helpers ---
def get_user_private_key_and_passphrase(user_id):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT pgp_private_key FROM users WHERE id = ?", (user_id,))
        private_key_encrypted = c.fetchone()['pgp_private_key']
        if not private_key_encrypted:
            return {'has_private_key': False}
        decrypted_data = cipher.decrypt(private_key_encrypted).decode().split('||')
        return {'has_private_key': True, 'private_key': decrypted_data[0], 'passphrase': decrypted_data[1]}

def fetch_conversations(user_id, gpg, passphrase):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT DISTINCT 
                CASE WHEN m.sender_id = ? THEN m.recipient_id ELSE m.sender_id END as recipient_id,
                CASE WHEN m.sender_id = ? THEN r.pusername ELSE s.pusername END as recipient_name,
                MAX(m.created_at) as last_message_time,
                (SELECT content FROM messages m2 
                 WHERE (m2.sender_id = m.sender_id AND m2.recipient_id = m.recipient_id) 
                    OR (m2.sender_id = m.recipient_id AND m2.recipient_id = m.sender_id)
                 ORDER BY m2.created_at DESC LIMIT 1) as last_message_encrypted
            FROM messages m
            LEFT JOIN users s ON s.id = m.sender_id
            LEFT JOIN users r ON r.id = m.recipient_id
            WHERE ? IN (m.sender_id, m.recipient_id)
            GROUP BY recipient_id, recipient_name, s.pusername, r.pusername
            ORDER BY last_message_time DESC
        """, (user_id, user_id, user_id))
        conversations_raw = [dict(row) for row in c.fetchall()]
        conversations = []
        for convo in conversations_raw:
            if convo['last_message_encrypted']:
                if gpg:
                    try:
                        decrypted = gpg.decrypt(convo['last_message_encrypted'], passphrase=passphrase)
                        convo['last_message'] = str(decrypted) if decrypted and decrypted.ok else "[Decryption Failed]"
                    except Exception:
                        convo['last_message'] = "[Decryption Failed]"
                else:
                    convo['last_message'] = "[Encrypted - GPG Unavailable]"
            else:
                convo['last_message'] = "Start a conversation"
            conversations.append(convo)
        return {'conversations': conversations}

def fetch_order_messages(user_id, gpg, passphrase):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT m.*, s.pusername as sender_name, r.pusername as recipient_name, o.id as order_id
            FROM messages m
            LEFT JOIN users s ON s.id = m.sender_id
            LEFT JOIN users r ON r.id = m.recipient_id
            JOIN orders o ON (m.sender_id = o.user_id OR m.recipient_id = o.user_id)
            WHERE ? IN (m.sender_id, m.recipient_id)
            ORDER BY m.created_at DESC
        """, (user_id,))
        messages_raw = [dict(row) for row in c.fetchall()]
        messages = []
        for msg in messages_raw:
            if msg.get('content'):
                if gpg:
                    try:
                        decrypted = gpg.decrypt(msg['content'], passphrase=passphrase)
                        msg['content'] = str(decrypted) if decrypted and decrypted.ok else "[Decryption Failed]"
                    except Exception:
                        msg['content'] = "[Decryption Failed]"
                else:
                    msg['content'] = "[Encrypted - GPG Unavailable]"
            else:
                msg['content'] = ""
            messages.append(msg)
        return {'order_messages': messages}

def fetch_trash(user_id, gpg, passphrase):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT m.*, s.pusername as sender_name, r.pusername as recipient_name
            FROM messages m
            LEFT JOIN users s ON s.id = m.sender_id
            LEFT JOIN users r ON r.id = m.recipient_id
            WHERE (m.sender_id = ? OR m.recipient_id = ?) AND m.trashed = 1
            ORDER BY m.created_at DESC
        """, (user_id, user_id))
        messages_raw = [dict(row) for row in c.fetchall()]
        messages = []
        for msg in messages_raw:
            if msg.get('content'):
                if gpg:
                    try:
                        decrypted = gpg.decrypt(msg['content'], passphrase=passphrase)
                        msg['content'] = str(decrypted) if decrypted and decrypted.ok else "[Decryption Failed]"
                    except Exception:
                        msg['content'] = "[Decryption Failed]"
                else:
                    msg['content'] = "[Encrypted - GPG Unavailable]"
            else:
                msg['content'] = ""
            messages.append(msg)
        return {'trash': messages}

def fetch_invitations(user_id):
    # Placeholder: implement invitation logic as needed
    return {'invitations': []}

@user_bp.route('/notifications')
@login_required
def notifications():
    user_id = session['user_id']
    notifications = get_user_notifications(user_id, unread_only=False, limit=20)
    return render_template('user/notifications.html', notifications=notifications)

@user_bp.route('/notifications/read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification(notification_id):
    user_id = session['user_id']
    mark_notification_read(notification_id, user_id)
    return ('', 204)

# Route to serve CAPTCHA image
@user_bp.route('/captcha_image')
def captcha_image():
    return serve_captcha_image()

# Route to refresh CAPTCHA via AJAX
@user_bp.route('/captcha_refresh')
def captcha_refresh():
    """Refresh CAPTCHA and return new image URL."""
    try:
        # Generate new CAPTCHA
        code = generate_captcha_code()
        set_captcha_code(code)
        return jsonify({'success': True, 'url': url_for('user.captcha_image') + '?' + str(int(time.time()))})
    except Exception as e:
        logging.error(f"Failed to refresh CAPTCHA: {e}")
        return jsonify({'success': False, 'error': 'Failed to refresh CAPTCHA'}), 500


