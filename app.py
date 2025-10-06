from flask import Flask, request, abort, session, url_for, flash, render_template, redirect, g
from werkzeug.middleware.proxy_fix import ProxyFix
from config import Config
from routes import init_routes
from utils.crypto import get_exchange_rates
from utils.database import init_db, get_db_connection, get_settings, get_product_rating, get_profile_data, get_product_count,close_db, get_rates, update_rates, get_user_profile_data, send_notification_with_email
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
#from utils.security import generate_csrf_token
from flask_limiter import Limiter
from flask_wtf.csrf import CSRFProtect
import redis
import logging
import sqlite3
from utils.news import get_latest_news
from utils.categories import get_categories_with_counts
from routes import init_routes
from flask_session import Session
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
import os
from dotenv import load_dotenv
from utils.ddos_protection import init_ddos_protection, check_ddos_protection, require_recaptcha
from utils.bitcoin import check_payment
from utils.monero import check_monero_payment

# Load environment variables from .env file
load_dotenv()
app = Flask(__name__)
app.jinja_env.add_extension('jinja2.ext.do')
app.config.from_object(Config)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
# Configure session with Redis fallback
app.config['SECRET_KEY'] = Config.SECRET_KEY

# Ensure session configuration is set before CSRF initialization
app.config['SESSION_COOKIE_SECURE'] = False  # Set to False for development
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_DOMAIN'] = None  # Allow all domains for development

# Tor-specific session configuration
app.config['SESSION_COOKIE_PATH'] = '/'
app.config['SESSION_COOKIE_NAME'] = 'marketplace_session'
app.config['SESSION_REFRESH_EACH_REQUEST'] = True

# Try to use Redis for sessions, fallback to filesystem if Redis is unavailable
try:
    redis_client = redis.Redis(
        host=os.getenv('REDIS_HOST', 'localhost'),
        port=int(os.getenv('REDIS_PORT', 6379)),
        password=os.getenv('REDIS_PASSWORD', None),
        socket_connect_timeout=5,
        socket_timeout=5
    )
    # Test Redis connection
    redis_client.ping()
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SESSION_REDIS'] = redis_client
    print("Using Redis for session storage")
except Exception as e:
    print(f"Redis not available, using filesystem sessions: {e}")
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_FILE_DIR'] = '/tmp/flask_sessions'
    # Create session directory if it doesn't exist
    os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)

Session(app)

# Upload folder for categories
app.config['UPLOAD_FOLDER'] = 'static/uploads/categories'
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)    
# @app.before_request
# def enforce_tor():
#    if not request.headers.get('X-Forwarded-For', '').endswith('.onion'):
#        abort(403, "Access restricted to Tor network")

# Initialize LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'user.login'  # type: ignore
# Initialize Bcrypt
bcrypt = Bcrypt(app)
# User model
from flask_login import UserMixin

class User(UserMixin):
    def __init__(self, id, username, pusername, pin, password, role, active, registered_at, btc_address, avatar, login_phrase, status, session_timeout, profile_visibility, is_vendor, notify_messages, notify_orders, pgp_public_key, pgp_private_key, vendor_status, two_factor_secret, mnemonic_hash, created_at, last_login, jabber, description, currencyid, stealth, multisig, refund, canbuy, pinbuy, phis, menu_follow, feedback, tocountryid, countryid, discardww):
        self.id = id
        self.username = username
        self.pusername = pusername
        self.pin = pin
        self.password = password
        self.role = role
        self.active = active
        self.registered_at = registered_at
        self.btc_address = btc_address
        self.avatar = avatar
        self.login_phrase = login_phrase
        self.status = status
        self.session_timeout = session_timeout
        self.profile_visibility = profile_visibility
        self.is_vendor = is_vendor
        self.notify_messages = notify_messages
        self.notify_orders = notify_orders
        self.pgp_public_key = pgp_public_key
        self.pgp_private_key = pgp_private_key
        self.vendor_status = vendor_status
        self.two_factor_secret = two_factor_secret
        self.mnemonic_hash = mnemonic_hash
        self.created_at = created_at
        self.last_login = last_login
        self.jabber = jabber
        self.description = description
        self.currencyid = currencyid
        self.stealth = stealth
        self.multisig = multisig
        self.refund = refund
        self.canbuy = canbuy
        self.pinbuy = pinbuy
        self.phis = phis
        self.menu_follow = menu_follow
        self.feedback = feedback
        self.tocountryid = tocountryid
        self.countryid = countryid
        self.discardww = discardww

    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT id, username, pusername, pin, password, role, active, registered_at,
                   btc_address, avatar, login_phrase, status, session_timeout, profile_visibility,
                   is_vendor, notify_messages, notify_orders, pgp_public_key, pgp_private_key,
                   vendor_status, two_factor_secret, mnemonic_hash, created_at, last_login,
                   jabber, description, currencyid, stealth, multisig, refund, canbuy, pinbuy,
                   phis, menu_follow, feedback, tocountryid, countryid, discardww
            FROM users WHERE id = ?
        """, (user_id,))
        user_data = c.fetchone()
        if user_data:
            return User(*user_data)
    return None
   
@app.after_request
def add_security_headers(response):
    # Use security headers from config
    from config import Config
    config = Config()
    for header, value in config.SECURITY_HEADERS.items():
        response.headers[header] = value
    return response

# Add basename filter
@app.template_filter('basename')
def basename_filter(path):
    return os.path.basename(path) if path else ''
        
# Initialize rate limiter - TEMPORARILY DISABLED FOR TESTING
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",  # Use redis:// in production for persistence
    default_limits=["100000 per day", "50000 per hour"]  # Temporarily increased for testing
)
# Define background jobs before scheduler setup

def monitor_btc_deposits():
    from utils.bitcoin import check_payment
    import logging
    
    logger = logging.getLogger(__name__)
    
    try:
        settings = get_settings()
        min_btc = float(settings.get('btc_min_deposit', 0.0001))
        min_conf = int(settings.get('btc_min_confirmations', 2))
        
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT user_id, btc_address FROM user_crypto_addresses WHERE btc_address IS NOT NULL")
            
            for row in c.fetchall():
                try:
                    user_id, btc_address = row['user_id'], row['btc_address']
                    # Check for new payment with min confirmations and amount
                    txid = check_payment(btc_address, min_btc)
                    if txid:
                        # Check if already credited
                        c.execute("SELECT 1 FROM transactions WHERE tx_id = ? AND type = 'deposit'", (txid,))
                        if not c.fetchone():
                            # Credit user balance
                            c.execute("UPDATE users SET btc_balance = btc_balance + ? WHERE id = ?", (min_btc, user_id))
                            c.execute("INSERT INTO transactions (user_id, currency, type, amount, address, tx_id, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)", (user_id, 'BTC', 'deposit', min_btc, btc_address, txid, 'completed'))
                            c.execute("INSERT INTO notifications (user_id, message, type) VALUES (?, ?, ?)", (user_id, f'BTC deposit of {min_btc} credited to your wallet.', 'success'))
                            conn.commit()
                            logger.info(f"BTC deposit of {min_btc} credited to user {user_id}")
                except Exception as e:
                    logger.error(f"Error processing BTC deposit for user {row.get('user_id', 'unknown')}: {str(e)}")
                    continue
    except Exception as e:
        logger.error(f"Error in monitor_btc_deposits: {str(e)}")

def monitor_xmr_deposits():
    from utils.monero import check_monero_payment
    import logging
    
    logger = logging.getLogger(__name__)
    
    try:
        settings = get_settings()
        min_xmr = float(settings.get('xmr_min_deposit', 0.01))
        min_conf = int(settings.get('xmr_min_confirmations', 10))
        
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT user_id, xmr_subaddress FROM user_crypto_addresses WHERE xmr_subaddress IS NOT NULL")
            
            for row in c.fetchall():
                try:
                    user_id, xmr_address = row['user_id'], row['xmr_subaddress']
                    # Check for new payment with min confirmations and amount
                    tx_hash = check_monero_payment(xmr_address, min_xmr, min_conf)
                    if tx_hash:
                        # Check if already credited
                        c.execute("SELECT 1 FROM transactions WHERE tx_id = ? AND type = 'deposit'", (tx_hash,))
                        if not c.fetchone():
                            # Credit user balance
                            c.execute("UPDATE users SET xmr_balance = xmr_balance + ? WHERE id = ?", (min_xmr, user_id))
                            c.execute("INSERT INTO transactions (user_id, currency, type, amount, address, tx_id, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)", (user_id, 'XMR', 'deposit', min_xmr, xmr_address, tx_hash, 'completed'))
                            c.execute("INSERT INTO notifications (user_id, message, type) VALUES (?, ?, ?)", (user_id, f'XMR deposit of {min_xmr} credited to your wallet.', 'success'))
                            conn.commit()
                            logger.info(f"XMR deposit of {min_xmr} credited to user {user_id}")
                except Exception as e:
                    logger.error(f"Error processing XMR deposit for user {row.get('user_id', 'unknown')}: {str(e)}")
                    continue
    except Exception as e:
        logger.error(f"Error in monitor_xmr_deposits: {str(e)}")

def monitor_order_payments():
    from utils.bitcoin import check_payment
    from utils.monero import check_monero_payment
    from utils.database import send_notification_with_email
    import logging
    
    logger = logging.getLogger(__name__)
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT o.id, o.user_id, o.product_id, e.crypto_currency, e.multisig_address, e.escrow_address, e.amount_btc, e.amount_xmr FROM orders o JOIN escrow e ON o.id = e.order_id WHERE o.status = 'pending' AND o.escrow_status = 'pending'")
            
            for row in c.fetchall():
                try:
                    order_id = row['id']
                    user_id = row['user_id']
                    product_id = row['product_id']
                    currency = row['crypto_currency']
                    address = row['multisig_address'] or row.get('escrow_address')
                    
                    if currency == 'BTC':
                        try:
                            txid = check_payment(address, row['amount_btc'])
                            amount = row['amount_btc']
                        except Exception as e:
                            logger.error(f"Error checking BTC payment for order {order_id}: {str(e)}")
                            continue
                    elif currency == 'XMR':
                        try:
                            txid = check_monero_payment(address, row.get('amount_xmr', 0))
                            amount = row.get('amount_xmr', 0)
                        except Exception as e:
                            logger.error(f"Error checking XMR payment for order {order_id}: {str(e)}")
                            continue
                    else:
                        txid = None
                        amount = 0
                    
                    if txid:
                        c.execute("UPDATE orders SET status = 'paid', escrow_status = 'held' WHERE id = ?", (order_id,))
                        c.execute("UPDATE escrow SET status = 'held', txid = ?, created_at = CURRENT_TIMESTAMP WHERE order_id = ?", (txid, order_id))
                        # Notify user
                        send_notification_with_email(user_id, f'Payment of {amount} {currency} received for your order #{order_id}. Order is now in escrow.', 'success', subject='Order Payment Received')
                        # Notify admin (assume admin user_id = 1)
                        send_notification_with_email(1, f'Order #{order_id} payment detected: {amount} {currency}. Escrow held.', 'info', subject='Order Payment Detected')
                        # Optionally, notify vendor as well
                        c.execute("SELECT vendor_id FROM products WHERE id = ?", (product_id,))
                        vendor = c.fetchone()
                        if vendor:
                            send_notification_with_email(vendor['vendor_id'], f'Order #{order_id} for your product has been paid and is now in escrow.', 'info', subject='Order Paid and Escrowed')
                        conn.commit()
                        logger.info(f"Order {order_id} payment confirmed and escrow held. Notifications sent.")
                except Exception as e:
                    logger.error(f"Error processing order {row.get('id', 'unknown')}: {str(e)}")
                    continue
    except Exception as e:
        logger.error(f"Error in monitor_order_payments: {str(e)}")

# Initialize scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(func=update_rates, trigger='interval', minutes=10)
scheduler.add_job(func=monitor_btc_deposits, trigger='interval', minutes=5)
scheduler.add_job(func=monitor_xmr_deposits, trigger='interval', minutes=5)
scheduler.add_job(func=monitor_order_payments, trigger='interval', minutes=2)
scheduler.start()

# Shutdown scheduler on app exit
atexit.register(lambda: scheduler.shutdown())

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize CSRF protection
csrf = CSRFProtect(app)
logger.debug("CSRFProtect initialized")

# Configure CSRF protection
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour
app.config['WTF_CSRF_SSL_STRICT'] = False  # Allow HTTP for development
app.config['WTF_CSRF_CHECK_DEFAULT'] = False  # Disable automatic checking

# Tor-specific CSRF configuration
app.config['WTF_CSRF_HEADERS'] = ['X-CSRFToken']
app.config['WTF_CSRF_SSL_STRICT'] = False
app.config['WTF_CSRF_TIME_LIMIT'] = None  # No time limit for Tor

# Ensure CSRF is properly configured
logger.debug(f"CSRF enabled: {app.config.get('WTF_CSRF_ENABLED')}")
logger.debug(f"Secret key configured: {bool(app.config.get('SECRET_KEY'))}")

# Ensure session is properly initialized for CSRF
@app.before_request
def ensure_session():
    # Check if request is coming from Tor
    is_tor_request = request.headers.get('X-Forwarded-For', '').endswith('.onion') or \
                    request.headers.get('Host', '').endswith('.onion') or \
                    '.onion' in request.headers.get('Host', '')
    
    # Ensure session is properly configured
    if not session.get('_id'):
        session['_id'] = 'session_initialized'
        session.modified = True
        
    # Set session as permanent for CSRF
    session.permanent = True
    
    # Ensure session is saved
    if session.modified:
        session.modified = True
        
    # Debug session for CSRF issues
    if request.endpoint and 'login' in request.endpoint:
        logger.debug(f"Session data: {dict(session)}")
        logger.debug(f"Session modified: {session.modified}")
        logger.debug(f"Session ID: {session.get('_id', 'No session ID')}")
        logger.debug(f"Tor request: {is_tor_request}")
        
        # Test CSRF token generation
        from flask_wtf.csrf import generate_csrf
        try:
            token = generate_csrf()
            logger.debug(f"CSRF token generated in before_request: {token[:20]}...")
        except Exception as e:
            logger.error(f"Error generating CSRF token in before_request: {e}")
        
    # Ensure session is properly configured for CSRF
    if not session.get('_csrf_token'):
        session['_csrf_token'] = 'csrf_token_initialized'
        session.modified = True




logging.basicConfig(level=logging.INFO, filename='app.log', format='%(asctime)s %(levelname)s: %(message)s')
# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(429)
def rate_limit_exceeded(e):
    return render_template('429.html'), 429

@app.errorhandler(400)
def bad_request(e):
    if 'CSRF' in str(e):
        logger.error(f"CSRF error: {e}")
        flash("CSRF token validation failed. Please try refreshing the page.", 'error')
        return redirect(url_for('user.login'))
    return render_template('error.html', message=str(e)), 400

@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"Internal Server Error: {e}")
    logger.error(f"Request URL: {request.url}")
    logger.error(f"Request Method: {request.method}")
    logger.error(f"User Agent: {request.headers.get('User-Agent', 'Unknown')}")
    logger.error(f"Remote Addr: {request.remote_addr}")
    logger.error(f"X-Forwarded-For: {request.headers.get('X-Forwarded-For', 'None')}")
    
    # Check if this is a Tor request
    is_tor = request.headers.get('X-Forwarded-For', '').endswith('.onion') or '.onion' in request.headers.get('Host', '')
    if is_tor:
        logger.error("Error occurred on Tor network")
    
    return render_template('error.html', message="An internal server error occurred. Please try again later."), 500

# Initialize database and routes
init_db()
init_routes(app)

# Initialize DDoS protection with Redis fallback
try:
    redis_client = redis.Redis(
        host=os.getenv('REDIS_HOST', 'localhost'),
        port=int(os.getenv('REDIS_PORT', 6379)),
        password=os.getenv('REDIS_PASSWORD', None),
        socket_connect_timeout=5,
        socket_timeout=5
    )
    # Test Redis connection
    redis_client.ping()
    init_ddos_protection(redis_client)
    print("DDoS protection initialized with Redis")
except Exception as e:
    print(f"DDoS protection not available - Redis connection failed: {e}")
    # Initialize DDoS protection with None to disable it
    from utils.ddos_protection import ddos_protection, recaptcha
    ddos_protection = None
    recaptcha = None
# Before request: Store rates in g
@app.before_request
def before_request():
    g.rates = get_rates()
    
    # Apply DDoS protection to all requests - TEMPORARILY DISABLED FOR TESTING
    from utils.ddos_protection import ddos_protection
    if ddos_protection and False:  # Temporarily disabled
        allowed, reason = ddos_protection.check_request()
        if not allowed:
            logger.warning(f"Request blocked: {reason}")
            abort(429, description=f"Rate limit exceeded: {reason}")
    
# After request: Close database
@app.teardown_appcontext
def teardown_db(exception):
    close_db()
    
# Remove server info from headers
@app.after_request
def remove_server_info(response):
    response.headers["Server"] = "Marketplace"
    response.headers["X-Powered-By"] = None
    return response


# Inject settings into all templates
@app.context_processor
def inject_settings():
    return {'settings': get_settings()}

# Inject CSRF token globally
@app.context_processor
def inject_csrf_token():
    from flask_wtf.csrf import generate_csrf
    try:
        token = generate_csrf()
        logger.debug(f"CSRF token generated in context processor: {token[:20]}...")
        return {'csrf_token': generate_csrf}
    except Exception as e:
        logger.error(f"Error generating CSRF token in context processor: {e}")
        return {'csrf_token': lambda: 'error'}

@app.context_processor
def inject_globals():
    categories = get_categories_with_counts()
    user_id = session.get('user_id')
    profile_data, error = get_user_profile_data(user_id) if user_id else (None, None)
    if error:
        flash(error, 'error')
    
    if not profile_data:
        # Provide a default structure for guests or if the user is not found
        profile_data = {
            'pusername': 'Guest',
            'avatar': None,
            'btc_balance': 0.0,
            'xmr_balance': 0.0,
            'role': 'guest'
        }
    rates = get_rates()
    logger.info(f"Injected categories: {categories}")
    return {
        'news_articles': get_latest_news(limit=10),
        'categories': categories,
        'profile_data': profile_data,
        'rates': rates
    }

# Define custom Jinja2 filter for currency formatting
def format_currency(value):
    """Format a number as currency with commas and two decimal places."""
    try:
        return "{:,.2f}".format(float(value))
    except (ValueError, TypeError):
        logger.error("Invalid value for format_currency: %s", value)
        return str(value)

app.jinja_env.filters['format_currency'] = format_currency

# Temporary route to clear session
@app.route('/clear-session')
def clear_session():
    """Clear the current session and start a new one."""
    logger.debug(f"Clearing session: {session}")
    session.clear()  # Clear all session data
    session.modified = True  # Ensure session is updated
    logger.debug("Session cleared, new session started")
    return redirect(url_for('user.login'))

@app.route('/debug-session')
def debug_session():
    """Debug session information."""
    return {
        'session_data': dict(session),
        'session_id': session.get('_id', 'No session ID'),
        'session_modified': session.modified,
        'secret_key_configured': bool(app.config.get('SECRET_KEY')),
        'csrf_enabled': app.config.get('WTF_CSRF_ENABLED', False)
    }

@app.route('/exchange')
def exchange():
    """Display cryptocurrency exchange rates."""
    rates = get_exchange_rates()
    if not rates:
        logger.error("Exchange rates unavailable")
        return render_template('error.html', message="Unable to fetch exchange rates"), 500
    return render_template('exchange.html', rates=rates)

@app.route('/test-csrf')
def test_csrf():
    """Test CSRF token generation."""
    from flask_wtf.csrf import generate_csrf
    token = generate_csrf()
    return {
        'csrf_token': token,
        'session_id': session.get('_id', 'No session ID'),
        'secret_key_configured': bool(app.config.get('SECRET_KEY')),
        'csrf_enabled': app.config.get('WTF_CSRF_ENABLED', False),
        'session_data': dict(session),
        'session_modified': session.modified,
        'session_permanent': session.permanent
    }


# Add global Jinja functions (once)
def get_sponsored_ads(placement_type, limit=3):
    """Get sponsored ads for a specific placement type"""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT sa.*, p.title, p.description, p.price_usd, p.featured_image,
                       u.pusername as vendor_name
                FROM sponsored_ads sa
                JOIN products p ON sa.product_id = p.id
                JOIN users u ON sa.vendor_id = u.id
                WHERE sa.placement_type = ? AND sa.status = 'active'
                AND p.status = 'active' AND p.stock > 0
                ORDER BY sa.bid_amount DESC
                LIMIT ?
            """, (placement_type, limit))
            
            ads = [dict(row) for row in c.fetchall()]
            
            # Record impressions for each ad
            for ad in ads:
                c.execute("""
                    INSERT OR REPLACE INTO ad_impressions (ad_id, product_id, impression_count, date)
                    VALUES (?, ?, 
                        COALESCE((SELECT impression_count FROM ad_impressions 
                                 WHERE ad_id = ? AND date = CURRENT_DATE), 0) + 1,
                        CURRENT_DATE)
                """, (ad['id'], ad['product_id'], ad['id']))
            
            conn.commit()
            return ads
    except Exception as e:
        logger.error(f"Error getting sponsored ads: {str(e)}")
        return []

app.jinja_env.globals.update(
    get_product_rating=get_product_rating,
    get_product_count=get_product_count,
    get_sponsored_ads=get_sponsored_ads
)

@app.context_processor
def inject_user_notifications():
    if 'user_id' in session:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0", (session['user_id'],))
            unread_count = c.fetchone()[0]
            c.execute("SELECT message, type, created_at FROM notifications WHERE user_id = ? AND is_read = 0 ORDER BY created_at DESC LIMIT 5", (session['user_id'],))
            unread_notifications = [dict(row) for row in c.fetchall()]
            
            # Get favorites count
            c.execute("SELECT COUNT(*) as count FROM favorites WHERE user_id = ?", (session['user_id'],))
            favorite_products_count = c.fetchone()['count']
            
            c.execute("SELECT COUNT(*) as count FROM favorite_vendors WHERE user_id = ?", (session['user_id'],))
            favorite_vendors_count = c.fetchone()['count']
            
            total_favorites_count = favorite_products_count + favorite_vendors_count
            
        return dict(
            unread_notifications=unread_notifications, 
            unread_notification_count=unread_count,
            favorites_count=total_favorites_count
        )
    return dict(unread_notifications=[], unread_notification_count=0, favorites_count=0)

if __name__ == '__main__':
    update_rates()
    app.run(debug=True)
    app.run(host='127.0.0.1', port=5000, debug=True)