from flask import Flask, request, abort, session, url_for, flash, render_template, redirect, g
from werkzeug.middleware.proxy_fix import ProxyFix
from config import Config
from routes import init_routes
from utils.crypto import get_exchange_rates
from utils.database import init_db, get_db_connection, get_settings, get_product_rating, get_profile_data, get_product_count,close_db, get_rates, update_rates, get_user_profile_data
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

# Load environment variables from .env file
load_dotenv()
app = Flask(__name__)
app.jinja_env.add_extension('jinja2.ext.do')
app.config.from_object(Config)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
app.secret_key = Config.SECRET_KEY  # Ensure this is static in production (e.g., from env)

# Configure session
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(32))
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = redis.Redis(
    host=os.getenv('REDIS_HOST', 'localhost'),
    port=os.getenv('REDIS_PORT', 6379),
    password=os.getenv('REDIS_PASSWORD', None)
)
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
login_manager.login_view = 'user.login'
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
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'none'"
    return response

# Add basename filter
@app.template_filter('basename')
def basename_filter(path):
    return os.path.basename(path) if path else ''
        
# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",  # Use redis:// in production for persistence
    default_limits=["100 per day", "50 per hour"]  # Increased hourly default
)
# Initialize scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(func=update_rates, trigger='interval', minutes=10)
scheduler.start()

# Shutdown scheduler on app exit
atexit.register(lambda: scheduler.shutdown())

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize CSRF protection
csrf = CSRFProtect(app)
logger.debug("CSRFProtect initialized")
logging.basicConfig(level=logging.INFO, filename='app.log', format='%(asctime)s %(levelname)s: %(message)s')
# Example error handler
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Initialize database and routes
init_db()
init_routes(app)
# Before request: Store rates in g
@app.before_request
def before_request():
    g.rates = get_rates()
    
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

def get_id(self):
        return str(self.id)
# Temporary route to clear session
@app.route('/clear-session')
def clear_session():
    """Clear the current session and start a new one."""
    logger.debug(f"Clearing session: {session}")
    session.clear()  # Clear all session data
    session.modified = True  # Ensure session is updated
    logger.debug("Session cleared, new session started")
    return redirect(url_for('user.login'))

@app.route('/exchange')
def exchange():
    """Display cryptocurrency exchange rates."""
    rates = get_exchange_rates()
    if not rates:
        logger.error("Exchange rates unavailable")
        return render_template('error.html', message="Unable to fetch exchange rates"), 500
    return render_template('exchange.html', rates=rates)


# Add global Jinja functions (once)
app.jinja_env.globals.update(
    get_product_rating=get_product_rating,
    get_product_count=get_product_count
)


if __name__ == '__main__':
    update_rates()
    app.run(debug=True)
    app.run(host='127.0.0.1', port=5000, debug=True)