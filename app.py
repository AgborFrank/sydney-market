from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix
from config import Config
from routes import init_routes
from utils.database import init_db, get_db_connection, get_settings, get_product_rating, get_product_count
from utils.security import generate_csrf_token
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()
app = Flask(__name__)
app.config.from_object(Config)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
app.secret_key = Config.SECRET_KEY  # Ensure this is static in production (e.g., from env)

# Upload folder for categories
app.config['UPLOAD_FOLDER'] = 'static/uploads/categories'
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",  # Use redis:// in production for persistence
    default_limits=["100 per day", "50 per hour"]  # Increased hourly default
)

# Initialize database and routes
init_db()
init_routes(app)

# Remove server info from headers
@app.after_request
def remove_server_info(response):
    response.headers["Server"] = "Marketplace"
    response.headers["X-Powered-By"] = None
    return response

# Inject CSRF token into all templates
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf_token())

# Inject category tree into all templates
@app.context_processor
def inject_categories():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM categories")
        categories = c.fetchall()
    category_tree = {cat['id']: dict(cat, subcategories=[]) for cat in categories}
    for cat in categories:
        if cat['parent_id']:
            category_tree[cat['parent_id']]['subcategories'].append(category_tree[cat['id']])
    top_level_categories = [cat for cat in category_tree.values() if not cat['parent_id']]
    return dict(top_level_categories=top_level_categories)

# Inject settings into all templates
@app.context_processor
def inject_settings():
    return {'settings': get_settings()}

# Add global Jinja functions (once)
app.jinja_env.globals.update(
    get_product_rating=get_product_rating,
    get_product_count=get_product_count
)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)