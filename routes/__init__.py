from flask import session, redirect, url_for
from functools import wraps

def require_role(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] != role:
                return redirect(url_for('user.login'))  # Redirect to login if role mismatch
            return f(*args, **kwargs)
        return decorated_function
    return decorator

from .user import user_bp
from .vendor import vendor_bp
from .admin import admin_bp
from .public import public_bp
from .forum import forum_bp
from .cart import cart_bp
from .wallet import wallet_bp

def init_routes(app):
    app.register_blueprint(public_bp)
    app.register_blueprint(user_bp, url_prefix='/user')
    app.register_blueprint(vendor_bp, url_prefix='/vendor')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(forum_bp, url_prefix='/forum')
    app.register_blueprint(cart_bp, url_prefix='/cart')
    app.register_blueprint(wallet_bp, url_prefix='/wallet')