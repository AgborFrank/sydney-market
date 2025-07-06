from utils.database import get_db_connection
from flask import session, redirect, url_for, flash
from flask_login import login_required

def has_active_subscription(user_id):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT * FROM vendor_subscriptions 
            WHERE vendor_id = ? AND status = 'active'
        """, (user_id,))
        return c.fetchone() is not None

def require_vendor_role(func):
    """Decorator to require vendor role for access"""
    def wrapper(*args, **kwargs):
        if 'role' not in session or session['role'] != 'vendor':
            flash("You must be a vendor to access this page.", 'error')
            return redirect(url_for('user.dashboard'))
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper