from flask import Blueprint, request, flash, redirect, url_for, render_template, session, send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_session import Session
from flask_limiter.util import get_remote_address
from utils.database import get_db_connection, get_settings, create_test_admin_and_news, log_wallet_change  # Absolute import from utils.database
from utils.crypto import get_btc_price, get_xmr_price
import os
import logging
import re
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from flask_login import login_required, current_user, login_user
import atexit
import secrets
import sqlite3
from utils.ddos_protection import ddos_protection
from flask_wtf.csrf import generate_csrf
from utils.security import log_admin_action_encrypted

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')
logger = logging.getLogger(__name__)

@admin_bp.context_processor
def inject_csrf_token():
    return {'csrf_token': generate_csrf}

@admin_bp.context_processor
def inject_settings():
    return {'settings': get_settings()}

# Directory for category images
UPLOAD_FOLDER = 'static/uploads/categories'
UPLOAD_FOLDER_LOGOS = 'static/uploads/logos'
UPLOAD_FOLDER_CATEGORIES = 'static/uploads/categories'
UPLOAD_FOLDER_PRODUCTS = 'static/uploads/products'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 2 * 1024 * 1024 #2MB

# Ensure upload folders exist
for folder in [UPLOAD_FOLDER_CATEGORIES, UPLOAD_FOLDER, UPLOAD_FOLDER_PRODUCTS, UPLOAD_FOLDER_LOGOS]:
    if not os.path.exists(folder):
        os.makedirs(folder)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def require_admin_role(func):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash("You must be an admin to access this page.", 'error')
            return redirect(url_for('admin.login'))
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

def is_admin():
    if not session.get('user_id'):
        return False
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT role FROM users WHERE id = ?", (session['user_id'],))
            user = c.fetchone()
            return user and user['role'] == 'admin'
    except Exception as e:
        logger.error(f"Error checking admin status: {str(e)}")
        return False

#@admin_bp.before_request
#def restrict_admin():
#    if not is_admin():
#        flash("Access denied. Admins only.", 'error')
#        return redirect(url_for('public.index'))

@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session and session.get('role') == 'admin':
        return redirect(url_for('admin.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        pin = request.form.get('pin', '').strip()
        
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username = ? AND role = 'admin'", (username,))
            admin = c.fetchone()
            
            if not admin:
                flash("Invalid username or not an admin.", 'error')
                return render_template('admin/login.html', step='username', error="Invalid username or not an admin.")
            
            admin = dict(admin)
            
            # Fetch admin_action_logging setting
            c.execute("SELECT value FROM security_settings WHERE setting_name = 'admin_action_logging'")
            admin_action_logging = c.fetchone()
            admin_action_logging = admin_action_logging['value'] if admin_action_logging else 'enabled'
            
            # Fetch admin's PGP public key
            pgp_pubkey = admin.get('pgp_public_key')
            
            if password and not pin:  # Step 1: Check password
                if not check_password_hash(admin['password'], password):
                    if admin_action_logging == 'enabled' and pgp_pubkey:
                        try:
                            log_admin_action_encrypted(f"Failed admin login (bad password) for {username}", username, pgp_pubkey)
                        except Exception as e:
                            logger.error(f"Failed to log encrypted admin action: {e}")
                    flash("Incorrect password.", 'error')
                    return render_template('admin/login.html', step='username', error="Incorrect password.")
                return render_template('admin/login.html', 
                                     step='pin', 
                                     username=username, 
                                     login_phrase=admin['login_phrase'])
            
            if pin:  # Step 2: Check PIN
                if pin != admin['pin']:
                    if admin_action_logging == 'enabled' and pgp_pubkey:
                        try:
                            log_admin_action_encrypted(f"Failed admin login (bad PIN) for {username}", username, pgp_pubkey)
                        except Exception as e:
                            logger.error(f"Failed to log encrypted admin action: {e}")
                    flash("Incorrect PIN.", 'error')
                    return render_template('admin/login.html', 
                                         step='pin', 
                                         username=username, 
                                         login_phrase=admin['login_phrase'], 
                                         error="Incorrect PIN.")
                session['user_id'] = admin['id']
                session['admin_id'] = admin['id']
                session['role'] = 'admin'
                flash("Logged in successfully.", 'success')
                if admin_action_logging == 'enabled' and pgp_pubkey:
                    try:
                        log_admin_action_encrypted(f"Admin {username} logged in successfully", username, pgp_pubkey)
                    except Exception as e:
                        logger.error(f"Failed to log encrypted admin action: {e}")
                return redirect(url_for('admin.dashboard'))
    
    return render_template('admin/login.html', step='username')

@admin_bp.route('/dashboard')
@require_admin_role
def dashboard():
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        
        # Total Users
        c.execute("SELECT COUNT(*) AS count FROM users")
        total_users = c.fetchone()['count']
        
        # Total Products
        c.execute("SELECT COUNT(*) AS count FROM products")
        total_products = c.fetchone()['count']
        
        # Total Orders
        c.execute("SELECT COUNT(*) AS count FROM orders")
        total_orders = c.fetchone()['count']
        
        # Total Sales (BTC, completed orders)
        c.execute("SELECT SUM(amount_btc) AS total FROM orders WHERE status = 'completed'")
        total_sales = c.fetchone()['total'] or 0.0
        
        # Recent Orders (limit 5)
        c.execute("""
            SELECT o.id, u.pusername AS user, p.title AS product, v.pusername AS vendor,
                   o.amount_btc, o.status, o.created_at
            FROM orders o
            JOIN users u ON o.user_id = u.id
            JOIN products p ON o.product_id = p.id
            JOIN users v ON o.vendor_id = v.id
            ORDER BY o.created_at DESC
            LIMIT 5
        """)
        recent_orders = [dict(row) for row in c.fetchall()]
        
        # Pending Disputes Count
        c.execute("SELECT COUNT(*) AS count FROM orders WHERE dispute_status = 'open'")
        pending_disputes_count = c.fetchone()['count']
        
        # Recent Withdrawals (limit 5)
        c.execute("""
            SELECT w.id, u.pusername AS user, w.amount_btc, w.status, w.requested_at
            FROM withdrawals w
            JOIN users u ON w.user_id = u.id
            ORDER BY w.requested_at DESC
            LIMIT 5
        """)
        recent_withdrawals = [dict(row) for row in c.fetchall()]
        
        # Total Escrow (BTC, pending)
        c.execute("SELECT SUM(amount_btc) AS total FROM escrow WHERE status = 'pending'")
        escrow_total_btc = c.fetchone()['total'] or 0.0
    
    return render_template('admin/dashboard.html',
        total_users=total_users,
        total_products=total_products,
        total_orders=total_orders,
        total_sales=total_sales,
        recent_orders=recent_orders,
        pending_disputes_count=pending_disputes_count,
        recent_withdrawals=recent_withdrawals,
        escrow_total_btc=escrow_total_btc
    )

@admin_bp.route('/vendor-settings', methods=['GET', 'POST'])
@require_admin_role
def admin_vendor_settings():
    admin_id = session['user_id']
    
    if request.method == 'POST':
        # Fetch all form data
        business_name = request.form.get('business_name', '').strip()
        description = request.form.get('description', '').strip()
        support_contact = request.form.get('support_contact', '').strip()
        min_order_amount = request.form.get('min_order_amount', '0.0').strip()
        warehouse_address = request.form.get('warehouse_address', '').strip()
        shipping_details = request.form.get('shipping_details', '').strip()
        processing_time = request.form.get('processing_time', '').strip()
        shipping_zones = request.form.get('shipping_zones', '').strip()
        shipping_location = request.form.get('shipping_location', '').strip()
        shipping_destinations = request.form.get('shipping_destinations', '').strip()
        shipping_policy = request.form.get('shipping_policy', '').strip()
        return_policy = request.form.get('return_policy', '').strip()
        rules = request.form.get('rules', '').strip()
        
        # Basic validation
        if not business_name or not shipping_zones or not shipping_location or not shipping_destinations:
            flash("Business name, shipping zones, shipping location, and shipping destinations are required.", 'error')
        else:
            try:
                # Convert min_order_amount to float, default to 0.0 if empty
                min_order_amount = float(min_order_amount) if min_order_amount else 0.0
                
                with get_db_connection() as conn:
                    c = conn.cursor()
                    # Debug: Print data before executing
                    print("Saving vendor settings:", admin_id, business_name, shipping_location, shipping_destinations)
                    c.execute("""
                        INSERT INTO vendor_settings (
                            user_id, business_name, description, support_contact, min_order_amount,
                            warehouse_address, shipping_details, processing_time, shipping_zones,
                            shipping_location, shipping_destinations, shipping_policy, return_policy, rules
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(user_id) DO UPDATE SET
                            business_name = excluded.business_name,
                            description = excluded.description,
                            support_contact = excluded.support_contact,
                            min_order_amount = excluded.min_order_amount,
                            warehouse_address = excluded.warehouse_address,
                            shipping_details = excluded.shipping_details,
                            processing_time = excluded.processing_time,
                            shipping_zones = excluded.shipping_zones,
                            shipping_location = excluded.shipping_location,
                            shipping_destinations = excluded.shipping_destinations,
                            shipping_policy = excluded.shipping_policy,
                            return_policy = excluded.return_policy,
                            rules = excluded.rules
                    """, (admin_id, business_name, description, support_contact, min_order_amount,
                          warehouse_address, shipping_details, processing_time, shipping_zones,
                          shipping_location, shipping_destinations, shipping_policy, return_policy, rules))
                    conn.commit()
                    flash("Vendor settings updated successfully!", 'success')
                    return redirect(url_for('admin.dashboard'))
            except ValueError:
                flash("Minimum order amount must be a valid number.", 'error')
            except Exception as e:
                flash(f"Error updating vendor settings: {str(e)}", 'error')
                print(f"Database error: {str(e)}")  # Debug output
    
    # Fetch existing settings
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT business_name, description, support_contact, min_order_amount,
                   warehouse_address, shipping_details, processing_time, shipping_zones,
                   shipping_location, shipping_destinations, shipping_policy, return_policy, rules
            FROM vendor_settings WHERE user_id = ?
        """, (admin_id,))
        settings = c.fetchone()
        settings = dict(settings) if settings else {
            'business_name': '', 'description': '', 'support_contact': '', 'min_order_amount': 0.0,
            'warehouse_address': '', 'shipping_details': '', 'processing_time': '', 'shipping_zones': '',
            'shipping_location': '', 'shipping_destinations': '', 'shipping_policy': '', 'return_policy': '', 'rules': ''
        }

    return render_template('admin/vendor_settings.html', settings=settings, title="Admin Vendor Settings")

@admin_bp.route('/categories', methods=['GET', 'POST'])
def manage_categories():
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('admin.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM categories ORDER BY name")
        categories = [dict(row) for row in c.fetchall()]
        
        if request.method == 'POST':
            category_name = request.form.get('category_name', '').strip()
            description = request.form.get('description', '').strip()
            parent_id = request.form.get('parent_id', None, type=int) or None
            image = request.files.get('image')
            
            if not category_name:
                flash("Category name is required.", 'error')
                return render_template('admin/categories.html', categories=categories, error="Category name is required.")
            
            image_path = None
            if image and allowed_file(image.filename):
                filename = secure_filename(image.filename)
                image_path = os.path.join('uploads/categories', filename).replace('\\', '/')  
                image.save(os.path.join(UPLOAD_FOLDER, filename))
            
            try:
                c.execute("""
                    INSERT INTO categories (name, description, parent_id, image_path)
                    VALUES (?, ?, ?, ?)
                """, (category_name, description or None, parent_id, image_path))
                conn.commit()
                flash("Category added successfully.", 'success')
            except sqlite3.IntegrityError:
                flash("Category name already exists.", 'error')
            
            return redirect(url_for('admin.manage_categories'))
    
    return render_template('admin/categories.html', categories=categories)

@admin_bp.route('/edit-category/<int:category_id>', methods=['GET', 'POST'])
def admin_edit_category(category_id):
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('admin.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM categories WHERE id = ?", (category_id,))
        edit_category = c.fetchone()
        if not edit_category:
            flash("Category not found.", 'error')
            return redirect(url_for('admin.manage_categories'))
        edit_category = dict(edit_category)
        
        c.execute("SELECT * FROM categories ORDER BY name")
        categories = [dict(row) for row in c.fetchall()]
        
        if request.method == 'POST':
            category_name = request.form.get('category_name', '').strip()
            description = request.form.get('description', '').strip()
            parent_id = request.form.get('parent_id', None, type=int) or None
            image = request.files.get('image')
            
            if not category_name:
                flash("Category name is required.", 'error')
                return render_template('admin/categories.html', categories=categories, edit_category=edit_category, error="Category name is required.")
            
            image_path = edit_category['image_path']
            if image and allowed_file(image.filename):
                filename = secure_filename(image.filename)
                image_path = os.path.join('uploads/categories', filename)
                image.save(os.path.join(UPLOAD_FOLDER, filename))
            
            if parent_id == category_id:
                parent_id = None
            
            c.execute("""
                UPDATE categories 
                SET name = ?, description = ?, parent_id = ?, image_path = ?
                WHERE id = ?
            """, (category_name, description or None, parent_id, image_path, category_id))
            conn.commit()
            flash("Category updated successfully.", 'success')
            return redirect(url_for('admin.manage_categories'))
    
    return render_template('admin/categories.html', categories=categories, edit_category=edit_category)

@admin_bp.route('/delete-category/<int:category_id>', methods=['POST'])
def admin_delete_category(category_id):
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('admin.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM categories WHERE id = ?", (category_id,))
        category = c.fetchone()
        if not category:
            flash("Category not found.", 'error')
            return redirect(url_for('admin.manage_categories'))
        
        c.execute("SELECT COUNT(*) FROM products WHERE category_id = ?", (category_id,))
        product_count = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM categories WHERE parent_id = ?", (category_id,))
        subcategory_count = c.fetchone()[0]
        
        if product_count > 0 or subcategory_count > 0:
            flash("Cannot delete category with products or subcategories.", 'error')
            return redirect(url_for('admin.manage_categories'))
        
        c.execute("DELETE FROM categories WHERE id = ?", (category_id,))
        conn.commit()
        flash("Category deleted successfully.", 'success')
    
    return redirect(url_for('admin.manage_categories'))

@admin_bp.route('/register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        pusername = request.form.get('pusername', '').strip()
        pin = request.form.get('pin', '').strip()
        login_phrase = request.form.get('login_phrase', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        # Validation
        if not all([username, pusername, pin, login_phrase, password, confirm_password]):
            flash("All fields are required.", 'error')
            return render_template('admin/register.html', error="All fields are required.")
        
        if len(username) < 3 or len(username) > 50:
            flash("Private username must be 3-50 characters.", 'error')
            return render_template('admin/register.html', error="Private username must be 3-50 characters.")
        
        if len(pusername) < 3 or len(pusername) > 50:
            flash("Public username must be 3-50 characters.", 'error')
            return render_template('admin/register.html', error="Public username must be 3-50 characters.")
        
        if len(pin) != 6 or not pin.isdigit():
            flash("PIN must be a 6-digit number.", 'error')
            return render_template('admin/register.html', error="PIN must be a 6-digit number.")
        
        if len(login_phrase) > 100:
            flash("Pass phrase must be under 100 characters.", 'error')
            return render_template('admin/register.html', error="Pass phrase must be under 100 characters.")
        
        if len(password) < 8:
            flash("Password must be at least 8 characters.", 'error')
            return render_template('admin/register.html', error="Password must be at least 8 characters.")
        
        if password != confirm_password:
            flash("Passwords do not match.", 'error')
            return render_template('admin/register.html', error="Passwords do not match.")
        
        with get_db_connection() as conn:
            c = conn.cursor()
            try:
                c.execute("""
                    INSERT INTO users (username, pusername, pin, login_phrase, password, role)
                    VALUES (?, ?, ?, ?, ?, 'admin')
                """, (username, pusername, pin, login_phrase, generate_password_hash(password)))
                conn.commit()
                flash("Admin registered successfully. Please log in.", 'success')
                return redirect(url_for('admin.login'))
            except sqlite3.IntegrityError:
                flash("Username or public username already exists.", 'error')
                return render_template('admin/register.html', error="Username or public username already exists.")
    
    return render_template('admin/register.html')

@admin_bp.route('/products/all-products', methods=['GET', 'POST'])
def manage_products():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT id, name FROM categories ORDER BY name")
            categories = [dict(row) for row in c.fetchall()]
            
            # Filters
            category_id = request.args.get('category_id', type=int)
            status = request.args.get('status')
            search = request.args.get('search', '').strip()
            page = request.args.get('page', 1, type=int)
            per_page = 10
            
            # Build query
            query = """
                SELECT p.*, c.name as category_name, u.pusername as vendor_name
                FROM products p 
                LEFT JOIN categories c ON p.category_id = c.id
                LEFT JOIN users u ON p.vendor_id = u.id
                WHERE 1=1
            """
            params = []
            
            if category_id:
                query += " AND p.category_id = ?"
                params.append(category_id)
            if status:
                query += " AND p.status = ?"
                params.append(status)
            if search:
                query += " AND (p.title LIKE ? OR p.sku LIKE ?)"
                params.extend([f'%{search}%', f'%{search}%'])
            
            # Count total for pagination
            c.execute(f"SELECT COUNT(*) as total FROM ({query})", params)
            total = c.fetchone()['total']
            total_pages = (total + per_page - 1) // per_page
            
            # Add pagination
            query += " ORDER BY p.created_at DESC LIMIT ? OFFSET ?"
            params.extend([per_page, (page - 1) * per_page])
            
            c.execute(query, params)
            products = [dict(row) for row in c.fetchall()]
            
            c.execute("SELECT * FROM product_images")
            product_images = [dict(row) for row in c.fetchall()]
            
            if request.method == 'POST':
                title = request.form.get('title', '').strip()
                description = request.form.get('description', '').strip()
                price_usd = request.form.get('price_usd', type=float)
                price_btc = request.form.get('price_btc', type=float)
                price_xmr = request.form.get('price_xmr', type=float)
                original_price_usd = request.form.get('original_price_usd', type=float)
                discount_active = bool(request.form.get('discount_active'))
                stock = request.form.get('stock', type=int)
                category_id = request.form.get('category_id', type=int)
                sku = request.form.get('sku', '').strip() or None
                weight_grams = request.form.get('weight_grams', type=float)
                shipping_dimensions = request.form.get('shipping_dimensions', '').strip() or None
                shipping_methods = request.form.get('shipping_methods', '').strip() or None
                shipping_destinations = request.form.get('shipping_destinations', '').strip()
                moq = request.form.get('moq', type=int, default=1)
                lead_time = request.form.get('lead_time', '').strip() or None
                packaging_details = request.form.get('packaging_details', '').strip() or None
                tags = request.form.get('tags', '').strip() or None
                status = request.form.get('status', 'pending')
                product_type = request.form.get('product_type', 'physical')
                featured_image = request.files.get('featured_image')
                additional_images = request.files.getlist('additional_images')
                
                # Calculate crypto prices if not provided
                btc_rate = 0.000015  # 1 USD = 0.000015 BTC
                xmr_rate = 0.006     # 1 USD = 0.006 XMR
                price_btc = price_btc if price_btc else (price_usd * btc_rate if price_usd else 0.0)
                price_xmr = price_xmr if price_xmr else (price_usd * xmr_rate if price_usd else 0.0)
                
                # Validation
                errors = []
                if not all([title, description, price_usd, price_btc, price_xmr, stock is not None, category_id, shipping_destinations]):
                    errors.append("All required fields must be filled.")
                if any(x <= 0 for x in [price_usd, price_btc, price_xmr] if x is not None):
                    errors.append("Prices must be positive.")
                if stock < 0:
                    errors.append("Stock must be non-negative.")
                if moq < 1:
                    errors.append("MOQ must be at least 1.")
                if product_type not in ['physical', 'digital']:
                    errors.append("Invalid product type.")
                if status not in ['pending', 'active', 'rejected', 'disabled']:
                    errors.append("Invalid status.")
                
                if errors:
                    for error in errors:
                        flash(error, 'error')
                    return render_template('admin/products/all-products.html',
                                         categories=categories,
                                         products=products,
                                         product_images=product_images,
                                         total_pages=total_pages,
                                         current_page=page)
                
                featured_image_path = None
                if featured_image and allowed_file(featured_image.filename):
                    if featured_image.content_length > MAX_FILE_SIZE:
                        flash('Featured image exceeds 2MB.', 'error')
                        return render_template('admin/products/all-products.html',
                                             categories=categories,
                                             products=products,
                                             product_images=product_images,
                                             total_pages=total_pages,
                                             current_page=page)
                    filename = secure_filename(f"{secrets.token_hex(8)}_{featured_image.filename}")
                    featured_image_path = os.path.join('uploads/products', filename).replace('\\', '/')
                    featured_image.save(os.path.join(UPLOAD_FOLDER_PRODUCTS, filename))
                
                try:
                    c.execute("""
                        INSERT INTO products (
                            title, description, price_usd, price_btc, price_xmr, original_price_usd,
                            discount_active, stock, category_id, vendor_id, sku, weight_grams,
                            shipping_dimensions, shipping_methods, shipping_destinations, moq,
                            lead_time, packaging_details, tags, status, product_type, featured_image
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (title, description, price_usd, price_btc, price_xmr, original_price_usd,
                          discount_active, stock, category_id, session['admin_id'], sku, weight_grams,
                          shipping_dimensions, shipping_methods, shipping_destinations, moq,
                          lead_time, packaging_details, tags, status, product_type, featured_image_path))
                    product_id = c.lastrowid
                    
                    for image in additional_images[:5]:
                        if image and allowed_file(image.filename):
                            if image.content_length > MAX_FILE_SIZE:
                                flash(f"Image {image.filename} exceeds 2MB.", 'error')
                                continue
                            filename = secure_filename(f"{secrets.token_hex(8)}_{image.filename}")
                            image_path = os.path.join('Uploads/products', filename).replace('\\', '/')
                            image.save(os.path.join(UPLOAD_FOLDER_PRODUCTS, filename))
                            c.execute("INSERT INTO product_images (product_id, image_path) VALUES (?, ?)",
                                      (product_id, image_path))
                    
                    conn.commit()
                    flash("Product added successfully.", 'success')
                    return redirect(url_for('admin.manage_products'))
                except sqlite3.IntegrityError as e:
                    if 'UNIQUE constraint failed: products.sku' in str(e):
                        flash('SKU already exists.', 'error')
                    elif 'FOREIGN KEY constraint failed' in str(e):
                        flash('Invalid category or vendor ID.', 'error')
                    else:
                        flash(f'Error adding product: {str(e)}', 'error')
                    logger.error(f"IntegrityError adding product: {str(e)}")
                
                return render_template('admin/products/all-products.html',
                                     categories=categories,
                                     products=products,
                                     product_images=product_images,
                                     total_pages=total_pages,
                                     current_page=page)
            
            return render_template('admin/products/all-products.html',
                                 categories=categories,
                                 products=products,
                                 product_images=product_images,
                                 total_pages=total_pages,
                                 current_page=page)
    except Exception as e:
        logger.error(f"Error in manage_products: {str(e)}")
        flash('An error occurred. Please try again.', 'error')
        return redirect(url_for('admin.manage_products'))

@admin_bp.route('/products/change-status/<int:product_id>', methods=['POST'])
def change_product_status(product_id):
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    status = request.form.get('status')
    if status not in ['pending', 'active', 'rejected', 'disabled']:
        flash('Invalid status.', 'error')
        return redirect(url_for('admin.manage_products'))
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("UPDATE products SET status = ? WHERE id = ?", (status, product_id))
            if c.rowcount == 0:
                flash('Product not found.', 'error')
            else:
                conn.commit()
                flash('Product status updated.', 'success')
    except Exception as e:
        logger.error(f"Error changing status: {str(e)}")
        flash('Error updating status.', 'error')
    
    return redirect(url_for('admin.manage_products'))

@admin_bp.route('/products/delete/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            # Delete associated images
            c.execute("SELECT image_path FROM product_images WHERE product_id = ?", (product_id,))
            images = c.fetchall()
            for img in images:
                try:
                    os.remove(os.path.join(UPLOAD_FOLDER_PRODUCTS, img['image_path'].replace('uploads/', '')))
                except OSError:
                    pass
            c.execute("DELETE FROM product_images WHERE product_id = ?", (product_id,))
            
            # Delete product
            c.execute("DELETE FROM products WHERE id = ?", (product_id,))
            if c.rowcount == 0:
                flash('Product not found.', 'error')
            else:
                conn.commit()
                flash('Product deleted.', 'success')
    except Exception as e:
        logger.error(f"Error deleting product: {str(e)}")
        flash('Error deleting product.', 'error')
    
    return redirect(url_for('admin.manage_products'))

@admin_bp.route('/products/toggle-featured/<int:product_id>', methods=['POST'])
def toggle_featured(product_id):
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT is_featured FROM products WHERE id = ?", (product_id,))
            product = c.fetchone()
            if not product:
                flash('Product not found.', 'error')
                return redirect(url_for('admin.manage_products'))
            
            new_featured = 0 if product['is_featured'] else 1
            c.execute("UPDATE products SET is_featured = ? WHERE id = ?", (new_featured, product_id))
            conn.commit()
            flash('Featured status updated.', 'success')
    except Exception as e:
        logger.error(f"Error toggling featured: {str(e)}")
        flash('Error updating featured status.', 'error')
    
    return redirect(url_for('admin.manage_products'))


@admin_bp.route('/products', methods=['GET', 'POST'])
def admin_products():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT id, pusername FROM users WHERE role = 'vendor'")
            vendors = [dict(row) for row in c.fetchall()]
            c.execute("SELECT id, name, parent_id FROM categories")
            categories = [dict(row) for row in c.fetchall()]
            c.execute("SELECT * FROM products")
            products = [dict(row) for row in c.fetchall()]
            c.execute("SELECT id, product_id, image_path FROM product_images")
            product_images = [dict(row) for row in c.fetchall()]
            
            if request.method == 'POST':
                title = request.form.get('title', '').strip()
                description = request.form.get('description', '').strip()
                price_usd = request.form.get('price_usd', type=float)
                price_btc = request.form.get('price_btc', type=float)
                price_xmr = request.form.get('price_xmr', type=float)
                stock = request.form.get('stock', type=int)
                vendor_id = request.form.get('vendor_id', type=int)
                category_id = request.form.get('category_id', type=int)
                sku = request.form.get('sku', '').strip() or None
                tags = request.form.get('tags', '').strip() or None
                origin_country = request.form.get('origin_country', '').strip() or None
                shipping_destinations = request.form.get('shipping_destinations', '').strip()
                shipping_methods = request.form.get('shipping_methods', '').strip() or None
                weight_grams = request.form.get('weight_grams', type=float)
                visibility = request.form.get('visibility', 'public')
                status = request.form.get('status', 'pending')
                is_featured = 1 if request.form.get('is_featured') else 0
                product_type = request.form.get('product_type', 'physical')
                
                # Calculate crypto prices if not provided
                btc_rate = 0.000015  # 1 USD = 0.000015 BTC
                xmr_rate = 0.006     # 1 USD = 0.006 XMR
                price_btc = price_btc if price_btc else (price_usd * btc_rate if price_usd else 0.0)
                price_xmr = price_xmr if price_xmr else (price_usd * xmr_rate if price_usd else 0.0)
                
                errors = []
                if not title:
                    errors.append("Title is required.")
                if not description:
                    errors.append("Description is required.")
                if price_usd is None or price_usd <= 0:
                    errors.append("Price (USD) must be positive.")
                if price_btc is None or price_btc <= 0:
                    errors.append("Price (BTC) must be positive.")
                if price_xmr is None or price_xmr <= 0:
                    errors.append("Price (XMR) must be positive.")
                if stock is None or stock < 0:
                    errors.append("Stock must be non-negative.")
                if not shipping_destinations:
                    errors.append("Shipping destinations are required.")
                if vendor_id not in [v['id'] for v in vendors]:
                    errors.append("Invalid vendor selected.")
                if category_id not in [c['id'] for c in categories]:
                    errors.append("Invalid category selected.")
                if product_type not in ['physical', 'digital']:
                    errors.append("Product type must be 'physical' or 'digital'.")
                if status not in ['pending', 'active', 'rejected', 'disabled']:
                    errors.append("Invalid status selected.")
                
                if errors:
                    for error in errors:
                        flash(error, 'error')
                    return redirect(url_for('admin.admin_products'))
                
                featured_image_path = None
                if 'featured_image' in request.files:
                    file = request.files['featured_image']
                    if file and allowed_file(file.filename):
                        if file.content_length > MAX_FILE_SIZE:
                            flash('Featured image exceeds 2MB.', 'error')
                            return redirect(url_for('admin.admin_products'))
                        filename = secure_filename(f"{secrets.token_hex(8)}_{file.filename}")
                        file.save(os.path.join(UPLOAD_FOLDER_PRODUCTS, filename))
                        featured_image_path = os.path.join('uploads/products', filename).replace('\\', '/')
                
                try:
                    c.execute("""
                        INSERT INTO products (
                            vendor_id, title, description, price_usd, price_btc, price_xmr,
                            stock, category_id, sku, tags, origin_country, shipping_destinations,
                            shipping_methods, weight_grams, visibility, status, is_featured,
                            featured_image, product_type
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (vendor_id, title, description, price_usd, price_btc, price_xmr,
                          stock, category_id, sku, tags, origin_country, shipping_destinations,
                          shipping_methods, weight_grams, visibility, status, is_featured,
                          featured_image_path, product_type))
                    product_id = c.lastrowid
                    
                    if 'additional_images' in request.files:
                        files = request.files.getlist('additional_images')
                        for file in files[:5]:
                            if file and allowed_file(file.filename):
                                if file.content_length > MAX_FILE_SIZE:
                                    flash(f"Image {file.filename} exceeds 2MB.", 'error')
                                    continue
                                filename = secure_filename(f"{secrets.token_hex(8)}_{file.filename}")
                                file.save(os.path.join(UPLOAD_FOLDER_PRODUCTS, filename))
                                image_path = os.path.join('uploads/products', filename).replace('\\', '/')
                                c.execute("INSERT INTO product_images (product_id, image_path) VALUES (?, ?)",
                                          (product_id, image_path))
                    
                    conn.commit()
                    flash('Product added successfully.', 'success')
                    logger.info(f"Product added: {title} (ID: {product_id})")
                except sqlite3.IntegrityError as e:
                    if 'UNIQUE constraint failed: products.sku' in str(e):
                        flash('SKU already exists.', 'error')
                    elif 'FOREIGN KEY constraint failed' in str(e):
                        flash('Invalid vendor or category ID.', 'error')
                    elif 'NOT NULL constraint failed' in str(e):
                        flash(f'Missing required field: {str(e)}', 'error')
                    else:
                        flash(f'Error adding product: {str(e)}', 'error')
                    logger.error(f"IntegrityError adding product: {str(e)}")
                return redirect(url_for('admin.admin_products'))
            
            return render_template('admin/products/add.html',
                                 vendors=vendors,
                                 categories=categories,
                                 products=products,
                                 product_images=product_images,
                                 edit_product=None,
                                 additional_images=[])
    except Exception as e:
        logger.error(f"Error in admin_products: {str(e)}")
        flash('An error occurred. Please try again.', 'error')
        return redirect(url_for('admin.admin_products'))

@admin_bp.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
def admin_edit_product(product_id):
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM products WHERE id = ?", (product_id,))
        edit_product = c.fetchone()
        if not edit_product:
            flash('Product not found.', 'error')
            return redirect(url_for('admin.admin_products'))
        
        c.execute("SELECT id, pusername FROM users WHERE role = 'vendor'")
        vendors = [dict(row) for row in c.fetchall()]
        c.execute("SELECT id, name, parent_id FROM categories")
        categories = [dict(row) for row in c.fetchall()]
        c.execute("SELECT id, product_id, image_path FROM product_images WHERE product_id = ?", (product_id,))
        additional_images = [dict(row) for row in c.fetchall()]
        
        if request.method == 'POST':
            title = request.form.get('title')
            description = request.form.get('description')
            price_usd = request.form.get('price_usd', type=float)
            stock = request.form.get('stock', type=int)
            vendor_id = request.form.get('vendor_id', type=int)
            category_id = request.form.get('category_id', type=int)
            sku = request.form.get('sku')
            tags = request.form.get('tags')
            origin_country = request.form.get('origin_country')
            shipping_destinations = request.form.get('shipping_destinations')
            shipping_methods = request.form.get('shipping_methods')
            weight_grams = request.form.get('weight_grams', type=float)
            visibility = request.form.get('visibility', 'public')
            status = request.form.get('status', 'active')
            is_featured = 1 if request.form.get('is_featured') else 0
            
            featured_image_path = edit_product['featured_image']
            if 'featured_image' in request.files:
                file = request.files['featured_image']
                if file and allowed_file(file.filename):
                    if file.content_length > MAX_FILE_SIZE:
                        flash('Featured image exceeds 2MB.', 'error')
                        return redirect(url_for('admin.admin_products'))
                    filename = secure_filename(f"{secrets.token_hex(8)}_{file.filename}")
                    file.save(os.path.join(UPLOAD_FOLDER_PRODUCTS, filename))
                    featured_image_path = os.path.join('uploads', filename)
            
            try:
                c.execute("""
                    UPDATE products SET vendor_id = ?, title = ?, description = ?, price_usd = ?,
                                       stock = ?, category_id = ?, sku = ?, tags = ?, origin_country = ?,
                                       shipping_destinations = ?, shipping_methods = ?, weight_grams = ?,
                                       visibility = ?, status = ?, is_featured = ?, featured_image = ?
                    WHERE id = ?
                """, (vendor_id, title, description, price_usd, stock, category_id, sku, tags,
                      origin_country, shipping_destinations, shipping_methods, weight_grams,
                      visibility, status, is_featured, featured_image_path, product_id))
                
                if 'additional_images' in request.files:
                    files = request.files.getlist('additional_images')
                    for file in files[:5 - len(additional_images)]:  # Limit total to 5
                        if file and allowed_file(file.filename):
                            if file.content_length > MAX_FILE_SIZE:
                                flash(f"Image {file.filename} exceeds 2MB.", 'error')
                                continue
                            filename = secure_filename(f"{secrets.token_hex(8)}_{file.filename}")
                            file.save(os.path.join(UPLOAD_FOLDER_PRODUCTS, filename))
                            image_path = os.path.join('uploads/products', filename)
                            c.execute("INSERT INTO product_images (product_id, image_path) VALUES (?, ?)",
                                      (product_id, image_path))
                
                conn.commit()
                flash('Product updated successfully.', 'success')
                return redirect(url_for('admin.admin_products'))
            except sqlite3.IntegrityError:
                flash('SKU already exists or required fields missing.', 'error')
        
        return render_template('admin/products.html',
            vendors=vendors,
            categories=categories,
            products=[],
            product_images=additional_images,
            edit_product=edit_product,
            additional_images=additional_images
        )

@admin_bp.route('/delete_product/<int:product_id>', methods=['POST'])
def admin_delete_product(product_id):
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT title, featured_image FROM products WHERE id = ?", (product_id,))
        product = c.fetchone()
        if not product:
            flash('Product not found.', 'error')
        else:
            c.execute("SELECT image_path FROM product_images WHERE product_id = ?", (product_id,))
            images = c.fetchall()
            for image in images:
                try:
                    os.remove(os.path.join(UPLOAD_FOLDER_PRODUCTS, os.path.basename(image['image_path'])))
                except OSError:
                    pass
            if product['featured_image']:
                try:
                    os.remove(os.path.join(UPLOAD_FOLDER_PRODUCTS, os.path.basename(product['featured_image'])))
                except OSError:
                    pass
            c.execute("DELETE FROM product_images WHERE product_id = ?", (product_id,))
            c.execute("DELETE FROM products WHERE id = ?", (product_id,))
            conn.commit()
            flash(f"Product {product['title']} deleted successfully.", 'success')
    return redirect(url_for('admin.admin_products'))

@admin_bp.route('/delete_image/<int:image_id>', methods=['GET'])
def admin_delete_image(image_id):
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT image_path FROM product_images WHERE id = ?", (image_id,))
        image = c.fetchone()
        if not image:
            flash('Image not found.', 'error')
        else:
            try:
                os.remove(os.path.join(UPLOAD_FOLDER_PRODUCTS, os.path.basename(image['image_path'])))
            except OSError:
                pass
            c.execute("DELETE FROM product_images WHERE id = ?", (image_id,))
            conn.commit()
            flash('Image deleted successfully.', 'success')
    return redirect(url_for('admin.admin_products'))


@admin_bp.route('/settings', methods=['GET', 'POST'])
def admin_settings():
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('admin.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        
        if request.method == 'POST':
            # Appearance
            site_name = request.form.get('site_name', '').strip()
            primary_color = request.form.get('primary_color', '#facc15')
            secondary_color = request.form.get('secondary_color', '#1f2937')
            logo = request.files.get('logo')
            
            # SEO
            meta_title = request.form.get('meta_title', '').strip()
            meta_description = request.form.get('meta_description', '').strip()
            
            # Security
            maintenance_mode = '1' if request.form.get('maintenance_mode') else '0'
            two_factor_required = '1' if request.form.get('two_factor_required') else '0'
            session_timeout = request.form.get('session_timeout', type=int, default=30)
            max_login_attempts = request.form.get('max_login_attempts', type=int, default=5)
            
            # Marketplace
            btc_conversion_enabled = '1' if request.form.get('btc_conversion_enabled') else '0'
            min_order_amount_usd = request.form.get('min_order_amount_usd', type=float, default=10.00)
            support_email = request.form.get('support_email', '').strip()
            pgp_key = request.form.get('pgp_key', '').strip()

            # Wallets
            btc_escrow_wallet = request.form.get('btc_escrow_wallet', '').strip()
            btc_admin_wallet = request.form.get('btc_admin_wallet', '').strip()
            xmr_escrow_wallet = request.form.get('xmr_escrow_wallet', '').strip()
            xmr_admin_wallet = request.form.get('xmr_admin_wallet', '').strip()

            # Escrow/Transaction
            escrow_fee_percent = request.form.get('escrow_fee_percent', type=float, default=2.5)
            vendor_bond_amount = request.form.get('vendor_bond_amount', type=float, default=0.05)
            escrow_auto_release_hours = request.form.get('escrow_auto_release_hours', type=int, default=72)

            # Validation
            if not site_name or not meta_title or not meta_description:
                flash("Site name, meta title, and meta description are required.", 'error')
                return render_template('admin/settings.html', settings=get_settings(), error="Required fields missing.")

            if session_timeout < 5 or max_login_attempts < 1:
                flash("Session timeout must be at least 5 minutes, and max login attempts must be at least 1.", 'error')
                return render_template('admin/settings.html', settings=get_settings(), error="Invalid security settings.")

            if min_order_amount_usd < 0:
                flash("Minimum order amount cannot be negative.", 'error')
                return render_template('admin/settings.html', settings=get_settings(), error="Invalid marketplace settings.")

            # Wallet validation (simple, can be improved)
            if not btc_escrow_wallet or not btc_admin_wallet or not xmr_escrow_wallet or not xmr_admin_wallet:
                flash("All wallet addresses are required.", 'error')
                return render_template('admin/settings.html', settings=get_settings(), error="Wallet addresses required.")
            if escrow_fee_percent < 0 or escrow_fee_percent > 100:
                flash("Escrow fee percent must be between 0 and 100.", 'error')
                return render_template('admin/settings.html', settings=get_settings(), error="Invalid escrow fee.")
            if vendor_bond_amount < 0:
                flash("Vendor bond amount cannot be negative.", 'error')
                return render_template('admin/settings.html', settings=get_settings(), error="Invalid vendor bond amount.")
            if escrow_auto_release_hours < 1:
                flash("Escrow auto-release must be at least 1 hour.", 'error')
                return render_template('admin/settings.html', settings=get_settings(), error="Invalid auto-release time.")

            # Handle logo upload
            logo_path = get_settings().get('logo_path', '/static/uploads/logos/default_logo.png')
            if logo and allowed_file(logo.filename):
                filename = secure_filename(logo.filename)
                logo_path = os.path.join('uploads', 'logos', filename).replace('\\', '/')
                logo.save(os.path.join(UPLOAD_FOLDER_LOGOS, filename))
            
            # Update settings
            updates = [
                ('site_name', site_name),
                ('primary_color', primary_color),
                ('secondary_color', secondary_color),
                ('logo_path', logo_path),
                ('meta_title', meta_title),
                ('meta_description', meta_description),
                ('maintenance_mode', maintenance_mode),
                ('two_factor_required', two_factor_required),
                ('session_timeout', str(session_timeout)),
                ('max_login_attempts', str(max_login_attempts)),
                ('btc_conversion_enabled', btc_conversion_enabled),
                ('min_order_amount_usd', str(min_order_amount_usd)),
                ('support_email', support_email),
                ('pgp_key', pgp_key),
                # New wallet and escrow settings
                ('btc_escrow_wallet', btc_escrow_wallet),
                ('btc_admin_wallet', btc_admin_wallet),
                ('xmr_escrow_wallet', xmr_escrow_wallet),
                ('xmr_admin_wallet', xmr_admin_wallet),
                ('escrow_fee_percent', str(escrow_fee_percent)),
                ('vendor_bond_amount', str(vendor_bond_amount)),
                ('escrow_auto_release_hours', str(escrow_auto_release_hours))
            ]
            c.executemany("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", updates)
            conn.commit()
            
            flash("Settings updated successfully.", 'success')
            return redirect(url_for('admin.admin_settings'))
        
        return render_template('admin/settings.html', settings=get_settings())

@admin_bp.route('/users', methods=['GET'])
def manage_users():
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 10
    search = request.args.get('search', '').strip()
    role = request.args.get('role', '')
    status = request.args.get('status', '')
    
    query = """
        SELECT u.id, u.pusername, u.role, u.created_at, u.last_login, u.btc_address, u.status,
               COUNT(o.id) AS order_count,
               COALESCE(SUM(o.amount_btc), 0) AS total_spent_btc
        FROM users u
        LEFT JOIN orders o ON u.id = o.user_id
        WHERE u.role != 'vendor'
    """
    params = []
    
    if search:
        query += " AND (u.pusername LIKE ? OR u.status LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])
    if role:
        query += " AND u.role = ?"
        params.append(role)
    if status:
        query += " AND u.status = ?"
        params.append(status)
    
    query += " GROUP BY u.id ORDER BY u.created_at DESC"
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute(query, params)
        total_users = len(c.fetchall())
        total_pages = (total_users + per_page - 1) // per_page
        
        offset = (page - 1) * per_page
        query += " LIMIT ? OFFSET ?"
        params.extend([per_page, offset])
        
        c.execute(query, params)
        users = [dict(row) for row in c.fetchall()]
    
    return render_template('admin/users.html',
        users=users,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        total_users=total_users,
        success=request.args.get('success'),  # For compatibility
        error=request.args.get('error')
    )



@admin_bp.route('/users/suspend/<int:user_id>', methods=['POST'])
def admin_suspend_user(user_id):
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('admin.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT id, role FROM users WHERE id = ? AND role != 'admin'", (user_id,))
        user = c.fetchone()
        if not user:
            flash("User not found or cannot suspend an admin.", 'error')
            return redirect(url_for('admin.manage_users'))
        
        c.execute("UPDATE users SET active = 0 WHERE id = ?", (user_id,))
        conn.commit()
        flash(f"User {user_id} suspended successfully.", 'success')
        return redirect(url_for('admin.manage_users'))

@admin_bp.route('/suspend_user/<int:user_id>', methods=['POST'])
def suspend_user(user_id):
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT pusername FROM users WHERE id = ? AND role != 'vendor'", (user_id,))
        user = c.fetchone()
        if not user:
            flash('User not found or is a vendor.', 'error')
        else:
            c.execute("UPDATE users SET status = 'suspended' WHERE id = ?", (user_id,))
            conn.commit()
            flash(f"User {user['pusername']} suspended successfully.", 'success')
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/reactivate_user/<int:user_id>', methods=['POST'])
def reactivate_user(user_id):
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT pusername FROM users WHERE id = ? AND role != 'vendor'", (user_id,))
        user = c.fetchone()
        if not user:
            flash('User not found or is a vendor.', 'error')
        else:
            c.execute("UPDATE users SET status = 'active' WHERE id = ?", (user_id,))
            conn.commit()
            flash(f"User {user['pusername']} reactivated successfully.", 'success')
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/ban_user/<int:user_id>', methods=['POST'])
def ban_user(user_id):
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT pusername FROM users WHERE id = ? AND role != 'vendor'", (user_id,))
        user = c.fetchone()
        if not user:
            flash('User not found or is a vendor.', 'error')
        else:
            c.execute("UPDATE users SET status = 'banned' WHERE id = ?", (user_id,))
            conn.commit()
            flash(f"User {user['pusername']} banned permanently.", 'success')
    return redirect(url_for('admin.manage_users'))

#FAQS
@admin_bp.route('/faqs')
@require_admin_role
def faqs():
    """Display all FAQs grouped by category."""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            # Fetch categories
            c.execute("SELECT id, name FROM faq_categories ORDER BY name")
            categories = [dict(row) for row in c.fetchall()]
            
            # Fetch FAQs with category names
            c.execute("""
                SELECT f.id, f.question, f.answer, f.category_id, fc.name as category_name
                FROM faqs f
                JOIN faq_categories fc ON f.category_id = fc.id
                ORDER BY fc.name, f.question
            """)
            faqs = [dict(row) for row in c.fetchall()]
            
            # Group FAQs by category
            grouped_faqs = {cat['name']: [] for cat in categories}
            for faq in faqs:
                grouped_faqs[faq['category_name']].append(faq)
            
            # Calculate total FAQs
            total_faqs = sum(len(faq_list) for faq_list in grouped_faqs.values())
            
            return render_template('admin/faqs.html', grouped_faqs=grouped_faqs, categories=categories, total_faqs=total_faqs)
    except Exception as e:
        logger.error(f"Error fetching FAQs: {str(e)}")
        flash("Error loading FAQs.", 'error')
        return redirect(url_for('admin.dashboard'))

@admin_bp.route('/faqs/new', methods=['GET', 'POST'])
@require_admin_role
def new_faq():
    """Create a new FAQ."""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT id, name FROM faq_categories ORDER BY name")
            categories = [dict(row) for row in c.fetchall()]
            
            if request.method == 'POST':
                question = request.form.get('question', '').strip()
                answer = request.form.get('answer', '').strip()
                category_id = request.form.get('category_id', type=int)
                
                if not question or not answer or not category_id:
                    flash("All fields are required.", 'error')
                elif not any(cat['id'] == category_id for cat in categories):
                    flash("Invalid category.", 'error')
                else:
                    c.execute("""
                        INSERT INTO faqs (question, answer, category_id)
                        VALUES (?, ?, ?)
                    """, (question, answer, category_id))
                    conn.commit()
                    logger.info(f"FAQ created: {question}")
                    flash("FAQ created successfully.", 'success')
                    return redirect(url_for('admin.faqs'))
            
            return render_template('admin/faqs.html', categories=categories, action='new')
    except Exception as e:
        logger.error(f"Error creating FAQ: {str(e)}")
        flash("Error creating FAQ.", 'error')
        return redirect(url_for('admin.faqs'))

@admin_bp.route('/faqs/edit/<int:id>', methods=['GET', 'POST'])
@require_admin_role
def edit_faq(id):
    """Edit an existing FAQ."""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT id, name FROM faq_categories ORDER BY name")
            categories = [dict(row) for row in c.fetchall()]
            
            c.execute("SELECT id, question, answer, category_id FROM faqs WHERE id = ?", (id,))
            faq = c.fetchone()
            if not faq:
                flash("FAQ not found.", 'error')
                return redirect(url_for('admin.faqs'))
            
            faq = dict(faq)
            
            if request.method == 'POST':
                question = request.form.get('question', '').strip()
                answer = request.form.get('answer', '').strip()
                category_id = request.form.get('category_id', type=int)
                
                if not question or not answer or not category_id:
                    flash("All fields are required.", 'error')
                elif not any(cat['id'] == category_id for cat in categories):
                    flash("Invalid category.", 'error')
                else:
                    c.execute("""
                        UPDATE faqs
                        SET question = ?, answer = ?, category_id = ?, updated_at = ?
                        WHERE id = ?
                    """, (question, answer, category_id, datetime.now(), id))
                    conn.commit()
                    logger.info(f"FAQ updated: ID {id}")
                    flash("FAQ updated successfully.", 'success')
                    return redirect(url_for('admin.faqs'))
            
            return render_template('admin/faqs.html', faq=faq, categories=categories, action='edit')
    except Exception as e:
        logger.error(f"Error editing FAQ: {str(e)}")
        flash("Error editing FAQ.", 'error')
        return redirect(url_for('admin.faqs'))

@admin_bp.route('/faqs/delete/<int:id>', methods=['POST'])
@require_admin_role
def delete_faq(id):
    """Delete an FAQ."""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT id FROM faqs WHERE id = ?", (id,))
            if not c.fetchone():
                flash("FAQ not found.", 'error')
            else:
                c.execute("DELETE FROM faqs WHERE id = ?", (id,))
                conn.commit()
                logger.info(f"FAQ deleted: ID {id}")
                flash("FAQ deleted successfully.", 'success')
            return redirect(url_for('admin.faqs'))
    except Exception as e:
        logger.error(f"Error deleting FAQ: {str(e)}")
        flash("Error deleting FAQ.", 'error')
        return redirect(url_for('admin.faqs'))

@admin_bp.route('/reset_password/<int:user_id>', methods=['POST'])
def reset_password(user_id):
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT pusername FROM users WHERE id = ? AND role != 'vendor'", (user_id,))
        user = c.fetchone()
        if not user:
            flash('User not found or is a vendor.', 'error')
        else:
            new_password = secrets.token_urlsafe(12)
            password_hash = generate_password_hash(new_password)
            c.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
            c.execute("INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)",
                      (user_id, secrets.token_hex(16), datetime.utcnow() + timedelta(hours=24)))
            conn.commit()
            flash(f"Password reset for {user['pusername']}. New password: {new_password} (Note: Email not implemented).", 'success')
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if not is_admin():
        flash("Admin access required.", 'error')
        return redirect(url_for('admin.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT id, pusername, btc_address, pgp_public_key, role, is_vendor FROM users WHERE id = ?", (user_id,))
        user = c.fetchone()
        if not user:
            flash('User not found.', 'error')
            return redirect(url_for('admin.manage_users'))
        
        if request.method == 'POST':
            # Validate CSRF (uncomment in production)
            # validate_csrf_token()
            
            pusername = request.form.get('pusername', '').strip()
            btc_address = request.form.get('btc_address', '').strip()
            pgp_public_key = request.form.get('pgp_public_key', '').strip()
            promote_to_vendor = 'promote_to_vendor' in request.form
            
            # Validation
            if not pusername:
                flash("Public username is required.", 'error')
            elif len(pusername) > 50:
                flash("Public username cannot exceed 50 characters.", 'error')
            elif btc_address and not re.match(r'^(1|3|bc1)[a-zA-Z0-9]{25,34}$', btc_address):
                flash("Invalid Bitcoin address.", 'error')
            elif pgp_public_key and not pgp_public_key.startswith('-----BEGIN PGP PUBLIC KEY BLOCK-----'):
                flash("Invalid PGP public key format.", 'error')
            else:
                try:
                    # Check pusername uniqueness (excluding current user)
                    c.execute("SELECT id FROM users WHERE pusername = ? AND id != ?", (pusername, user_id))
                    if c.fetchone():
                        flash("Public username already exists.", 'error')
                    else:
                        # Update fields
                        role = 'vendor' if promote_to_vendor else user['role']
                        is_vendor = 1 if promote_to_vendor else user['is_vendor']
                        c.execute("""
                            UPDATE users
                            SET pusername = ?, btc_address = ?, pgp_public_key = ?, role = ?, is_vendor = ?
                            WHERE id = ?
                        """, (pusername, btc_address or None, pgp_public_key or None, role, is_vendor, user_id))
                        conn.commit()
                        flash(f"User {pusername} updated successfully.", 'success')
                        # Redirect to vendor profile if promoted
                        if promote_to_vendor:
                            return redirect(url_for('admin.vendor_profile', vendor_id=user_id))
                        return redirect(url_for('admin.manage_users'))
                except Exception as e:
                    logger.error(f"Error updating user: {str(e)}")
                    flash("Database error occurred. Please try again.", 'error')
        
        return render_template('admin/edit_user.html', user=user)

@admin_bp.route('/vendor_profile/<int:vendor_id>', methods=['GET'])
def admin_vendor_profile(vendor_id):
    if not is_admin():
        flash("Admin access required.", 'error')
        return redirect(url_for('admin.login'))
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            # Fetch vendor details with vendor level stats
            c.execute("""
                SELECT u.id, u.pusername, u.btc_address, u.pgp_public_key, u.role, u.is_vendor, u.vendor_status, u.level,
                       vl.level AS vendor_level, vl.sales_count, vl.positive_feedback_percentage, vl.joined_at, vl.updated_at,
                       AVG(vr.rating) AS avg_rating
                FROM users u
                LEFT JOIN vendor_levels vl ON u.id = vl.vendor_id
                LEFT JOIN vendor_ratings vr ON u.id = vr.vendor_id
                WHERE u.id = ? AND u.is_vendor = 1
                GROUP BY u.id
            """, (vendor_id,))
            vendor = c.fetchone()
            if not vendor:
                flash("Vendor not found.", 'error')
                return redirect(url_for('admin.manage_users'))
            
            # Fetch vendor products
            c.execute("""
                SELECT id, title, price_usd, stock, status
                FROM products
                WHERE vendor_id = ?
                ORDER BY created_at DESC
            """, (vendor_id,))
            products = [dict(row) for row in c.fetchall()]
        
        return render_template('admin/vendor_profile.html', vendor=vendor, products=products)
    except Exception as e:
        logger.error(f"Error fetching vendor profile: {str(e)}")
        flash("Database error occurred. Please try again.", 'error')
        return redirect(url_for('admin.manage_users'))

@admin_bp.route('/edit_vendor/<int:vendor_id>', methods=['GET', 'POST'])
def admin_edit_vendor(vendor_id):
    if not is_admin():
        flash("Admin access required.", 'error')
        return redirect(url_for('admin.login'))
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            if request.method == 'GET':
                # Fetch vendor details with vendor level stats
                c.execute("""
                    SELECT u.id, u.pusername, u.btc_address, u.pgp_public_key, u.role, u.is_vendor, u.vendor_status, u.level,
                           vl.level AS vendor_level, vl.sales_count, vl.positive_feedback_percentage, vl.joined_at, vl.updated_at,
                           AVG(vr.rating) AS avg_rating
                    FROM users u
                    LEFT JOIN vendor_levels vl ON u.id = vl.vendor_id
                    LEFT JOIN vendor_ratings vr ON u.id = vr.vendor_id
                    WHERE u.id = ? AND u.is_vendor = 1
                    GROUP BY u.id
                """, (vendor_id,))
                vendor = c.fetchone()
                if not vendor:
                    flash("Vendor not found.", 'error')
                    return redirect(url_for('admin.manage_vendors'))
                
                return render_template('admin/edit_vendor.html', vendor=vendor)
            
            elif request.method == 'POST':
                # Handle form submission
                pusername = request.form.get('pusername', '').strip()
                btc_address = request.form.get('btc_address', '').strip()
                pgp_public_key = request.form.get('pgp_public_key', '').strip()
                vendor_status = request.form.get('vendor_status', '').strip()
                level = request.form.get('level', type=int)
                sales_count = request.form.get('sales_count', type=int)
                positive_feedback_percentage = request.form.get('positive_feedback_percentage', type=float)
                
                # Validate inputs
                if not pusername:
                    flash("Public username is required.", 'error')
                    return redirect(url_for('admin.admin_edit_vendor', vendor_id=vendor_id))
                
                if level and not (1 <= level <= 10):
                    flash("Vendor level must be between 1 and 10.", 'error')
                    return redirect(url_for('admin.admin_edit_vendor', vendor_id=vendor_id))
                
                if sales_count is not None and sales_count < 0:
                    flash("Sales count cannot be negative.", 'error')
                    return redirect(url_for('admin.admin_edit_vendor', vendor_id=vendor_id))
                
                if positive_feedback_percentage is not None and not (0 <= positive_feedback_percentage <= 100):
                    flash("Positive feedback percentage must be between 0 and 100.", 'error')
                    return redirect(url_for('admin.admin_edit_vendor', vendor_id=vendor_id))
                
                # Check if vendor exists
                c.execute("SELECT id FROM users WHERE id = ? AND is_vendor = 1", (vendor_id,))
                vendor = c.fetchone()
                if not vendor:
                    flash("Vendor not found.", 'error')
                    return redirect(url_for('admin.manage_vendors'))
                
                # Update user table - only update non-empty fields
                update_fields = []
                update_values = []
                
                if pusername:
                    update_fields.append("pusername = ?")
                    update_values.append(pusername)
                
                if btc_address is not None:
                    update_fields.append("btc_address = ?")
                    update_values.append(btc_address)
                
                if pgp_public_key is not None:
                    update_fields.append("pgp_public_key = ?")
                    update_values.append(pgp_public_key)
                
                if vendor_status:
                    update_fields.append("vendor_status = ?")
                    update_values.append(vendor_status)
                
                if level is not None:
                    update_fields.append("level = ?")
                    update_values.append(level)
                
                if update_fields:
                    update_values.append(vendor_id)
                    c.execute(f"""
                        UPDATE users 
                        SET {', '.join(update_fields)}
                        WHERE id = ?
                    """, update_values)
                
                # Ensure vendor level record exists
                c.execute("SELECT vendor_id FROM vendor_levels WHERE vendor_id = ?", (vendor_id,))
                if not c.fetchone():
                    initialize_vendor_level(vendor_id)
                
                # Update vendor level stats
                if level is not None or sales_count is not None or positive_feedback_percentage is not None:
                    update_fields = []
                    update_values = []
                    
                    if level is not None:
                        update_fields.append("level = ?")
                        update_values.append(level)
                    
                    if sales_count is not None:
                        update_fields.append("sales_count = ?")
                        update_values.append(sales_count)
                    
                    if positive_feedback_percentage is not None:
                        update_fields.append("positive_feedback_percentage = ?")
                        update_values.append(positive_feedback_percentage)
                    
                    if update_fields:
                        update_fields.append("updated_at = ?")
                        update_values.append(datetime.utcnow())
                        update_values.append(vendor_id)
                        
                        c.execute(f"""
                            UPDATE vendor_levels 
                            SET {', '.join(update_fields)}
                            WHERE vendor_id = ?
                        """, update_values)
                        
                                        # Log the change if level was updated
                if level is not None:
                    c.execute("SELECT level FROM vendor_levels WHERE vendor_id = ?", (vendor_id,))
                    current_level = c.fetchone()
                    if current_level and current_level['level'] != level:
                        c.execute("""
                            INSERT INTO vendor_level_logs (vendor_id, old_level, new_level, reason)
                            VALUES (?, ?, ?, ?)
                        """, (vendor_id, current_level['level'], level, 'Manual update by admin'))
                
                conn.commit()
                
                # Log admin action if logging is enabled
                try:
                    from utils.security import log_admin_action_encrypted
                    c.execute("SELECT value FROM security_settings WHERE setting_name = 'admin_action_logging'")
                    admin_action_logging = c.fetchone()
                    admin_action_logging = admin_action_logging['value'] if admin_action_logging else 'enabled'
                    
                    if admin_action_logging == 'enabled':
                        c.execute("SELECT pgp_public_key FROM users WHERE id = ?", (session.get('admin_id'),))
                        admin = c.fetchone()
                        if admin and admin['pgp_public_key']:
                            changes = []
                            if pusername: changes.append(f"username: {pusername}")
                            if btc_address is not None: changes.append(f"btc_address: {btc_address}")
                            if pgp_public_key is not None: changes.append(f"pgp_public_key: updated")
                            if vendor_status: changes.append(f"vendor_status: {vendor_status}")
                            if level is not None: changes.append(f"level: {level}")
                            if sales_count is not None: changes.append(f"sales_count: {sales_count}")
                            if positive_feedback_percentage is not None: changes.append(f"feedback: {positive_feedback_percentage}%")
                            
                            change_summary = ", ".join(changes) if changes else "no changes"
                            log_admin_action_encrypted(
                                f"Admin edited vendor {vendor_id} ({change_summary})", 
                                session.get('username', 'unknown'), 
                                admin['pgp_public_key']
                            )
                except Exception as e:
                    logger.error(f"Failed to log admin action: {e}")
                
                flash("Vendor profile and stats updated successfully.", 'success')
                return redirect(url_for('admin.admin_vendor_profile', vendor_id=vendor_id))
        
    except Exception as e:
        logger.error(f"Error editing vendor: {str(e)}")
        flash("Database error occurred. Please try again.", 'error')
        return redirect(url_for('admin.manage_vendors'))

@admin_bp.route('/vendor_level_history/<int:vendor_id>')
def admin_vendor_level_history(vendor_id):
    if not is_admin():
        flash("Admin access required.", 'error')
        return redirect(url_for('admin.login'))
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Get vendor info
            c.execute("SELECT pusername FROM users WHERE id = ? AND is_vendor = 1", (vendor_id,))
            vendor = c.fetchone()
            if not vendor:
                flash("Vendor not found.", 'error')
                return redirect(url_for('admin.manage_vendors'))
            
            # Get level change history
            c.execute("""
                SELECT old_level, new_level, reason, created_at
                FROM vendor_level_logs
                WHERE vendor_id = ?
                ORDER BY created_at DESC
            """, (vendor_id,))
            history = [dict(row) for row in c.fetchall()]
            
            return render_template('admin/vendor_level_history.html', vendor=vendor, history=history)
            
    except Exception as e:
        logger.error(f"Error fetching vendor level history: {str(e)}")
        flash("Database error occurred. Please try again.", 'error')
        return redirect(url_for('admin.manage_vendors'))

@admin_bp.route('/users/reactivate/<int:user_id>', methods=['POST'])
def admin_reactivate_user(user_id):
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('admin.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT id, role FROM users WHERE id = ? AND role != 'admin'", (user_id,))
        user = c.fetchone()
        if not user:
            flash("User not found or cannot reactivate an admin.", 'error')
            return redirect(url_for('admin.manage_users'))
        
        c.execute("UPDATE users SET active = 1 WHERE id = ?", (user_id,))
        conn.commit()
        flash(f"User {user_id} reactivated successfully.", 'success')
        return redirect(url_for('admin.manage_users'))

@admin_bp.route('/users/promote/<int:user_id>', methods=['POST'])
def admin_promote_user(user_id):
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('admin.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT id, role FROM users WHERE id = ? AND role != 'admin'", (user_id,))
        user = c.fetchone()
        if not user:
            flash("User not found or cannot promote an admin.", 'error')
            return redirect(url_for('admin.manage_users'))
        
        new_role = 'vendor' if user['role'] == 'user' else 'user'
        c.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
        conn.commit()
        
        # Initialize vendor level record if promoting to vendor
        if new_role == 'vendor':
            initialize_vendor_level(user_id)
        
        flash(f"User {user_id} {'promoted to vendor' if new_role == 'vendor' else 'demoted to user'} successfully.", 'success')
        return redirect(url_for('admin.manage_users'))
    
@admin_bp.route('/vendor/orders', methods=['GET'])
def manage_orders():
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('admin.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT o.*, p.title
            FROM orders o
            JOIN products p ON o.product_id = p.id
            ORDER BY o.created_at DESC
        """)
        orders = [dict(row) for row in c.fetchall()]
        return render_template('admin/vendor_orders.html', orders=orders)

@admin_bp.route('/my_orders', methods=['GET', 'POST'])
def admin_my_orders():
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('admin.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT o.*, p.title
            FROM orders o
            JOIN products p ON o.product_id = p.id
            WHERE o.vendor_id = ?
            ORDER BY o.created_at DESC
        """, (session['admin_id'],))
        orders = [dict(row) for row in c.fetchall()]
        
        if request.method == 'POST':
            order_id = request.form.get('order_id', type=int)
            action = request.form.get('action')
            
            c.execute("SELECT * FROM orders WHERE id = ? AND vendor_id = ?", (order_id, session['admin_id']))
            order = c.fetchone()
            if not order:
                flash("Order not found or you don't have permission to modify it.", 'error')
                return redirect(url_for('admin.admin_my_orders'))
            
            if action == 'ship':
                c.execute("UPDATE orders SET status = 'shipped' WHERE id = ?", (order_id,))
                conn.commit()
                flash(f"Order {order_id} marked as shipped.", 'success')
            elif action == 'deliver':
                c.execute("UPDATE orders SET status = 'delivered', escrow_status = 'released' WHERE id = ?", (order_id,))
                conn.commit()
                flash(f"Order {order_id} marked as delivered and escrow released.", 'success')
            elif action == 'cancel':
                c.execute("UPDATE orders SET status = 'cancelled', escrow_status = 'refunded' WHERE id = ?", (order_id,))
                conn.commit()
                flash(f"Order {order_id} cancelled and refunded.", 'success')
            
            return redirect(url_for('admin.admin_my_orders'))
        
        return render_template('admin/my_orders.html', orders=orders)

@admin_bp.route('/orders/resolve_dispute/<int:order_id>', methods=['POST'])
def admin_order_resolve_dispute(order_id):
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    action = request.form.get('action')
    refund_percentage = request.form.get('refund_percentage', type=float, default=0.0)
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM orders WHERE id = ? AND dispute_status = 'pending'", (order_id,))
        order = c.fetchone()
        if not order:
            flash("Order not found or no pending dispute.", 'error')
            return redirect(url_for('admin.admin_orders'))
        
        if action == 'release':
            c.execute("UPDATE orders SET escrow_status = 'released', dispute_status = 'resolved' WHERE id = ?", (order_id,))
            conn.commit()
            flash(f"Dispute for order {order_id} resolved: Funds released to vendor.", 'success')
        elif action == 'refund':
            c.execute("UPDATE orders SET escrow_status = 'refunded', dispute_status = 'resolved', status = 'cancelled' WHERE id = ?", (order_id,))
            conn.commit()
            flash(f"Dispute for order {order_id} resolved: Funds refunded to buyer.", 'success')
        elif action == 'partial_refunded':
            refund_amount_btc = order['amount_btc'] * (refund_percentage / 100)
            vendor_amount_btc = order['amount_btc'] - refund_amount_btc
            # Placeholder: Implement partial refund logic
            c.execute("UPDATE orders SET escrow_status = 'partially_refunded', dispute_status = 'resolved' WHERE id = ?", (order_id,))
            conn.commit()
            flash(f"Dispute for order {order_id} resolved: {refund_percentage}% refunded to buyer.", 'success')
        else:
            flash("Invalid action.", 'error')
        
        return redirect(url_for('admin.admin_orders'))

@admin_bp.route('/vendors/approve/<int:vendor_id>', methods=['POST'])
def admin_approve_vendor(vendor_id):
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM vendor_subscriptions WHERE vendor_id = ? AND status = 'pending'", (vendor_id,))
        subscription = c.fetchone()
        if not subscription:
            flash("Vendor application not found.", 'error')
            return redirect(url_for('admin.manage_users'))
        
        # Verify bond payment
        from utils.bitcoin import check_payment
        txid = check_payment(subscription['payment_address'], subscription['bond_amount_usd'] / get_usd_to_btc_rate())
        if txid:
            c.execute("UPDATE vendor_subscriptions SET status = 'active', payment_txid = ? WHERE vendor_id = ?", (txid, vendor_id))
            c.execute("UPDATE users SET role = 'vendor' WHERE id = ?", (vendor_id,))
            conn.commit()
            
            # Initialize vendor level record
            initialize_vendor_level(vendor_id)
            
            flash(f"Vendor {vendor_id} approved successfully.", 'success')
        else:
            flash("Bond payment not received.", 'error')
        
        return redirect(url_for('admin.manage_users'))

@admin_bp.route('/messages', methods=['GET', 'POST'])
def messages():
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('admin.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        
        # Fetch sent messages
        c.execute("""
            SELECT * FROM messages 
            WHERE sender_id = ? 
            ORDER BY sent_at DESC
        """, (session['admin_id'],))
        messages = [dict(row) for row in c.fetchall()]
        
        if request.method == 'POST':
            recipient_type = request.form.get('recipient_type')
            recipient_id = request.form.get('recipient_id', type=int)
            subject = request.form.get('subject', '').strip()
            body = request.form.get('body', '').strip()
            
            # Validation
            if not subject or not body:
                flash("Subject and message body are required.", 'error')
                return render_template('admin/messages.html', messages=messages, error="Missing fields.")
            
            if recipient_type in ['vendor', 'user']:
                if not recipient_id:
                    flash("Recipient ID is required for specific user or vendor.", 'error')
                    return render_template('admin/messages.html', messages=messages, error="Missing recipient ID.")
                c.execute("SELECT id, role FROM users WHERE id = ?", (recipient_id,))
                user = c.fetchone()
                if not user or (recipient_type == 'vendor' and user['role'] != 'vendor') or (recipient_type == 'user' and user['role'] != 'user'):
                    flash(f"Invalid {recipient_type} ID.", 'error')
                    return render_template('admin/messages.html', messages=messages, error="Invalid recipient.")
            
            # PGP Encryption (if admin has a PGP key)
            settings = get_settings()
            pgp_key = settings.get('pgp_key', '')
            encrypted_body = None
            plaintext_body = body
            
            if pgp_key and recipient_type in ['vendor', 'user']:
                try:
                    public_key, _ = pgpy.PGPKey.from_blob(pgp_key)
                    message = pgpy.PGPMessage.new(body)
                    encrypted_body = str(public_key.encrypt(message))
                    plaintext_body = None  # Store only encrypted version for specific recipients
                except Exception as e:
                    flash(f"Failed to encrypt message: {str(e)}", 'error')
                    return render_template('admin/messages.html', messages=messages, error="Encryption failed.")
            
            # Insert message
            c.execute("""
                INSERT INTO messages (sender_id, recipient_type, recipient_id, subject, body, encrypted_body)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (session['admin_id'], recipient_type, recipient_id, subject, plaintext_body, encrypted_body))
            conn.commit()
            
            flash("Message sent successfully.", 'success')
            return redirect(url_for('admin.admin_messages'))
        
        return render_template('admin/messages.html', messages=messages) 
@admin_bp.route('/support', methods=['GET'])
@require_admin_role
def manage_support():
    """Display all support tickets with filtering and pagination."""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            # Filters
            status = request.args.get('status', '')
            category = request.args.get('category', '')
            search = request.args.get('search', '').strip()
            page = request.args.get('page', 1, type=int)
            per_page = 10

            # Build query
            query = """
                SELECT t.id, t.user_id, u.pusername, t.subject, t.category, t.priority, t.status, t.created_at, t.updated_at
                FROM tickets t
                JOIN users u ON t.user_id = u.id
                WHERE 1=1
            """
            params = []

            if status:
                query += " AND t.status = ?"
                params.append(status)
            if category:
                query += " AND t.category = ?"
                params.append(category)
            if search:
                query += " AND (t.subject LIKE ? OR t.description LIKE ?)"
                params.extend([f'%{search}%', f'%{search}%'])

            # Count total for pagination
            c.execute(f"SELECT COUNT(*) as total FROM ({query})", params)
            total = c.fetchone()['total']
            total_pages = (total + per_page - 1) // per_page

            # Add pagination
            query += " ORDER BY t.updated_at DESC LIMIT ? OFFSET ?"
            params.extend([per_page, (page - 1) * per_page])

            c.execute(query, params)
            tickets = [dict(row) for row in c.fetchall()]

            # Get available categories and statuses
            c.execute("SELECT DISTINCT category FROM tickets")
            categories = [row['category'] for row in c.fetchall()]
            statuses = ['open', 'in-progress', 'closed']

            return render_template('admin/support.html',
                                 tickets=tickets,
                                 categories=categories,
                                 statuses=statuses,
                                 page=page,
                                 total_pages=total_pages,
                                 status_filter=status,
                                 category_filter=category,
                                 search=search)
    except Exception as e:
        logger.error(f"Error fetching support tickets: {str(e)}")
        flash("Error loading support tickets.", 'error')
        return redirect(url_for('admin.dashboard'))

@admin_bp.route('/support/ticket/<int:ticket_id>', methods=['GET', 'POST'])
@require_admin_role
def view_ticket(ticket_id):
    """View and respond to a specific support ticket."""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT t.id, t.user_id, u.pusername, t.subject, t.description, t.category, t.priority, t.status, t.created_at, t.updated_at
                FROM tickets t
                JOIN users u ON t.user_id = u.id
                WHERE t.id = ?
            """, (ticket_id,))
            ticket = c.fetchone()
            if not ticket:
                flash("Ticket not found.", 'error')
                return redirect(url_for('admin.manage_support'))

            ticket = dict(ticket)

            # Fetch ticket responses
            c.execute("""
                SELECT tr.id, tr.sender_id, u.pusername, tr.body, tr.created_at
                FROM ticket_responses tr
                JOIN users u ON tr.sender_id = u.id
                WHERE tr.ticket_id = ?
                ORDER BY tr.created_at
            """, (ticket_id,))
            responses = [dict(row) for row in c.fetchall()]

            if request.method == 'POST':
                action = request.form.get('action')
                response_body = request.form.get('response_body', '').strip()

                if action == 'respond' and response_body:
                    c.execute("""
                        INSERT INTO ticket_responses (ticket_id, sender_id, body, created_at)
                        VALUES (?, ?, ?, ?)
                    """, (ticket_id, session['user_id'], response_body, datetime.utcnow()))
                    c.execute("""
                        UPDATE tickets SET updated_at = ?, status = ?
                        WHERE id = ?
                    """, (datetime.utcnow(), 'in-progress', ticket_id))
                    conn.commit()
                    flash("Response added successfully.", 'success')
                    logger.info(f"Admin responded to ticket #{ticket_id}")
                    return redirect(url_for('admin.view_ticket', ticket_id=ticket_id))

                elif action == 'update_status':
                    new_status = request.form.get('status')
                    if new_status not in ['open', 'in-progress', 'closed']:
                        flash("Invalid status.", 'error')
                    else:
                        c.execute("""
                            UPDATE tickets SET status = ?, updated_at = ?
                            WHERE id = ?
                        """, (new_status, datetime.utcnow(), ticket_id))
                        conn.commit()
                        flash(f"Ticket status updated to {new_status}.", 'success')
                        logger.info(f"Ticket #{ticket_id} status updated to {new_status}")
                        return redirect(url_for('admin.view_ticket', ticket_id=ticket_id))

                else:
                    flash("Response body is required to respond.", 'error')

            return render_template('admin/ticket.html',
                                 ticket=ticket,
                                 responses=responses,
                                 statuses=['open', 'in-progress', 'closed'])
    except Exception as e:
        logger.error(f"Error handling ticket #{ticket_id}: {str(e)}")
        flash("Error handling ticket.", 'error')
        return redirect(url_for('admin.manage_support'))

def ensure_vendor_balance(user_id):
    """Initialize vendor balance if not exists."""
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT balance_btc FROM balances WHERE user_id = ?", (user_id,))
        if not c.fetchone():
            c.execute("""
                INSERT INTO balances (user_id, balance_usd, last_updated)
                VALUES (?, 0.0, ?)
            """, (user_id, datetime.utcnow()))
            conn.commit()

def get_order_fee_percentage():
    """Retrieve current order fee percentage."""
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT percentage FROM fees WHERE fee_type = 'order'")
        result = c.fetchone()
        return result['percentage'] / 100 if result else 0.05  # Default 5% if not found

@admin_bp.route('/fees')
def admin_fees():
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 10
    fee_type = request.args.get('fee_type', '').strip()
    
    query = "SELECT id, fee_type, percentage, description, updated_at FROM fees WHERE 1=1"
    params = []
    
    if fee_type:
        query += " AND fee_type LIKE ?"
        params.append(f"%{fee_type}%")
    
    query += " ORDER BY updated_at DESC"
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute(query, params)
        total_fees = len(c.fetchall())
        total_pages = (total_fees + per_page - 1) // per_page
        
        offset = (page - 1) * per_page
        query += " LIMIT ? OFFSET ?"
        params.extend([per_page, offset])
        
        c.execute(query, params)
        fees = [dict(row) for row in c.fetchall()]
    
    return render_template('admin/fees.html',
        fees=fees,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        total_fees=total_fees
    )

@admin_bp.route('/update_fee/<int:fee_id>', methods=['POST'])
def admin_update_fee(fee_id):
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    percentage = request.form.get('percentage', type=float)
    if percentage is None or percentage < 0 or percentage > 100:
        flash('Percentage must be between 0 and 100.', 'error')
        return redirect(url_for('admin.admin_fees'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT fee_type FROM fees WHERE id = ?", (fee_id,))
        fee = c.fetchone()
        if not fee:
            flash('Fee not found.', 'error')
            return redirect(url_for('admin.admin_fees'))
        
        c.execute("""
            UPDATE fees
            SET percentage = ?, updated_at = ?
            WHERE id = ?
        """, (percentage, datetime.utcnow(), fee_id))
        conn.commit()
        flash(f"Fee for {fee['fee_type']} updated to {percentage}% successfully.", 'success')
    
    return redirect(url_for('admin.admin_fees'))


@admin_bp.route('/vendor_disputes')
def admin_vendor_disputes():
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 10
    search = request.args.get('search', '').strip()
    status = request.args.get('status', '')
    
    query = """
        SELECT d.id, d.order_id, u.pusername AS buyer_username, v.pusername AS vendor_username,
               p.title AS product_title, o.amount_btc, o.amount_usd, d.status, d.reason, d.created_at,
               o.vendor_id
        FROM disputes d
        JOIN orders o ON d.order_id = o.id
        JOIN users u ON o.user_id = u.id
        JOIN users v ON o.vendor_id = v.id
        JOIN products p ON o.product_id = p.id
        WHERE 1=1
    """
    params = []
    
    if search:
        query += " AND (d.order_id LIKE ? OR u.pusername LIKE ? OR v.pusername LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
    if status:
        query += " AND d.status = ?"
        params.append(status)
    
    query += " ORDER BY d.created_at DESC"
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute(query, params)
        total_disputes = len(c.fetchall())
        total_pages = (total_disputes + per_page - 1) // per_page
        
        offset = (page - 1) * per_page
        query += " LIMIT ? OFFSET ?"
        params.extend([per_page, offset])
        
        c.execute(query, params)
        disputes = [dict(row) for row in c.fetchall()]
    
    return render_template('admin/vendor_disputes.html',
        disputes=disputes,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        total_disputes=total_disputes
    )

@admin_bp.route('/vendor_dispute_details/<int:dispute_id>')
def admin_vendor_dispute_details(dispute_id):
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT d.id, d.order_id, u.pusername AS buyer_username, v.pusername AS vendor_username,
                   p.title AS product_title, o.amount_btc, o.amount_usd, o.status AS order_status,
                   d.status, d.reason, d.comments, d.created_at, d.resolved_at,
                   su.pusername AS submitted_by_username, e.status AS escrow_status,
                   e.escrow_address, e.txid, o.vendor_id
            FROM disputes d
            JOIN orders o ON d.order_id = o.id
            JOIN users u ON o.user_id = u.id
            JOIN users v ON o.vendor_id = v.id
            JOIN products p ON o.product_id = p.id
            JOIN users su ON d.submitted_by = su.id
            LEFT JOIN escrow e ON d.order_id = e.order_id
            WHERE d.id = ?
        """, (dispute_id,))
        dispute = c.fetchone()
        if not dispute:
            flash('Dispute not found.', 'error')
            return redirect(url_for('admin.admin_vendor_disputes'))
        
        return render_template('admin/vendor_dispute_details.html',
            dispute=dict(dispute)
        )

@admin_bp.route('/resolve_vendor_dispute/<int:dispute_id>', methods=['POST'])
def admin_resolve_vendor_dispute(dispute_id):
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    action = request.form.get('action')
    comments = request.form.get('comments', '').strip()
    if action not in ['release', 'refund', 'escalate']:
        flash('Invalid action.', 'error')
        return redirect(url_for('admin.admin_vendor_disputes'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT d.status, d.order_id, o.status AS order_status, e.status AS escrow_status,
                   o.vendor_id, o.amount_usd
            FROM disputes d
            JOIN orders o ON d.order_id = o.id
            LEFT JOIN escrow e ON d.order_id = e.order_id
            WHERE d.id = ?
        """, (dispute_id,))
        result = c.fetchone()
        if not result:
            flash('Dispute not found.', 'error')
            return redirect(url_for('admin.admin_vendor_disputes'))
        
        if result['status'] != 'open':
            flash('Cannot resolve a dispute that is already resolved or escalated.', 'error')
            return redirect(url_for('admin.admin_vendor_disputes'))
        
        new_dispute_status = 'resolved' if action in ['release', 'refund'] else 'escalated'
        new_order_status = None
        new_escrow_status = None
        
        if action == 'release':
            new_order_status = 'completed'
            new_escrow_status = 'released'
            # Update vendor balance with fee deduction
            fee_percentage = get_order_fee_percentage()
            net_amount = result['amount_usd'] * (1 - fee_percentage)
            ensure_vendor_balance(result['vendor_id'])
            c.execute("""
                UPDATE balances
                SET balance_usd = balance_usd + ?, last_updated = ?
                WHERE user_id = ?
            """, (net_amount, datetime.utcnow(), result['vendor_id']))
        elif action == 'refund':
            new_order_status = 'cancelled'
            new_escrow_status = 'refunded'
        elif action == 'escalate':
            new_order_status = 'disputed'
            new_escrow_status = 'disputed'
        
        c.execute("""
            UPDATE disputes
            SET status = ?, comments = ?, resolved_at = ?
            WHERE id = ?
        """, (new_dispute_status, comments, datetime.utcnow() if new_dispute_status == 'resolved' else None, dispute_id))
        
        c.execute("UPDATE orders SET status = ?, dispute_status = ? WHERE id = ?",
                  (new_order_status, new_dispute_status, result['order_id']))
        
        if new_escrow_status:
            c.execute("UPDATE escrow SET status = ? WHERE order_id = ?",
                      (new_escrow_status, result['order_id']))
        
        conn.commit()
        
        action_text = {
            'release': 'resolved by releasing funds to vendor',
            'refund': 'resolved by refunding funds to buyer',
            'escalate': 'escalated for moderation'
        }[action]
        flash(f"Dispute #{dispute_id} {action_text} successfully.", 'success')
    
    return redirect(url_for('admin.admin_vendor_disputes'))

def get_withdrawal_fee_percentage():
    """Retrieve current withdrawal fee percentage."""
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT percentage FROM fees WHERE fee_type = 'withdrawal'")
        result = c.fetchone()
        return result['percentage'] / 100 if result else 0.02  # Default 2% if not found

@admin_bp.route('/security')
def admin_security():
    if not is_admin():
        return redirect(url_for('admin.login'))
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT setting_name, value FROM security_settings")
        settings = {row['setting_name']: row['value'] for row in c.fetchall()}
        # Fetch audit trail (last 10 security changes)
        c.execute("SELECT timestamp, action, admin FROM security_audit ORDER BY timestamp DESC LIMIT 10")
        audit_trail = [dict(row) for row in c.fetchall()]
    defaults = {
        '2fa_admin': 'disabled',
        '2fa_vendor': 'disabled',
        'password_min_length': '12',
        'password_require_special': 'yes',
        'session_timeout_minutes': '30',
        'max_failed_logins': '5',
        'lockout_minutes': '15',
        'admin_action_logging': 'enabled',
        'admin_login_captcha': 'enabled'
    }
    settings = {**defaults, **settings}
    return render_template('admin/security.html', settings=settings, audit_trail=audit_trail)

@admin_bp.route('/ddos_protection', methods=['GET', 'POST'])
def admin_ddos_protection():
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    from config import Config
    config = Config()
    
    if request.method == 'POST':
        # Update DDoS protection settings
        settings_updates = {
            'ddos_enabled': request.form.get('ddos_enabled') == '1',
            'block_suspicious_user_agents': request.form.get('block_suspicious_user_agents') == '1',
            'enable_ip_reputation': request.form.get('enable_ip_reputation') == '1',
            'recaptcha_enabled': request.form.get('recaptcha_enabled') == '1',
            'ddos_max_requests_per_minute': int(request.form.get('ddos_max_requests_per_minute', 60)),
            'ddos_max_requests_per_hour': int(request.form.get('ddos_max_requests_per_hour', 1000)),
            'ddos_max_requests_per_day': int(request.form.get('ddos_max_requests_per_day', 10000)),
            'ddos_burst_limit': int(request.form.get('ddos_burst_limit', 10)),
            'ddos_burst_window': int(request.form.get('ddos_burst_window', 5)),
            'ddos_block_duration': int(request.form.get('ddos_block_duration', 3600)),
            'recaptcha_site_key': request.form.get('recaptcha_site_key', ''),
            'recaptcha_secret_key': request.form.get('recaptcha_secret_key', ''),
            'ddos_whitelist_ips': request.form.get('ddos_whitelist_ips', '').split(',') if request.form.get('ddos_whitelist_ips') else []
        }
        
        # Update environment variables (in a real app, you'd update a config file or database)
        flash("DDoS protection settings updated successfully.", 'success')
        return redirect(url_for('admin.admin_ddos_protection'))
    
    # Get current settings
    settings = {
        'ddos_enabled': config.DDOS_ENABLED,
        'block_suspicious_user_agents': config.BLOCK_SUSPICIOUS_USER_AGENTS,
        'enable_ip_reputation': config.ENABLE_IP_REPUTATION,
        'recaptcha_enabled': config.RECAPTCHA_ENABLED,
        'ddos_max_requests_per_minute': config.DDOS_MAX_REQUESTS_PER_MINUTE,
        'ddos_max_requests_per_hour': config.DDOS_MAX_REQUESTS_PER_HOUR,
        'ddos_max_requests_per_day': config.DDOS_MAX_REQUESTS_PER_DAY,
        'ddos_burst_limit': config.DDOS_BURST_LIMIT,
        'ddos_burst_window': config.DDOS_BURST_WINDOW,
        'ddos_block_duration': config.DDOS_BLOCK_DURATION,
        'recaptcha_site_key': config.RECAPTCHA_SITE_KEY,
        'recaptcha_secret_key': config.RECAPTCHA_SECRET_KEY,
        'ddos_whitelist_ips': config.DDOS_WHITELIST_IPS
    }
    
    # Get DDoS statistics
    stats = ddos_protection.get_statistics() if ddos_protection else {
        'blocked_ips_count': 0,
        'whitelisted_ips_count': len(settings['ddos_whitelist_ips']),
        'recent_blocks': [],
        'total_requests_today': 0,
        'blocked_requests_today': 0
    }
    
    return render_template('admin/ddos_protection.html', settings=settings, stats=stats)

@admin_bp.route('/update_security', methods=['POST'])
def admin_update_security():
    if not is_admin():
        return redirect(url_for('admin.login'))
    settings = {
        '2fa_admin': 'enabled' if request.form.get('2fa_admin') == 'enabled' else 'disabled',
        '2fa_vendor': 'enabled' if request.form.get('2fa_vendor') == 'enabled' else 'disabled',
        'password_min_length': request.form.get('password_min_length', type=int),
        'password_require_special': 'yes' if request.form.get('password_require_special') == 'yes' else 'no',
        'session_timeout_minutes': request.form.get('session_timeout_minutes', type=int),
        'max_failed_logins': request.form.get('max_failed_logins', type=int),
        'lockout_minutes': request.form.get('lockout_minutes', type=int),
        'admin_action_logging': 'enabled' if request.form.get('admin_action_logging') == 'enabled' else 'disabled',
        'admin_login_captcha': 'enabled' if request.form.get('admin_login_captcha') == 'enabled' else 'disabled'
    }
    # Validate inputs
    if not (8 <= settings['password_min_length'] <= 50):
        flash('Password minimum length must be between 8 and 50.', 'error')
        return redirect(url_for('admin.admin_security'))
    if not (5 <= settings['session_timeout_minutes'] <= 1440):
        flash('Session timeout must be between 5 and 1440 minutes.', 'error')
        return redirect(url_for('admin.admin_security'))
    if not (3 <= settings['max_failed_logins'] <= 20):
        flash('Max failed logins must be between 3 and 20.', 'error')
        return redirect(url_for('admin.admin_security'))
    if not (1 <= settings['lockout_minutes'] <= 120):
        flash('Lockout duration must be between 1 and 120 minutes.', 'error')
        return redirect(url_for('admin.admin_security'))
    with get_db_connection() as conn:
        c = conn.cursor()
        for setting_name, value in settings.items():
            c.execute("""
                UPDATE security_settings
                SET value = ?, updated_at = ?
                WHERE setting_name = ?
            """, (str(value), datetime.utcnow(), setting_name))
        # Log audit trail
        c.execute("INSERT INTO security_audit (timestamp, action, admin) VALUES (?, ?, ?)", (datetime.utcnow(), 'Updated security settings', session.get('username', 'admin')))
        # Encrypted admin action log
        c.execute("SELECT pgp_public_key FROM users WHERE id = ?", (session['user_id'],))
        row = c.fetchone()
        pgp_pubkey = row['pgp_public_key'] if row and row['pgp_public_key'] else None
        c.execute("SELECT value FROM security_settings WHERE setting_name = 'admin_action_logging'")
        admin_action_logging = c.fetchone()
        admin_action_logging = admin_action_logging['value'] if admin_action_logging else 'enabled'
        if admin_action_logging == 'enabled' and pgp_pubkey:
            try:
                log_admin_action_encrypted("Admin updated security settings", session.get('username', 'admin'), pgp_pubkey)
            except Exception as e:
                logger.error(f"Failed to log encrypted admin action: {e}")
        conn.commit()
    flash('Security settings updated successfully.', 'success')
    return redirect(url_for('admin.admin_security'))

@admin_bp.route('/ban_vendor/<int:vendor_id>', methods=['POST'])
def admin_ban_vendor(vendor_id):
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT pusername FROM users WHERE id = ? AND role = 'vendor'", (vendor_id,))
        vendor = c.fetchone()
        if not vendor:
            flash('Vendor not found.', 'error')
            return redirect(url_for('admin.admin_vendor_disputes'))
        
        # Ban vendor
        c.execute("UPDATE users SET status = 'banned' WHERE id = ?", (vendor_id,))
        
        # Cancel open orders
        c.execute("""
            UPDATE orders
            SET status = 'cancelled', dispute_status = NULL
            WHERE vendor_id = ? AND status NOT IN ('completed', 'cancelled')
        """, (vendor_id,))
        
        # Update escrow for cancelled orders
        c.execute("""
            UPDATE escrow
            SET status = 'refunded'
            WHERE order_id IN (
                SELECT id FROM orders
                WHERE vendor_id = ? AND status = 'cancelled'
            )
        """, (vendor_id,))
        
        conn.commit()
        flash(f"Vendor {vendor['pusername']} banned successfully. Their open orders have been cancelled.", 'success')
    
    return redirect(url_for('admin.admin_vendor_disputes'))

@admin_bp.route('/admin/packages', methods=['GET', 'POST'])
def admin_packages():
    if not is_admin():
        flash("Only admins can access this page.", 'error')
        return redirect(url_for('public.index'))

    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            if request.method == 'POST':
                action = request.form.get('action')
                if action == 'add':
                    title = request.form.get('title')
                    features = request.form.get('features')
                    product_limit = request.form.get('product_limit', type=int)
                    price_usd = request.form.get('price_usd', type=float)
                    free = 1 if request.form.get('free') == '1' else 0

                    if not all([title, features, product_limit, price_usd]) or product_limit < 1 or price_usd < 0:
                        flash("Invalid package details.", 'error')
                    else:
                        c.execute("""
                            INSERT INTO packages (title, features, product_limit, price_usd, free)
                            VALUES (?, ?, ?, ?, ?)
                        """, (title, features, product_limit, price_usd, free))
                        conn.commit()
                        flash("Package added successfully!", 'success')

                elif action == 'edit':
                    package_id = request.form.get('package_id', type=int)
                    title = request.form.get('title')
                    features = request.form.get('features')
                    product_limit = request.form.get('product_limit', type=int)
                    price_usd = request.form.get('price_usd', type=float)
                    free = 1 if request.form.get('free') == '1' else 0

                    if not all([package_id, title, features, product_limit, price_usd]) or product_limit < 1 or price_usd < 0:
                        flash("Invalid package details.", 'error')
                    else:
                        c.execute("""
                            UPDATE packages 
                            SET title = ?, features = ?, product_limit = ?, price_usd = ?, free = ?
                            WHERE id = ?
                        """, (title, features, product_limit, price_usd, free, package_id))
                        if c.rowcount > 0:
                            conn.commit()
                            flash("Package updated successfully!", 'success')
                        else:
                            flash("Package not found.", 'error')

                elif action == 'delete':
                    package_id = request.form.get('package_id', type=int)
                    if not package_id:
                        flash("Invalid package ID.", 'error')
                    else:
                        # Check if package is in use
                        c.execute("SELECT COUNT(*) FROM vendor_subscriptions WHERE package_id = ?", (package_id,))
                        if c.fetchone()[0] > 0:
                            flash("Cannot delete package in use by vendors.", 'error')
                        else:
                            c.execute("DELETE FROM packages WHERE id = ?", (package_id,))
                            if c.rowcount > 0:
                                conn.commit()
                                flash("Package deleted successfully!", 'success')
                            else:
                                flash("Package not found.", 'error')

            c.execute("SELECT * FROM packages")
            packages = [dict(row) for row in c.fetchall()]
        
        return render_template('admin/packages.html', packages=packages)
    except Exception as e:
        print(f"Error in admin_packages: {str(e)}")
        flash("An error occurred.", 'error')
        return redirect(url_for('public.index'))
@admin_bp.route('/logout')
def admin_logout():
    session.pop('admin_id', None)
    session.pop('role', None)
    flash("Logged out successfully.", 'success')
    return redirect(url_for('admin.login'))


def is_valid_btc_address(address):
    """Validate Bitcoin testnet address."""
    try:
        # Basic regex for Bitcoin address (testnet starts with 'm', 'n', or '2')
        pattern = r'^(tb1|[mn2])[a-zA-HJ-NP-Z0-9]{25,59}$'
        if not re.match(pattern, address):
            return False
        # Use bitcoinlib to validate
        from bitcoinlib.keys import Address
        addr = Address.import_address(address, network='testnet')
        return addr.network.name == 'testnet'
    except Exception:
        return False

@admin_bp.route('/withdrawals')
def admin_withdrawals():
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 10
    search = request.args.get('search', '').strip()
    status = request.args.get('status', '')
    
    query = """
        SELECT w.id, u.pusername AS vendor_username, w.amount_usd, w.amount_btc, w.wallet_address,
               w.status, w.requested_at, w.crypto_currency, w.crypto_amount
        FROM withdrawals w
        JOIN users u ON w.user_id = u.id
        WHERE u.role = 'vendor'
    """
    params = []
    
    if search:
        query += " AND (w.id LIKE ? OR u.pusername LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])
    if status:
        query += " AND w.status = ?"
        params.append(status)
    
    query += " ORDER BY w.requested_at DESC"
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute(query, params)
        total_withdrawals = len(c.fetchall())
        total_pages = (total_withdrawals + per_page - 1) // per_page
        
        offset = (page - 1) * per_page
        query += " LIMIT ? OFFSET ?"
        params.extend([per_page, offset])
        
        c.execute(query, params)
        withdrawals = [dict(row) for row in c.fetchall()]
    
    return render_template('admin/withdrawal/requests.html',
        withdrawals=withdrawals,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        total_withdrawals=total_withdrawals
    )

@admin_bp.route('/withdrawal_details/<int:withdrawal_id>')
def admin_withdrawal_details(withdrawal_id):
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT w.id, u.pusername AS vendor_username, w.amount_btc, w.wallet_address as btc_address,
                   w.status, w.txid, w.rejection_reason, w.requested_at as created_at, b.balance_usd
            FROM withdrawals w
            JOIN users u ON w.user_id = u.id
            LEFT JOIN balances b ON w.user_id = b.user_id
            WHERE w.id = ? AND u.role = 'vendor'
        """, (withdrawal_id,))
        withdrawal = c.fetchone()
        if not withdrawal:
            flash('Withdrawal not found or not a vendor request.', 'error')
            return redirect(url_for('admin.admin_withdrawals'))
        
        withdrawal_dict = dict(withdrawal)
        # Calculate fee amount for approved withdrawals
        if withdrawal_dict['status'] == 'approved':
            fee_percentage = get_withdrawal_fee_percentage()
            withdrawal_dict['fee_amount'] = withdrawal_dict['amount_btc'] * fee_percentage
        else:
            withdrawal_dict['fee_amount'] = None
        
        return render_template('admin/withdrawal/details.html',
            withdrawal=withdrawal_dict
        )


@admin_bp.route('/reject_withdrawal/<int:withdrawal_id>', methods=['POST'])
def admin_reject_withdrawal(withdrawal_id):
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    rejection_reason = request.form.get('rejection_reason', '').strip()
    if not rejection_reason:
        flash('Rejection reason is required.', 'error')
        return redirect(url_for('admin.admin_withdrawals'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT w.status, u.pusername
            FROM withdrawals w
            JOIN users u ON w.user_id = u.id
            WHERE w.id = ? AND u.role = 'vendor'
        """, (withdrawal_id,))
        withdrawal = c.fetchone()
        if not withdrawal:
            flash('Withdrawal not found or not a vendor request.', 'error')
            return redirect(url_for('admin.admin_withdrawals'))
        
        if withdrawal['status'] != 'pending':
            flash('Cannot reject a withdrawal that is already approved or rejected.', 'error')
            return redirect(url_for('admin.admin_withdrawals'))
        
        c.execute("""
            UPDATE withdrawals
            SET status = 'rejected', rejection_reason = ?
            WHERE id = ?
        """, (rejection_reason, withdrawal_id))
        conn.commit()
        flash(f"Withdrawal #{withdrawal_id} for {withdrawal['pusername']} rejected successfully.", 'success')
    
    return redirect(url_for('admin.admin_withdrawals'))


@admin_bp.route('/user_orders')
def admin_user_orders():
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    user_id = request.args.get('user_id', type=int)
    if user_id:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT o.id, u.pusername AS buyer_username, v.pusername AS vendor_username,
                       p.title AS product_title, o.amount_btc, o.amount_usd, o.status, 
                       o.created_at, o.dispute_status
                FROM orders o
                JOIN users u ON o.user_id = u.id
                JOIN products p ON o.product_id = p.id
                JOIN users v ON o.vendor_id = v.id
                WHERE o.user_id = ?
                ORDER BY o.created_at DESC
            """, (user_id,))
            orders = [dict(row) for row in c.fetchall()]
            c.execute("SELECT pusername FROM users WHERE id = ?", (user_id,))
            user = c.fetchone()
            if not user:
                flash('User not found.', 'error')
                return redirect(url_for('admin.manage_users'))
        return render_template('admin/orders.html', orders=orders, user=user['pusername'])
    
    flash('User ID required to view orders.', 'error')
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/vendor_orders')
def admin_vendor_orders():
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    vendor_id = request.args.get('vendor_id', type=int)
    if vendor_id:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT o.id, u.pusername AS buyer_username, v.pusername AS vendor_username,
                       p.title AS product_title, o.amount_btc, o.amount_usd, o.status, 
                       o.created_at, o.dispute_status
                FROM orders o
                JOIN users u ON o.user_id = u.id
                JOIN products p ON o.product_id = p.id
                JOIN users v ON o.vendor_id = v.id
                WHERE o.vendor_id = ?
                ORDER BY o.created_at DESC
            """, (vendor_id,))
            orders = [dict(row) for row in c.fetchall()]
            c.execute("SELECT pusername FROM users WHERE id = ?", (vendor_id,))
            vendor = c.fetchone()
            if not vendor:
                flash('Vendor not found.', 'error')
                return redirect(url_for('admin.manage_vendors'))
        return render_template('admin/orders.html', orders=orders, vendor=vendor['pusername'])
    
    flash('Vendor ID required to view orders.', 'error')
    return redirect(url_for('admin.manage_vendors'))

@admin_bp.route('/orders')
def admin_orders():
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 10
        search = request.args.get('search', '').strip()
        status = request.args.get('status', '')
        
        query = """
            SELECT o.id, u.pusername AS buyer_username, v.pusername AS vendor_username,
                   p.title AS product_title, o.amount_btc, o.amount_usd, o.status, 
                   o.created_at, o.dispute_status
            FROM orders o
            JOIN users u ON o.user_id = u.id
            JOIN users v ON o.vendor_id = v.id
            JOIN products p ON o.product_id = p.id
            WHERE 1=1
        """
        params = []
        
        if search:
            query += " AND (o.id LIKE ? OR u.pusername LIKE ? OR v.pusername LIKE ? OR p.title LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%", f"%{search}%"])
        if status:
            query += " AND o.status = ?"
            params.append(status)
        
        query += " ORDER BY o.created_at DESC"
        
        with get_db_connection() as conn:
            c = conn.cursor()
            # Get total count for pagination
            count_query = query.replace("SELECT o.id, u.pusername AS buyer_username, v.pusername AS vendor_username, p.title AS product_title, o.amount_btc, o.amount_usd, o.status, o.created_at, o.dispute_status", "SELECT COUNT(*)")
            c.execute(count_query, params)
            count_result = c.fetchone()
            total_orders = count_result['COUNT(*)'] if count_result else 0
            total_pages = (total_orders + per_page - 1) // per_page
            
            offset = (page - 1) * per_page
            query += " LIMIT ? OFFSET ?"
            params.extend([per_page, offset])
            
            c.execute(query, params)
            orders = [dict(row) for row in c.fetchall()]
    
        # Get order statistics
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT COUNT(*) as total FROM orders")
            result = c.fetchone()
            total_all_orders = result['total'] if result else 0
            
            c.execute("SELECT COUNT(*) as pending FROM orders WHERE status = 'pending'")
            result = c.fetchone()
            pending_orders = result['pending'] if result else 0
            
            c.execute("SELECT COUNT(*) as disputed FROM orders WHERE dispute_status = 'open'")
            result = c.fetchone()
            disputed_orders = result['disputed'] if result else 0
            
            c.execute("SELECT SUM(amount_usd) as total_sales FROM orders WHERE status = 'completed'")
            result = c.fetchone()
            total_sales = result['total_sales'] if result and result['total_sales'] is not None else 0.0
        
        return render_template('admin/orders.html',
            orders=orders,
            page=page,
            per_page=per_page,
            total_pages=total_pages,
            total_orders=total_orders,
            total_all_orders=total_all_orders,
            pending_orders=pending_orders,
            disputed_orders=disputed_orders,
            total_sales=total_sales
        )
    except Exception as e:
        logger.error(f"Error in admin_orders: {str(e)}")
        flash(f"An error occurred while loading orders: {str(e)}", 'error')
        return render_template('admin/orders.html',
            orders=[],
            page=1,
            per_page=10,
            total_pages=0,
            total_orders=0,
            total_all_orders=0,
            pending_orders=0,
            disputed_orders=0,
            total_sales=0.0
        )

@admin_bp.route('/order_details/<int:order_id>')
def admin_order_details(order_id):
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT o.id, u.pusername AS buyer_username, v.pusername AS vendor_username,
                   p.title AS product_title, o.amount_btc, o.amount_usd, o.status, 
                   o.dispute_status, o.created_at, o.escrow_status
            FROM orders o
            JOIN users u ON o.user_id = u.id
            JOIN users v ON o.vendor_id = v.id
            JOIN products p ON o.product_id = p.id
            WHERE o.id = ?
        """, (order_id,))
        order = c.fetchone()
        if not order:
            flash('Order not found.', 'error')
            return redirect(url_for('admin.admin_orders'))
        
        c.execute("""
            SELECT multisig_address, buyer_address, vendor_address, escrow_address,
                   amount_usd, status, txid
            FROM escrow
            WHERE order_id = ?
        """, (order_id,))
        escrow = c.fetchone()
        
        return render_template('admin/order_details.html',
            order=dict(order),
            escrow=dict(escrow) if escrow else None
        )

@admin_bp.route('/update_order_status/<int:order_id>', methods=['POST'])
def admin_update_order_status(order_id):
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    new_status = request.form.get('status')
    if new_status not in ['pending', 'processing', 'shipped', 'completed', 'cancelled']:
        flash('Invalid status.', 'error')
        return redirect(url_for('admin.admin_orders'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT status FROM orders WHERE id = ?", (order_id,))
        order = c.fetchone()
        if not order:
            flash('Order not found.', 'error')
            return redirect(url_for('admin.admin_orders'))
        
        if order['status'] in ['completed', 'cancelled', 'disputed']:
            flash('Cannot update status of completed, cancelled, or disputed orders.', 'error')
            return redirect(url_for('admin.admin_orders'))
        
        c.execute("UPDATE orders SET status = ? WHERE id = ?", (new_status, order_id))
        conn.commit()
        flash(f"Order #{order_id} status updated to {new_status}.", 'success')
    
    return redirect(url_for('admin.admin_orders'))

@admin_bp.route('/bulk_update_orders', methods=['POST'])
def admin_bulk_update_orders():
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    order_ids = request.form.getlist('order_ids')
    new_status = request.form.get('status')
    
    if not order_ids or not new_status:
        flash('Please select orders and a status to update.', 'error')
        return redirect(url_for('admin.admin_orders'))
    
    if new_status not in ['pending', 'processing', 'shipped', 'completed', 'cancelled']:
        flash('Invalid status.', 'error')
        return redirect(url_for('admin.admin_orders'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        updated_count = 0
        for order_id in order_ids:
            c.execute("SELECT status FROM orders WHERE id = ?", (order_id,))
            order = c.fetchone()
            if order and order['status'] not in ['completed', 'cancelled', 'disputed']:
                c.execute("UPDATE orders SET status = ? WHERE id = ?", (new_status, order_id))
                updated_count += 1
        
        conn.commit()
        flash(f"Successfully updated {updated_count} orders to {new_status}.", 'success')
    
    return redirect(url_for('admin.admin_orders'))

@admin_bp.route('/approve_withdrawal/<int:withdrawal_id>', methods=['POST'])
def admin_approve_withdrawal(withdrawal_id):
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT w.status, w.amount_usd, w.wallet_address, u.pusername, w.user_id, w.amount_btc
            FROM withdrawals w
            JOIN users u ON w.user_id = u.id
            WHERE w.id = ? AND u.role = 'vendor'
        """, (withdrawal_id,))
        withdrawal = c.fetchone()
        if not withdrawal:
            flash('Withdrawal not found or not a vendor request.', 'error')
            return redirect(url_for('admin.admin_withdrawals'))
        
        if withdrawal['status'] != 'pending':
            flash('Cannot approve a withdrawal that is already approved or rejected.', 'error')
            return redirect(url_for('admin.admin_withdrawals'))
        
        if not is_valid_btc_address(withdrawal['wallet_address']):
            flash('Invalid Bitcoin testnet address.', 'error')
            return redirect(url_for('admin.admin_withdrawals'))
        
        # Check vendor balance with withdrawal fee
        fee_percentage = get_withdrawal_fee_percentage()
        fee_amount = withdrawal['amount_usd'] * fee_percentage
        total_deduction = withdrawal['amount_usd'] + fee_amount
        
        # Ensure vendor has a balance record
        c.execute("SELECT balance_usd FROM balances WHERE user_id = ?", (withdrawal['user_id'],))
        balance = c.fetchone()
        if not balance:
            # Create balance record if it doesn't exist
            c.execute("INSERT INTO balances (user_id, balance_usd, balance_btc, balance_xmr) VALUES (?, 0, 0, 0)", (withdrawal['user_id'],))
            balance = {'balance_usd': 0.0}
        
        if balance['balance_usd'] < total_deduction:
            flash(f"Insufficient balance for {withdrawal['pusername']}. Available: {balance['balance_usd']:.2f} USD, Required: {total_deduction:.2f} USD", 'error')
            return redirect(url_for('admin.admin_withdrawals'))
        
        # Simulate Bitcoin transaction (replace with bitcoinlib integration if needed)
        try:
            txid = f"mock_txid_{secrets.token_hex(16)}"
            # Uncomment for bitcoinlib integration (testnet):
            """
            wallet = wallet_create_or_open('marketplace_wallet', network='testnet')
            t = wallet.send_to(withdrawal['wallet_address'], int(withdrawal['amount_usd'] * 100000000), fee=1000)
            txid = t.txid
            wallet.transaction_import(t)
            """
            # Update withdrawal and balance
            c.execute("""
                UPDATE withdrawals
                SET status = 'approved', txid = ?
                WHERE id = ?
            """, (txid, withdrawal_id))
            c.execute("""
                UPDATE balances
                SET balance_usd = balance_usd - ?, last_updated = ?
                WHERE user_id = ?
            """, (total_deduction, datetime.utcnow(), withdrawal['user_id']))
            conn.commit()
            flash(f"Withdrawal #{withdrawal_id} for {withdrawal['pusername']} approved successfully. TXID: {txid}", 'success')
        except Exception as e:
            flash(f"Failed to process withdrawal: {str(e)}", 'error')
        
        return redirect(url_for('admin.admin_withdrawals'))

@admin_bp.route('/escrow')
def admin_escrow():
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 10
    search = request.args.get('search', '').strip()
    status = request.args.get('status', '')
    
    query = """
        SELECT e.order_id, u.pusername AS buyer_username, v.pusername AS vendor_username,
               p.title AS product_title, e.amount_btc, e.amount_usd, e.status, 
               o.status AS order_status, e.crypto_currency, e.created_at,
               vl.level AS vendor_level, vl.positive_feedback_percentage
        FROM escrow e
        JOIN orders o ON e.order_id = o.id
        JOIN users u ON o.user_id = u.id
        JOIN users v ON o.vendor_id = v.id
        JOIN products p ON o.product_id = p.id
        LEFT JOIN vendor_levels vl ON o.vendor_id = vl.vendor_id
    """
    params = []
    
    if search:
        query += " WHERE (e.order_id LIKE ? OR u.pusername LIKE ? OR v.pusername LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
    else:
        query += " WHERE 1=1"
    
    if status:
        query += " AND e.status = ?"
        params.append(status)
    
    query += " ORDER BY e.created_at DESC"
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute(query, params)
        total_escrows = len(c.fetchall())
        total_pages = (total_escrows + per_page - 1) // per_page
        
        offset = (page - 1) * per_page
        query += " LIMIT ? OFFSET ?"
        params.extend([per_page, offset])
        
        c.execute(query, params)
        escrows = [dict(row) for row in c.fetchall()]
    
    return render_template('admin/escrow.html',
        escrows=escrows,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        total_escrows=total_escrows
    )

@admin_bp.route('/escrow_details/<int:order_id>')
def admin_escrow_details(order_id):
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT e.order_id, u.pusername AS buyer_username, v.pusername AS vendor_username,
                   p.title AS product_title, e.amount_btc, e.amount_usd, e.status, 
                   o.status AS order_status, e.crypto_currency, e.created_at, 
                   e.multisig_address, e.buyer_address, e.vendor_address, e.escrow_address, e.txid,
                   vl.level AS vendor_level, vl.positive_feedback_percentage, vl.sales_count
            FROM escrow e
            JOIN orders o ON e.order_id = o.id
            JOIN users u ON o.user_id = u.id
            JOIN users v ON o.vendor_id = v.id
            JOIN products p ON o.product_id = p.id
            LEFT JOIN vendor_levels vl ON o.vendor_id = vl.vendor_id
            WHERE e.order_id = ?
        """, (order_id,))
        escrow = c.fetchone()
        if not escrow:
            flash('Escrow not found.', 'error')
            return redirect(url_for('admin.admin_escrow'))
        
        return render_template('admin/escrow_details.html',
            escrow=dict(escrow)
        )

@admin_bp.route('/update_escrow/<int:order_id>', methods=['POST'])
def admin_update_escrow(order_id):
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    action = request.form.get('action')
    if action not in ['release', 'refund']:
        flash('Invalid action.', 'error')
        return redirect(url_for('admin.admin_escrow'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT e.status, o.status AS order_status, o.vendor_id, e.amount_btc
            FROM escrow e
            JOIN orders o ON e.order_id = o.id
            WHERE e.order_id = ?
        """, (order_id,))
        result = c.fetchone()
        if not result:
            flash('Escrow not found.', 'error')
            return redirect(url_for('admin.admin_escrow'))
        
        if result['status'] not in ['pending', 'held', 'pending_release']:
            flash('Cannot update escrow that is already released, refunded, or disputed.', 'error')
            return redirect(url_for('admin.admin_escrow'))
        
        new_escrow_status = 'released' if action == 'release' else 'refunded'
        new_order_status = 'completed' if action == 'release' else 'cancelled'
        
        # Update escrow and order statuses
        c.execute("UPDATE escrow SET status = ? WHERE order_id = ?", (new_escrow_status, order_id))
        c.execute("UPDATE orders SET status = ? WHERE id = ?", (new_order_status, order_id))
        
        # If releasing funds, add to vendor balance
        if action == 'release':
            fee_percentage = 0.05  # 5% platform fee
            net_amount = result['amount_btc'] * (1 - fee_percentage)
            
            # Ensure vendor has balance record
            c.execute("SELECT user_id FROM balances WHERE user_id = ?", (result['vendor_id'],))
            if not c.fetchone():
                c.execute("INSERT INTO balances (user_id, balance_btc, balance_xmr, last_updated) VALUES (?, 0, 0, CURRENT_TIMESTAMP)", (result['vendor_id'],))
            
            c.execute("""
                UPDATE balances 
                SET balance_btc = balance_btc + ?, last_updated = CURRENT_TIMESTAMP
                WHERE user_id = ?
            """, (net_amount, result['vendor_id']))
            
            # Update vendor sales count and level
            c.execute("""
                UPDATE vendor_levels
                SET sales_count = sales_count + 1, updated_at = CURRENT_TIMESTAMP
                WHERE vendor_id = ?
            """, (result['vendor_id'],))
            
            # Trigger vendor level update
            update_vendor_level(result['vendor_id'])
        
        conn.commit()
        
        action_text = 'released to vendor' if action == 'release' else 'refunded to buyer'
        flash(f"Escrow for order #{order_id} {action_text} successfully.", 'success')
    
    return redirect(url_for('admin.admin_escrow'))


# New dispute management routes
@admin_bp.route('/disputes')
def admin_disputes():
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 10
    search = request.args.get('search', '').strip()
    status = request.args.get('status', '')
    
    query = """
        SELECT d.id, d.order_id, u.pusername AS buyer_username, p.title AS product_title,
               o.amount_btc, o.amount_usd, d.status, d.reason, d.created_at
        FROM disputes d
        JOIN orders o ON d.order_id = o.id
        JOIN users u ON o.user_id = u.id
        JOIN products p ON o.product_id = p.id
        WHERE o.vendor_id = ?
    """
    params = [session['user_id']]
    
    if search:
        query += " AND (d.order_id LIKE ? OR u.pusername LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])
    if status:
        query += " AND d.status = ?"
        params.append(status)
    
    query += " ORDER BY d.created_at DESC"
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute(query, params)
        total_disputes = len(c.fetchall())
        total_pages = (total_disputes + per_page - 1) // per_page
        
        offset = (page - 1) * per_page
        query += " LIMIT ? OFFSET ?"
        params.extend([per_page, offset])
        
        c.execute(query, params)
        disputes = [dict(row) for row in c.fetchall()]
    
    return render_template('admin/disputes.html',
        disputes=disputes,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        total_disputes=total_disputes
    )

@admin_bp.route('/dispute_details/<int:dispute_id>')
def admin_dispute_details(dispute_id):
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT d.id, d.order_id, u.pusername AS buyer_username, p.title AS product_title,
                   o.amount_btc, o.amount_usd, o.status AS order_status, d.status,
                   d.reason, d.comments, d.created_at, d.resolved_at,
                   su.pusername AS submitted_by_username,
                   e.status AS escrow_status, e.escrow_address, e.txid
            FROM disputes d
            JOIN orders o ON d.order_id = o.id
            JOIN users u ON o.user_id = u.id
            JOIN products p ON o.product_id = p.id
            JOIN users su ON d.submitted_by = su.id
            LEFT JOIN escrow e ON d.order_id = e.order_id
            WHERE d.id = ? AND o.vendor_id = ?
        """, (dispute_id, session['user_id']))
        dispute = c.fetchone()
        if not dispute:
            flash('Dispute not found or you are not the vendor.', 'error')
            return redirect(url_for('admin.admin_disputes'))
        
        return render_template('admin/dispute_details.html',
            dispute=dict(dispute)
        )

def update_vendor_level(vendor_id):
    """Update a single vendor's level based on sales, feedback, and time active."""
    with get_db_connection() as conn:
        c = conn.cursor()
        
        # First, recalculate metrics to ensure accuracy
        recalculate_vendor_metrics(vendor_id)
        
        # Fetch updated vendor data
        c.execute("""
            SELECT sales_count, positive_feedback_percentage, joined_at, level
            FROM vendor_levels
            WHERE vendor_id = ?
        """, (vendor_id,))
        vendor = c.fetchone()
        if not vendor:
            return
        
        sales_count = vendor['sales_count']
        feedback = vendor['positive_feedback_percentage']
        # Parse joined_at to datetime if needed
        joined_at = vendor['joined_at']
        if isinstance(joined_at, str):
            from datetime import datetime
            try:
                joined_at = datetime.strptime(joined_at, "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                joined_at = datetime.strptime(joined_at, "%Y-%m-%d %H:%M:%S")
        months_active = ((datetime.utcnow() - joined_at).days / 30.0)
        old_level = vendor['level']
        
        # Determine new level (10 levels)
        new_level = 1
        if sales_count >= 2000 and feedback >= 99 and months_active >= 24:
            new_level = 10
        elif sales_count >= 1000 and feedback >= 98 and months_active >= 18:
            new_level = 9
        elif sales_count >= 500 and feedback >= 97 and months_active >= 12:
            new_level = 8
        elif sales_count >= 250 and feedback >= 96 and months_active >= 9:
            new_level = 7
        elif sales_count >= 100 and feedback >= 95 and months_active >= 6:
            new_level = 6
        elif sales_count >= 50 and feedback >= 94 and months_active >= 4:
            new_level = 5
        elif sales_count >= 25 and feedback >= 93 and months_active >= 3:
            new_level = 4
        elif sales_count >= 15 and feedback >= 92 and months_active >= 2:
            new_level = 3
        elif sales_count >= 10 and feedback >= 90 and months_active >= 1:
            new_level = 2
        
        if new_level != old_level:
            c.execute("""
                UPDATE vendor_levels
                SET level = ?, updated_at = ?
                WHERE vendor_id = ?
            """, (new_level, datetime.utcnow(), vendor_id))
            
            # Also update users.level for consistency
            c.execute("UPDATE users SET level = ? WHERE id = ?", (new_level, vendor_id))
            
            c.execute("""
                INSERT INTO vendor_level_logs (vendor_id, old_level, new_level, reason)
                VALUES (?, ?, ?, ?)
            """, (vendor_id, old_level, new_level, 'Automated update based on sales and feedback'))
            conn.commit()

def update_all_vendor_levels():
    """Update levels for all vendors."""
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT vendor_id FROM vendor_levels")
        vendor_ids = [row['vendor_id'] for row in c.fetchall()]
    
    for vendor_id in vendor_ids:
        update_vendor_level(vendor_id)

def ensure_all_vendor_levels():
    """Ensure all vendors have vendor level records."""
    with get_db_connection() as conn:
        c = conn.cursor()
        
        # Get all vendors that don't have vendor level records
        c.execute("""
            SELECT u.id, u.created_at
            FROM users u
            LEFT JOIN vendor_levels vl ON u.id = vl.vendor_id
            WHERE u.role = 'vendor' AND vl.vendor_id IS NULL
        """)
        missing_vendors = c.fetchall()
        
        for vendor in missing_vendors:
            c.execute("""
                INSERT INTO vendor_levels (vendor_id, level, sales_count, positive_feedback_percentage, joined_at, updated_at)
                VALUES (?, 1, 0, 0.0, ?, ?)
            """, (vendor['id'], vendor['created_at'], datetime.utcnow()))
        
        conn.commit()
        return len(missing_vendors)

@admin_bp.route('/news', methods=['GET'])
def news():
    if not is_admin():
        flash("Admin access required.", 'error')
        return redirect(url_for('admin.login'))
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT n.id, n.title, n.content, n.created_at, n.updated_at, u.username as admin_name
                FROM news n
                JOIN users u ON n.admin_id = u.id
                ORDER BY n.created_at DESC
            """)
            news_articles = [dict(row) for row in c.fetchall()]
        return render_template('admin/news_manage.html', news_articles=news_articles)
    except Exception as e:
        logger.error(f"News list error: {str(e)}")
        flash("An error occurred while loading news.", 'error')
        return redirect(url_for('admin.dashboard'))

@admin_bp.route('/news/create', methods=['GET', 'POST'])
def create_news():
    if not is_admin():
        flash("Admin access required.", 'error')
        return redirect(url_for('admin.login'))
    admin_id = session['user_id']
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        if not title or not content:
            flash("Title and content are required.", 'error')
            return render_template('admin/news_create.html', form_data=request.form.to_dict())
        if len(title) > 100:
            flash("Title cannot exceed 100 characters.", 'error')
            return render_template('admin/news_create.html', form_data=request.form.to_dict())
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("""
                    INSERT INTO news (title, content, admin_id)
                    VALUES (?, ?, ?)
                """, (title, content, admin_id))
                conn.commit()
                flash("News article posted successfully.", 'success')
                return redirect(url_for('admin.news'))
        except Exception as e:
            logger.error(f"Create news error: {str(e)}")
            flash("An error occurred while posting news.", 'error')
            return render_template('admin/news_create.html', form_data=request.form.to_dict())
    return render_template('admin/news_create.html', form_data={})

@admin_bp.route('/news/edit/<int:news_id>', methods=['GET', 'POST'])
def edit_news(news_id):
    if not is_admin():
        flash("Admin access required.", 'error')
        return redirect(url_for('admin.login'))
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT id, title, content FROM news WHERE id = ?", (news_id,))
            news = c.fetchone()
            if not news:
                flash("News article not found.", 'error')
                return redirect(url_for('admin.news'))
            if request.method == 'POST':
                title = request.form.get('title', '').strip()
                content = request.form.get('content', '').strip()
                if not title or not content:
                    flash("Title and content are required.", 'error')
                    return render_template('admin/news_edit.html', news=news, form_data=request.form.to_dict())
                if len(title) > 100:
                    flash("Title cannot exceed 100 characters.", 'error')
                    return render_template('admin/news_edit.html', news=news, form_data=request.form.to_dict())
                c.execute("""
                    UPDATE news
                    SET title = ?, content = ?, updated_at = ?
                    WHERE id = ?
                """, (title, content, datetime.utcnow(), news_id))
                conn.commit()
                flash("News article updated successfully.", 'success')
                return redirect(url_for('admin.news'))
            return render_template('admin/news_edit.html', news=news, form_data=news)
    except Exception as e:
        logger.error(f"Edit news error: {str(e)}")
        flash("An error occurred while editing news.", 'error')
        return redirect(url_for('admin.news'))

@admin_bp.route('/news/delete/<int:news_id>', methods=['POST'])
def delete_news(news_id):
    if not is_admin():
        flash("Admin access required.", 'error')
        return redirect(url_for('admin.login'))
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("DELETE FROM news WHERE id = ?", (news_id,))
            conn.commit()
            if c.rowcount > 0:
                flash("News article deleted successfully.", 'success')
            else:
                flash("News article not found.", 'error')
        return redirect(url_for('admin.news'))
    except Exception as e:
        logger.error(f"Delete news error: {str(e)}")
        flash("An error occurred while deleting news.", 'error')
        return redirect(url_for('admin.news'))

# Initialize scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(func=update_all_vendor_levels, trigger="interval", days=1)
scheduler.start()
atexit.register(lambda: scheduler.shutdown())

@admin_bp.route('/vendors')
def manage_vendors():
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT u.id AS vendor_id, u.pusername, vl.level, vl.sales_count, 
                   vl.positive_feedback_percentage, vl.updated_at, AVG(vr.rating) AS avg_rating
            FROM users u
            LEFT JOIN vendor_levels vl ON u.id = vl.vendor_id
            LEFT JOIN vendor_ratings vr ON u.id = vr.vendor_id
            WHERE u.role = 'vendor'
            GROUP BY u.id
            ORDER BY u.pusername
        """)
        vendors = c.fetchall()
    
    if not vendors:
        flash('No vendors available.', 'info')
    
    return render_template('admin/vendors.html', vendors=vendors)

@admin_bp.route('/update_vendor_level/<int:vendor_id>', methods=['POST'])
def admin_update_vendor_level(vendor_id):
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    level = request.form.get('level', type=int)
    if not (1 <= level <= 10):
        flash('Vendor level must be between 1 and 10.', 'error')
        return redirect(url_for('admin.manage_vendors'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        
        # Check if vendor exists
        c.execute("SELECT id FROM users WHERE id = ? AND role = 'vendor'", (vendor_id,))
        vendor = c.fetchone()
        if not vendor:
            flash('Vendor not found.', 'error')
            return redirect(url_for('admin.manage_vendors'))
        
        # Check if vendor level record exists, create if not
        c.execute("SELECT level FROM vendor_levels WHERE vendor_id = ?", (vendor_id,))
        result = c.fetchone()
        if not result:
            # Initialize vendor level record
            initialize_vendor_level(vendor_id)
            old_level = 1
        else:
            old_level = result['level']
        
        c.execute("""
            UPDATE vendor_levels
            SET level = ?, updated_at = ?
            WHERE vendor_id = ?
        """, (level, datetime.utcnow(), vendor_id))
        
        # Also update users.level for consistency
        c.execute("UPDATE users SET level = ? WHERE id = ?", (level, vendor_id))
        
        c.execute("""
            INSERT INTO vendor_level_logs (vendor_id, old_level, new_level, reason)
            VALUES (?, ?, ?, ?)
        """, (vendor_id, old_level, level, 'Manual update by admin'))
        conn.commit()
    
    flash(f'Vendor level updated to {level} successfully.', 'success')
    return redirect(url_for('admin.manage_vendors'))

@admin_bp.route('/update_all_vendor_levels', methods=['POST'])
def admin_update_all_vendor_levels():
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    try:
        update_all_vendor_levels()
        flash('All vendor levels updated successfully.', 'success')
    except Exception as e:
        flash(f'Error updating vendor levels: {str(e)}', 'error')
    
    return redirect(url_for('admin.manage_vendors'))

# Example: Trigger level update after order completion (modify existing route)
@admin_bp.route('/disputes/resolve/<int:dispute_id>', methods=['POST'])
def admin_resolve_dispute(dispute_id):
    if not is_admin():
        return redirect(url_for('admin.admin_login'))
    
    action = request.form.get('action')
    comments = request.form.get('comments', '').strip()
    if action not in ['release', 'refund', 'escalate']:
        flash('Invalid action.', 'error')
        return redirect(url_for('admin.admin_disputes'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT d.status, d.order_id, o.status AS order_status, e.status AS escrow_status,
                   o.vendor_id, o.amount_btc
            FROM disputes d
            JOIN orders o ON d.order_id = o.id
            LEFT JOIN escrow e ON d.order_id = e.order_id
            WHERE d.id = ?
        """, (dispute_id,))
        result = c.fetchone()
        if not result:
            flash('Dispute not found.', 'error')
            return redirect(url_for('admin.admin_disputes'))
        
        if result['status'] != 'open':
            flash('Cannot resolve a dispute that is already resolved or escalated.', 'error')
            return redirect(url_for('admin.admin_disputes'))
        
        new_dispute_status = 'resolved' if action in ['release', 'refund'] else 'escalated'
        new_order_status = None
        new_escrow_status = None
        
        if action == 'release':
            new_order_status = 'completed'
            new_escrow_status = 'released'
            fee_percentage = get_order_fee_percentage()
            net_amount = result['amount_btc'] * (1 - fee_percentage)
            ensure_vendor_balance(result['vendor_id'])
            c.execute("""
                UPDATE balances
                SET balance_btc = balance_btc + ?, last_updated = ?
                WHERE user_id = ?
            """, (net_amount, datetime.utcnow(), result['vendor_id']))
            # Update sales count and trigger level update
            c.execute("""
                UPDATE vendor_levels
                SET sales_count = sales_count + 1, updated_at = ?
                WHERE vendor_id = ?
            """, (datetime.utcnow(), result['vendor_id']))
            update_vendor_level(result['vendor_id'])
        elif action == 'refund':
            new_order_status = 'cancelled'
            new_escrow_status = 'refunded'
        elif action == 'escalate':
            new_order_status = 'disputed'
            new_escrow_status = 'disputed'
        
        c.execute("""
            UPDATE disputes
            SET status = ?, comments = ?, resolved_at = ?
            WHERE id = ?
        """, (new_dispute_status, comments, datetime.utcnow() if new_dispute_status == 'resolved' else None, dispute_id))
        
        c.execute("UPDATE orders SET status = ?, dispute_status = ? WHERE id = ?",
                  (new_order_status, new_dispute_status, result['order_id']))
        
        if new_escrow_status:
            c.execute("UPDATE escrow SET status = ? WHERE order_id = ?",
                      (new_escrow_status, result['order_id']))
        
        conn.commit()
        
        action_text = {
            'release': 'resolved by releasing funds to vendor',
            'refund': 'resolved by refunding funds to buyer',
            'escalate': 'escalated for moderation'
        }[action]
        flash(f"Dispute #{dispute_id} {action_text} successfully.", 'success')
    
    return redirect(url_for('admin.admin_disputes'))

def initialize_vendor_level(vendor_id):
    """Initialize vendor level record for a new vendor."""
    with get_db_connection() as conn:
        c = conn.cursor()
        # Check if vendor level record already exists
        c.execute("SELECT vendor_id FROM vendor_levels WHERE vendor_id = ?", (vendor_id,))
        if c.fetchone():
            return  # Already exists
        
        # Get vendor's join date from users table
        c.execute("SELECT created_at FROM users WHERE id = ?", (vendor_id,))
        user = c.fetchone()
        if not user:
            return
        
        # Insert initial vendor level record
        c.execute("""
            INSERT INTO vendor_levels (vendor_id, level, sales_count, positive_feedback_percentage, joined_at, updated_at)
            VALUES (?, 1, 0, 0.0, ?, ?)
        """, (vendor_id, user['created_at'], datetime.utcnow()))
        conn.commit()

@admin_bp.route('/fix_vendor_levels', methods=['POST'])
def admin_fix_vendor_levels():
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    try:
        fixed_count = ensure_all_vendor_levels()
        flash(f'Fixed vendor levels for {fixed_count} vendors.', 'success')
    except Exception as e:
        flash(f'Error fixing vendor levels: {str(e)}', 'error')
    
    return redirect(url_for('admin.manage_vendors'))

@admin_bp.route('/recalculate_vendor_metrics', methods=['POST'])
def admin_recalculate_vendor_metrics():
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    try:
        results = recalculate_all_vendor_metrics()
        flash(f'Recalculated metrics for {len(results)} vendors.', 'success')
    except Exception as e:
        flash(f'Error recalculating vendor metrics: {str(e)}', 'error')
    
    return redirect(url_for('admin.manage_vendors'))

def recalculate_vendor_metrics(vendor_id):
    """Recalculate vendor metrics based on actual order and rating data."""
    with get_db_connection() as conn:
        c = conn.cursor()
        
        # Calculate total sales (completed orders)
        c.execute("""
            SELECT COUNT(*) as sales_count
            FROM orders
            WHERE vendor_id = ? AND status IN ('completed', 'delivered')
        """, (vendor_id,))
        sales_result = c.fetchone()
        sales_count = sales_result['sales_count'] if sales_result else 0
        
        # Calculate positive feedback percentage
        c.execute("""
            SELECT COUNT(*) as total_ratings,
                   SUM(CASE WHEN rating >= 4 THEN 1 ELSE 0 END) as positive_ratings
            FROM vendor_ratings
            WHERE vendor_id = ?
        """, (vendor_id,))
        rating_result = c.fetchone()
        
        if rating_result and rating_result['total_ratings'] > 0:
            positive_feedback_percentage = (rating_result['positive_ratings'] / rating_result['total_ratings']) * 100
        else:
            positive_feedback_percentage = 0.0
        
        # Update vendor level record
        c.execute("""
            UPDATE vendor_levels
            SET sales_count = ?, positive_feedback_percentage = ?, updated_at = ?
            WHERE vendor_id = ?
        """, (sales_count, positive_feedback_percentage, datetime.utcnow(), vendor_id))
        conn.commit()
        
        return sales_count, positive_feedback_percentage

def recalculate_all_vendor_metrics():
    """Recalculate metrics for all vendors."""
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT vendor_id FROM vendor_levels")
        vendor_ids = [row['vendor_id'] for row in c.fetchall()]
    
    results = {}
    for vendor_id in vendor_ids:
        sales_count, feedback_percentage = recalculate_vendor_metrics(vendor_id)
        results[vendor_id] = {'sales_count': sales_count, 'feedback_percentage': feedback_percentage}
    
    return results

def get_vendor_level_requirements():
    """Get vendor level requirements for documentation."""
    return {
        1: {"sales": 0, "feedback": 0, "months": 0, "description": "New Vendor"},
        2: {"sales": 10, "feedback": 90, "months": 1, "description": "10+ sales, 90%+ feedback"},
        3: {"sales": 15, "feedback": 92, "months": 2, "description": "15+ sales, 92%+ feedback"},
        4: {"sales": 25, "feedback": 93, "months": 3, "description": "25+ sales, 93%+ feedback"},
        5: {"sales": 50, "feedback": 94, "months": 4, "description": "50+ sales, 94%+ feedback"},
        6: {"sales": 100, "feedback": 95, "months": 6, "description": "100+ sales, 95%+ feedback"},
        7: {"sales": 250, "feedback": 96, "months": 9, "description": "250+ sales, 96%+ feedback"},
        8: {"sales": 500, "feedback": 97, "months": 12, "description": "500+ sales, 97%+ feedback"},
        9: {"sales": 1000, "feedback": 98, "months": 18, "description": "1000+ sales, 98%+ feedback"},
        10: {"sales": 2000, "feedback": 99, "months": 24, "description": "2000+ sales, 99%+ feedback"}
    }

@admin_bp.route('/auto_finalize_trusted_orders', methods=['POST'])
def admin_auto_finalize_trusted_orders():
    """Manually trigger auto-finalization of trusted vendor orders"""
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    # Skip CSRF validation for admin functions
    # validate_csrf_token()  # Uncomment if CSRF validation is enabled
    
    try:
        from routes.public import auto_finalize_trusted_vendor_orders
        auto_finalize_trusted_vendor_orders()
        flash("Auto-finalization of trusted vendor orders completed successfully.", 'success')
    except Exception as e:
        flash(f"Error during auto-finalization: {str(e)}", 'error')
    
    return redirect(url_for('admin.admin_escrow'))

@admin_bp.route('/debug_create_test_admin')
def debug_create_test_admin():
    create_test_admin_and_news()
    print('SESSION:', dict(session))
    return 'Test admin and news created. Session: ' + str(dict(session))

@admin_bp.route('/wallet_audit_log')
def wallet_audit_log():
    if not is_admin():
        return redirect(url_for('admin.login'))
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT timestamp, action, admin FROM security_audit WHERE action LIKE '%wallet%' ORDER BY timestamp DESC LIMIT 50")
        wallet_audit_trail = [dict(row) for row in c.fetchall()]
    return render_template('admin/wallet_audit_log.html', wallet_audit_trail=wallet_audit_trail)

@admin_bp.route('/deposits', methods=['GET'])
def admin_deposits():
    if 'user_id' not in session:
        flash('Please log in as an admin.', 'error')
        return redirect(url_for('auth.login'))
    with get_db_connection() as conn:
        c = conn.cursor()
        user_filter = request.args.get('user_id')
        currency_filter = request.args.get('currency')
        query = "SELECT t.id, t.user_id, u.pusername, t.currency, t.amount, t.address, t.tx_id, t.created_at FROM transactions t JOIN users u ON t.user_id = u.id WHERE t.type = 'deposit'"
        params = []
        if user_filter:
            query += " AND t.user_id = ?"
            params.append(user_filter)
        if currency_filter:
            query += " AND t.currency = ?"
            params.append(currency_filter)
        query += " ORDER BY t.created_at DESC LIMIT 50"
        c.execute(query, params)
        deposits = [dict(row) for row in c.fetchall()]
    return render_template('admin/deposits.html', deposits=deposits)

@admin_bp.route('/ads')
@require_admin_role
def admin_ads():
    """Admin dashboard to view and manage all user ads"""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Get all ads with vendor and product information
            c.execute("""
                SELECT sa.*, p.title as product_title, p.featured_image, p.price_usd,
                       u.pusername as vendor_name,
                       (SELECT SUM(impression_count) FROM ad_impressions WHERE ad_id = sa.id) as total_impressions,
                       (SELECT SUM(click_count) FROM ad_impressions WHERE ad_id = sa.id) as total_clicks,
                       (SELECT SUM(cost) FROM ad_impressions WHERE ad_id = sa.id) as total_cost
                FROM sponsored_ads sa
                JOIN products p ON sa.product_id = p.id
                JOIN users u ON sa.vendor_id = u.id
                ORDER BY sa.created_at DESC
            """)
            all_ads = [dict(row) for row in c.fetchall()]
            
            # Calculate summary statistics
            total_ads = len(all_ads)
            active_ads = len([ad for ad in all_ads if ad['status'] == 'active'])
            total_spend = sum(ad['total_cost'] or 0 for ad in all_ads)
            total_impressions = sum(ad['total_impressions'] or 0 for ad in all_ads)
            total_clicks = sum(ad['total_clicks'] or 0 for ad in all_ads)
            
            # Get recent ad performance (last 7 days)
            c.execute("""
                SELECT ai.*, sa.bid_amount, p.title as product_title, u.pusername as vendor_name
                FROM ad_impressions ai
                JOIN sponsored_ads sa ON ai.ad_id = sa.id
                JOIN products p ON sa.product_id = p.id
                JOIN users u ON sa.vendor_id = u.id
                WHERE ai.date >= date('now', '-7 days')
                ORDER BY ai.date DESC
            """)
            recent_performance = [dict(row) for row in c.fetchall()]
            
            # Get crypto prices for USD conversion
            btc_price = get_btc_price()
            xmr_price = get_xmr_price()
            
        return render_template('admin/ads.html',
                             all_ads=all_ads,
                             total_ads=total_ads,
                             active_ads=active_ads,
                             total_spend=total_spend,
                             total_impressions=total_impressions,
                             total_clicks=total_clicks,
                             recent_performance=recent_performance,
                             btc_price=btc_price,
                             xmr_price=xmr_price)
                             
    except Exception as e:
        print(f"DEBUG: Error in admin_ads route: {str(e)}")  # Debug print
        flash(f"Error loading ads dashboard: {str(e)}", 'error')
        return redirect(url_for('admin.dashboard'))

@admin_bp.route('/ads/<int:ad_id>')
@require_admin_role
def admin_ad_details(ad_id):
    """View detailed information about a specific ad"""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Get ad details with vendor and product information
            c.execute("""
                SELECT sa.*, p.title as product_title, p.description, p.featured_image, p.price_usd,
                       u.pusername as vendor_name, u.created_at as vendor_joined
                FROM sponsored_ads sa
                JOIN products p ON sa.product_id = p.id
                JOIN users u ON sa.vendor_id = u.id
                WHERE sa.id = ?
            """, (ad_id,))
            ad = c.fetchone()
            
            if not ad:
                flash("Ad not found.", 'error')
                return redirect(url_for('admin.admin_ads'))
            
            ad = dict(ad)
            
            # Get daily performance data
            c.execute("""
                SELECT date, impression_count, click_count, cost
                FROM ad_impressions
                WHERE ad_id = ?
                ORDER BY date DESC
                LIMIT 30
            """, (ad_id,))
            daily_data = [dict(row) for row in c.fetchall()]
            
            # Calculate totals
            total_impressions = sum(row['impression_count'] for row in daily_data)
            total_clicks = sum(row['click_count'] for row in daily_data)
            total_cost = sum(row['cost'] for row in daily_data)
            ctr = (total_clicks / total_impressions * 100) if total_impressions > 0 else 0
            
            # Get vendor's other ads
            c.execute("""
                SELECT sa.*, p.title as product_title
                FROM sponsored_ads sa
                JOIN products p ON sa.product_id = p.id
                WHERE sa.vendor_id = ? AND sa.id != ?
                ORDER BY sa.created_at DESC
                LIMIT 5
            """, (ad['vendor_id'], ad_id))
            vendor_other_ads = [dict(row) for row in c.fetchall()]
            
            return render_template('admin/ad_details.html',
                                 ad=ad,
                                 daily_data=daily_data,
                                 total_impressions=total_impressions,
                                 total_clicks=total_clicks,
                                 total_cost=total_cost,
                                 ctr=ctr,
                                 vendor_other_ads=vendor_other_ads)
                                 
    except Exception as e:
        flash(f"Error loading ad details: {str(e)}", 'error')
        return redirect(url_for('admin.admin_ads'))

@admin_bp.route('/ads/<int:ad_id>/edit', methods=['GET', 'POST'])
@require_admin_role
def admin_edit_ad(ad_id):
    """Edit an ad campaign (admin can edit any ad)"""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Get ad details
            c.execute("""
                SELECT sa.*, p.title as product_title, u.pusername as vendor_name
                FROM sponsored_ads sa
                JOIN products p ON sa.product_id = p.id
                JOIN users u ON sa.vendor_id = u.id
                WHERE sa.id = ?
            """, (ad_id,))
            ad = c.fetchone()
            
            if not ad:
                flash("Ad not found.", 'error')
                return redirect(url_for('admin.admin_ads'))
            
            ad = dict(ad)
            
            if request.method == 'POST':
                # Get form data
                bid_amount = request.form.get('bid_amount', type=float)
                daily_budget = request.form.get('daily_budget', type=float)
                status = request.form.get('status')
                placement_type = request.form.get('placement_type')
                
                # Validation
                if not all([bid_amount, daily_budget, status, placement_type]):
                    flash("All fields are required.", 'error')
                    return redirect(url_for('admin.admin_edit_ad', ad_id=ad_id))
                
                if status not in ['active', 'paused', 'ended']:
                    flash("Invalid status.", 'error')
                    return redirect(url_for('admin.admin_edit_ad', ad_id=ad_id))
                
                # Update ad
                c.execute("""
                    UPDATE sponsored_ads 
                    SET bid_amount = ?, daily_budget = ?, status = ?, placement_type = ?
                    WHERE id = ?
                """, (bid_amount, daily_budget, status, placement_type, ad_id))
                
                conn.commit()
                
                # Log admin action
                log_admin_action_encrypted(
                    f"Admin edited ad {ad_id} for vendor {ad['vendor_name']}. "
                    f"Changes: bid={bid_amount}, budget={daily_budget}, status={status}",
                    session.get('username', 'admin'),
                    None
                )
                
                flash("Ad updated successfully!", 'success')
                return redirect(url_for('admin.admin_ad_details', ad_id=ad_id))
            
            # GET request - show edit form
            return render_template('admin/edit_ad.html', ad=ad)
                                 
    except Exception as e:
        flash(f"Error editing ad: {str(e)}", 'error')
        return redirect(url_for('admin.admin_ads'))

@admin_bp.route('/ads/<int:ad_id>/delete', methods=['POST'])
@require_admin_role
def admin_delete_ad(ad_id):
    """Delete an ad campaign (admin can delete any ad)"""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Get ad details for logging
            c.execute("""
                SELECT sa.*, u.pusername as vendor_name
                FROM sponsored_ads sa
                JOIN users u ON sa.vendor_id = u.id
                WHERE sa.id = ?
            """, (ad_id,))
            ad = c.fetchone()
            
            if not ad:
                flash("Ad not found.", 'error')
                return redirect(url_for('admin.admin_ads'))
            
            ad = dict(ad)
            
            # Calculate refund amount (unused budget)
            total_spent = 0
            c.execute("SELECT SUM(cost) FROM ad_impressions WHERE ad_id = ?", (ad_id,))
            spent_result = c.fetchone()
            if spent_result and spent_result[0]:
                total_spent = spent_result[0]
            
            total_budget = ad['daily_budget'] * ad['duration_days']
            refund_amount = total_budget - total_spent
            
            if refund_amount > 0:
                # Refund unused budget to vendor
                if ad['crypto_currency'] == 'BTC':
                    c.execute("""
                        UPDATE users SET balance_btc = balance_btc + ? WHERE id = ?
                    """, (refund_amount, ad['vendor_id']))
                else:
                    c.execute("""
                        UPDATE users SET balance_xmr = balance_xmr + ? WHERE id = ?
                    """, (refund_amount, ad['vendor_id']))
            
            # Delete ad impressions
            c.execute("DELETE FROM ad_impressions WHERE ad_id = ?", (ad_id,))
            
            # Delete the ad
            c.execute("DELETE FROM sponsored_ads WHERE id = ?", (ad_id,))
            
            conn.commit()
            
            # Log admin action
            log_admin_action_encrypted(
                f"Admin deleted ad {ad_id} for vendor {ad['vendor_name']}. "
                f"Refunded: {refund_amount} {ad['crypto_currency']}",
                session.get('username', 'admin'),
                None
            )
            
            flash(f"Ad deleted successfully! Refunded {refund_amount:.6f} {ad['crypto_currency']} to vendor.", 'success')
            
    except Exception as e:
        flash(f"Error deleting ad: {str(e)}", 'error')
    
    return redirect(url_for('admin.admin_ads'))

@admin_bp.route('/ads/vendor/<int:vendor_id>')
@require_admin_role
def admin_vendor_ads(vendor_id):
    """View all ads for a specific vendor"""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Get vendor information
            c.execute("SELECT id, pusername, email, created_at FROM users WHERE id = ?", (vendor_id,))
            vendor = c.fetchone()
            
            if not vendor:
                flash("Vendor not found.", 'error')
                return redirect(url_for('admin.admin_ads'))
            
            vendor = dict(vendor)
            
            # Get all ads for this vendor
            c.execute("""
                SELECT sa.*, p.title as product_title, p.featured_image, p.price_usd,
                       (SELECT SUM(impression_count) FROM ad_impressions WHERE ad_id = sa.id) as total_impressions,
                       (SELECT SUM(click_count) FROM ad_impressions WHERE ad_id = sa.id) as total_clicks,
                       (SELECT SUM(cost) FROM ad_impressions WHERE ad_id = sa.id) as total_cost
                FROM sponsored_ads sa
                JOIN products p ON sa.product_id = p.id
                WHERE sa.vendor_id = ?
                ORDER BY sa.created_at DESC
            """, (vendor_id,))
            vendor_ads = [dict(row) for row in c.fetchall()]
            
            # Calculate vendor's ad statistics
            total_ads = len(vendor_ads)
            active_ads = len([ad for ad in vendor_ads if ad['status'] == 'active'])
            total_spend = sum(ad['total_cost'] or 0 for ad in vendor_ads)
            total_impressions = sum(ad['total_impressions'] or 0 for ad in vendor_ads)
            total_clicks = sum(ad['total_clicks'] or 0 for ad in vendor_ads)
            
            # Get crypto prices
            btc_price = get_btc_price()
            xmr_price = get_xmr_price()
            
            return render_template('admin/vendor_ads.html',
                                 vendor=vendor,
                                 vendor_ads=vendor_ads,
                                 total_ads=total_ads,
                                 active_ads=active_ads,
                                 total_spend=total_spend,
                                 total_impressions=total_impressions,
                                 total_clicks=total_clicks,
                                 btc_price=btc_price,
                                 xmr_price=xmr_price)
                                 
    except Exception as e:
        flash(f"Error loading vendor ads: {str(e)}", 'error')
        return redirect(url_for('admin.admin_ads'))

@admin_bp.route('/ads/analytics')
@require_admin_role
def admin_ads_analytics():
    """Overall ads analytics and reporting"""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Get overall statistics
            c.execute("SELECT COUNT(*) as total FROM sponsored_ads")
            total_ads = c.fetchone()['total']
            
            c.execute("SELECT COUNT(*) as active FROM sponsored_ads WHERE status = 'active'")
            active_ads = c.fetchone()['active']
            
            c.execute("SELECT SUM(cost) as total_spend FROM ad_impressions")
            total_spend = c.fetchone()['total_spend'] or 0
            
            c.execute("SELECT SUM(impression_count) as total_impressions FROM ad_impressions")
            total_impressions = c.fetchone()['total_impressions'] or 0
            
            c.execute("SELECT SUM(click_count) as total_clicks FROM ad_impressions")
            total_clicks = c.fetchone()['total_clicks'] or 0
            
            # Calculate CTR
            ctr = (total_clicks / total_impressions * 100) if total_impressions > 0 else 0
            
            # Get daily performance for last 30 days
            c.execute("""
                SELECT date, 
                       SUM(impression_count) as impressions,
                       SUM(click_count) as clicks,
                       SUM(cost) as spend
                FROM ad_impressions
                WHERE date >= date('now', '-30 days')
                GROUP BY date
                ORDER BY date DESC
            """)
            daily_performance = [dict(row) for row in c.fetchall()]
            
            # Get top performing ads
            c.execute("""
                SELECT sa.id, sa.bid_amount, p.title as product_title, u.pusername as vendor_name,
                       (SELECT SUM(impression_count) FROM ad_impressions WHERE ad_id = sa.id) as impressions,
                       (SELECT SUM(click_count) FROM ad_impressions WHERE ad_id = sa.id) as clicks,
                       (SELECT SUM(cost) FROM ad_impressions WHERE ad_id = sa.id) as spend
                FROM sponsored_ads sa
                JOIN products p ON sa.product_id = p.id
                JOIN users u ON sa.vendor_id = u.id
                WHERE sa.status = 'active'
                ORDER BY (SELECT SUM(click_count) FROM ad_impressions WHERE ad_id = sa.id) DESC
                LIMIT 10
            """)
            top_ads = [dict(row) for row in c.fetchall()]
            
            # Get top spending vendors
            c.execute("""
                SELECT u.pusername as vendor_name,
                       COUNT(sa.id) as total_ads,
                       SUM(ai.cost) as total_spend
                FROM sponsored_ads sa
                JOIN users u ON sa.vendor_id = u.id
                LEFT JOIN ad_impressions ai ON sa.id = ai.ad_id
                GROUP BY sa.vendor_id, u.pusername
                ORDER BY total_spend DESC
                LIMIT 10
            """)
            top_vendors = [dict(row) for row in c.fetchall()]
            
            # Get crypto prices
            btc_price = get_btc_price()
            xmr_price = get_xmr_price()
            
            return render_template('admin/ads_analytics.html',
                                 total_ads=total_ads,
                                 active_ads=active_ads,
                                 total_spend=total_spend,
                                 total_impressions=total_impressions,
                                 total_clicks=total_clicks,
                                 ctr=ctr,
                                 daily_performance=daily_performance,
                                 top_ads=top_ads,
                                 top_vendors=top_vendors,
                                 btc_price=btc_price,
                                 xmr_price=xmr_price)
                                 
    except Exception as e:
        flash(f"Error loading analytics: {str(e)}", 'error')
        return redirect(url_for('admin.admin_ads'))

