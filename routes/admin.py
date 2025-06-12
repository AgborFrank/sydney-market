from flask import Blueprint, request, flash, redirect, url_for, render_template, session, send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_session import Session
from flask_limiter.util import get_remote_address
from utils.database import get_db_connection, get_settings  # Absolute import from utils.database
import os
import logging
import re
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from flask_login import login_required, current_user, login_user
import atexit
import secrets
import sqlite3

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')
limiter = Limiter(get_remote_address, app=None)  # Attach in app.py
logger = logging.getLogger(__name__)


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
            
            if password and not pin:  # Step 1: Check password
                if not check_password_hash(admin['password'], password):
                    flash("Incorrect password.", 'error')
                    return render_template('admin/login.html', step='username', error="Incorrect password.")
                return render_template('admin/login.html', 
                                     step='pin', 
                                     username=username, 
                                     login_phrase=admin['login_phrase'])
            
            if pin:  # Step 2: Check PIN
                if pin != admin['pin']:
                    flash("Incorrect PIN.", 'error')
                    return render_template('admin/login.html', 
                                         step='pin', 
                                         username=username, 
                                         login_phrase=admin['login_phrase'], 
                                         error="Incorrect PIN.")
                session['user_id'] = admin['id']  # Changed from admin_id to user_id
                session['admin_id'] = admin['id']
                session['role'] = 'admin'
                flash("Logged in successfully.", 'success')
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
                   o.amount_usd, o.status, o.created_at
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
            SELECT w.id, u.pusername AS user, w.amount_usd, w.status, w.requested_at
            FROM withdrawals w
            JOIN users u ON w.user_id = u.id
            ORDER BY w.requested_at DESC
            LIMIT 5
        """)
        recent_withdrawals = [dict(row) for row in c.fetchall()]
        
        # Total Escrow (BTC, pending)
        c.execute("SELECT SUM(amount_usd) AS total FROM escrow WHERE status = 'pending'")
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
@limiter.limit("50 per hour")
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
@limiter.limit("50 per hour")
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
@limiter.limit("50 per hour")
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
@limiter.limit("50 per hour")
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
@limiter.limit("50 per hour")
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
@limiter.limit("50 per hour")
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
@limiter.limit("50 per hour")
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
@limiter.limit("50 per hour")
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
                ('pgp_key', pgp_key)
            ]
            c.executemany("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", updates)
            conn.commit()
            
            flash("Settings updated successfully.", 'success')
            return redirect(url_for('admin.admin_settings'))
        
        return render_template('admin/settings.html', settings=get_settings())

@admin_bp.route('/users', methods=['GET'])
@limiter.limit("50 per hour")
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
@limiter.limit("50 per hour")
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
            
            return render_template('admin/faqs.html', grouped_faqs=grouped_faqs, categories=categories)
    except Exception as e:
        logger.error(f"Error fetching FAQs: {str(e)}")
        flash("Error loading FAQs.", 'error')
        return redirect(url_for('admin.dashboard'))

@admin_bp.route('/faqs/new', methods=['GET', 'POST'])
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
            # Fetch vendor details
            c.execute("""
                SELECT id, pusername, btc_address, pgp_public_key, role, is_vendor, vendor_status, level
                FROM users
                WHERE id = ? AND is_vendor = 1
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

@admin_bp.route('/users/reactivate/<int:user_id>', methods=['POST'])
@limiter.limit("50 per hour")
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
@limiter.limit("50 per hour")
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
        flash(f"User {user_id} {'promoted to vendor' if new_role == 'vendor' else 'demoted to user'} successfully.", 'success')
        return redirect(url_for('admin.manage_users'))
    
@admin_bp.route('/vendor/orders', methods=['GET'])
@limiter.limit("50 per hour")
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
@limiter.limit("50 per hour")
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
                flash("Order not found or you don’t have permission to modify it.", 'error')
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
@limiter.limit("50 per hour")
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
@limiter.limit("50 per hour")
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
            flash(f"Vendor {vendor_id} approved successfully.", 'success')
        else:
            flash("Bond payment not received.", 'error')
        
        return redirect(url_for('admin.manage_users'))

@admin_bp.route('/messages', methods=['GET', 'POST'])
@limiter.limit("50 per hour")
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
@limiter.limit("50 per hour")
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
@limiter.limit("50 per hour")
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
    
    # Ensure all settings exist in the response
    defaults = {
        '2fa_admin': 'disabled',
        '2fa_vendor': 'disabled',
        'password_min_length': '12',
        'password_require_special': 'yes',
        'session_timeout_minutes': '30'
    }
    settings = {**defaults, **settings}
    
    return render_template('admin/security.html', settings=settings)

@admin_bp.route('/update_security', methods=['POST'])
def admin_update_security():
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    # Get form data
    settings = {
        '2fa_admin': 'enabled' if request.form.get('2fa_admin') == 'enabled' else 'disabled',
        '2fa_vendor': 'enabled' if request.form.get('2fa_vendor') == 'enabled' else 'disabled',
        'password_min_length': request.form.get('password_min_length', type=int),
        'password_require_special': 'yes' if request.form.get('password_require_special') == 'yes' else 'no',
        'session_timeout_minutes': request.form.get('session_timeout_minutes', type=int)
    }
    
    # Validate inputs
    if not (8 <= settings['password_min_length'] <= 50):
        flash('Password minimum length must be between 8 and 50.', 'error')
        return redirect(url_for('admin.admin_security'))
    
    if not (5 <= settings['session_timeout_minutes'] <= 1440):
        flash('Session timeout must be between 5 and 1440 minutes.', 'error')
        return redirect(url_for('admin.admin_security'))
    
    # Update settings
    with get_db_connection() as conn:
        c = conn.cursor()
        for setting_name, value in settings.items():
            c.execute("""
                UPDATE security_settings
                SET value = ?, updated_at = ?
                WHERE setting_name = ?
            """, (str(value), datetime.utcnow(), setting_name))
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

                    if not all([title, features, product_limit, price_usd]) or product_limit < 1 or price_usd < 0:
                        flash("Invalid package details.", 'error')
                    else:
                        c.execute("""
                            INSERT INTO packages (title, features, product_limit, price_usd)
                            VALUES (?, ?, ?, ?)
                        """, (title, features, product_limit, price_usd))
                        conn.commit()
                        flash("Package added successfully!", 'success')

                elif action == 'edit':
                    package_id = request.form.get('package_id', type=int)
                    title = request.form.get('title')
                    features = request.form.get('features')
                    product_limit = request.form.get('product_limit', type=int)
                    price_usd = request.form.get('price_usd', type=float)

                    if not all([package_id, title, features, product_limit, price_usd]) or product_limit < 1 or price_usd < 0:
                        flash("Invalid package details.", 'error')
                    else:
                        c.execute("""
                            UPDATE packages 
                            SET title = ?, features = ?, product_limit = ?, price_usd = ?
                            WHERE id = ?
                        """, (title, features, product_limit, price_usd, package_id))
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
        SELECT w.id, u.pusername AS vendor_username, w.amount_usd, w.wallet_address,
               w.status, w.requested_at
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
            SELECT w.id, u.pusername AS vendor_username, w.amount_btc, w.btc_address,
                   w.status, w.txid, w.rejection_reason, w.created_at, b.balance_btc
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
                SELECT o.id, u.pusername AS user, p.title AS product, v.pusername AS vendor,
                       o.amount_btc, o.status, o.created_at
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
                return redirect(url_for('admin.admin_users'))
        return render_template('admin/orders.html', orders=orders, user=user['pusername'])
    
    flash('User ID required to view orders.', 'error')
    return redirect(url_for('admin.admin_users'))

@admin_bp.route('/orders')
def admin_orders():
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 10
    search = request.args.get('search', '').strip()
    status = request.args.get('status', '')
    
    query = """
        SELECT o.id, u.pusername AS buyer_username, p.title AS product_title,
               o.amount_usd, o.status, o.created_at
        FROM orders o
        JOIN users u ON o.user_id = u.id
        JOIN products p ON o.product_id = p.id
        WHERE o.vendor_id = ?
    """
    params = [session['user_id']]
    
    if search:
        query += " AND (o.id LIKE ? OR u.pusername LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])
    if status:
        query += " AND o.status = ?"
        params.append(status)
    
    query += " ORDER BY o.created_at DESC"
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute(query, params)
        total_orders = len(c.fetchall())
        total_pages = (total_orders + per_page - 1) // per_page
        
        offset = (page - 1) * per_page
        query += " LIMIT ? OFFSET ?"
        params.extend([per_page, offset])
        
        c.execute(query, params)
        orders = [dict(row) for row in c.fetchall()]
    
    return render_template('admin/orders.html',
        orders=orders,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        total_orders=total_orders
    )

@admin_bp.route('/order_details/<int:order_id>')
def admin_order_details(order_id):
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT o.id, u.pusername AS buyer_username, p.title AS product_title,
                   o.amount_btc, o.amount_usd, o.status, o.dispute_status,
                   o.crypto_currency, o.created_at
            FROM orders o
            JOIN users u ON o.user_id = u.id
            JOIN products p ON o.product_id = p.id
            WHERE o.id = ? AND o.vendor_id = ?
        """, (order_id, session['user_id']))
        order = c.fetchone()
        if not order:
            flash('Order not found or you are not the vendor.', 'error')
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
        c.execute("SELECT status FROM orders WHERE id = ? AND vendor_id = ?", (order_id, session['user_id']))
        order = c.fetchone()
        if not order:
            flash('Order not found or you are not the vendor.', 'error')
            return redirect(url_for('admin.admin_orders'))
        
        if order['status'] in ['completed', 'cancelled', 'disputed']:
            flash('Cannot update status of completed, cancelled, or disputed orders.', 'error')
            return redirect(url_for('admin.admin_orders'))
        
        c.execute("UPDATE orders SET status = ? WHERE id = ?", (new_status, order_id))
        conn.commit()
        flash(f"Order #{order_id} status updated to {new_status}.", 'success')
    
    return redirect(url_for('admin.admin_orders'))

@admin_bp.route('/approve_withdrawal/<int:withdrawal_id>', methods=['POST'])
def admin_approve_withdrawal(withdrawal_id):
    if not is_admin():
        return redirect(url_for('admin.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT w.status, w.amount_usd, w.wallet_address, u.pusername, w.user_id
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
        ensure_vendor_balance(withdrawal['user_id'])
        c.execute("SELECT balance_usd FROM balances WHERE user_id = ?", (withdrawal['user_id'],))
        balance = c.fetchone()
        if balance['balance_usd'] < total_deduction:
            flash(f"Insufficient balance for {withdrawal['pusername']}. Available: {balance['balance_usd']} USD", 'error')
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
        SELECT e.order_id, u.pusername AS buyer_username, p.title AS product_title,
               e.amount_btc, e.amount_usd, e.status, o.status AS order_status,
               e.crypto_currency, e.created_at
        FROM escrow e
        JOIN orders o ON e.order_id = o.id
        JOIN users u ON o.user_id = u.id
        JOIN products p ON o.product_id = p.id
        WHERE o.vendor_id = ?
    """
    params = [session['user_id']]
    
    if search:
        query += " AND (e.order_id LIKE ? OR u.pusername LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])
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
            SELECT e.order_id, u.pusername AS buyer_username, p.title AS product_title,
                   e.amount_usd, e.amount_usd, e.status, o.status AS order_status,
                   e.crypto_currency, e.created_at, e.multisig_address, e.buyer_address,
                   e.vendor_address, e.escrow_address, e.txid
            FROM escrow e
            JOIN orders o ON e.order_id = o.id
            JOIN users u ON o.user_id = u.id
            JOIN products p ON o.product_id = p.id
            WHERE e.order_id = ? AND o.vendor_id = ?
        """, (order_id, session['user_id']))
        escrow = c.fetchone()
        if not escrow:
            flash('Escrow not found or you are not the vendor.', 'error')
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
            SELECT e.status, o.status AS order_status
            FROM escrow e
            JOIN orders o ON e.order_id = o.id
            WHERE e.order_id = ? AND o.vendor_id = ?
        """, (order_id, session['user_id']))
        result = c.fetchone()
        if not result:
            flash('Escrow not found or you are not the vendor.', 'error')
            return redirect(url_for('admin.admin_escrow'))
        
        if result['status'] not in ['pending', 'held']:
            flash('Cannot update escrow that is already released, refunded, or disputed.', 'error')
            return redirect(url_for('admin.admin_escrow'))
        
        new_escrow_status = 'released' if action == 'release' else 'refunded'
        new_order_status = 'completed' if action == 'release' else 'cancelled'
        
        # Update escrow and order statuses
        c.execute("UPDATE escrow SET status = ? WHERE order_id = ?", (new_escrow_status, order_id))
        c.execute("UPDATE orders SET status = ? WHERE id = ?", (new_order_status, order_id))
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
        
        # Fetch vendor data
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
        months_active = ((datetime.utcnow() - vendor['joined_at']).days / 30.0)
        old_level = vendor['level']
        
        # Determine new level
        new_level = 1
        if sales_count >= 500 and feedback >= 97 and months_active >= 12:
            new_level = 5
        elif sales_count >= 100 and feedback >= 95 and months_active >= 6:
            new_level = 4
        elif sales_count >= 50 and feedback >= 92 and months_active >= 3:
            new_level = 3
        elif sales_count >= 10 and feedback >= 90 and months_active >= 1:
            new_level = 2
        
        if new_level != old_level:
            c.execute("""
                UPDATE vendor_levels
                SET level = ?, updated_at = ?
                WHERE vendor_id = ?
            """, (new_level, datetime.utcnow(), vendor_id))
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


@admin_bp.route('/news', methods=['GET'])
def news():
    if not is_admin():
        flash("Admin access required.", 'error')
        return redirect(url_for('admin.login'))
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT n.id, n.title, n.content, n.created_at, n.updated_at, u.pusername as admin_name
                FROM news n
                JOIN users u ON n.admin_id = u.id
                ORDER BY n.created_at DESC
            """)
            news_articles = [dict(row) for row in c.fetchall()]
        
        return render_template('admin/news.html', news_articles=news_articles, mode='list')
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
            return render_template('admin/news.html', mode='create', form_data=request.form.to_dict())
        
        if len(title) > 100:
            flash("Title cannot exceed 100 characters.", 'error')
            return render_template('admin/news.html', mode='create', form_data=request.form.to_dict())
        
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
            return render_template('admin/news.html', mode='create', form_data=request.form.to_dict())
    
    return render_template('admin/news.html', mode='create', form_data={})

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
                    return render_template('admin/news.html', mode='edit', news=news, form_data=request.form.to_dict())
                
                if len(title) > 100:
                    flash("Title cannot exceed 100 characters.", 'error')
                    return render_template('admin/news.html', mode='edit', news=news, form_data=request.form.to_dict())
                
                c.execute("""
                    UPDATE news
                    SET title = ?, content = ?, updated_at = ?
                    WHERE id = ?
                """, (title, content, datetime.utcnow(), news_id))
                conn.commit()
                flash("News article updated successfully.", 'success')
                return redirect(url_for('admin.news'))
            
            return render_template('admin/news.html', mode='edit', news=news, form_data=news)
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
    if not (1 <= level <= 5):
        flash('Vendor level must be between 1 and 5.', 'error')
        return redirect(url_for('admin.manage_vendors'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT level FROM vendor_levels WHERE vendor_id = ?", (vendor_id,))
        result = c.fetchone()
        if not result:
            flash('Vendor not found.', 'error')
            return redirect(url_for('admin.manage_vendors'))
        
        old_level = result['level']
        
        c.execute("""
            UPDATE vendor_levels
            SET level = ?, updated_at = ?
            WHERE vendor_id = ?
        """, (level, datetime.utcnow(), vendor_id))
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

