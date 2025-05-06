from flask import Blueprint, request, flash, redirect, url_for, render_template, session, send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from utils.database import get_db_connection, get_settings  # Absolute import from utils.database
import os
import sqlite3

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')
limiter = Limiter(get_remote_address, app=None)  # Attach in app.py

# Directory for category images
UPLOAD_FOLDER = 'static/uploads/categories'
UPLOAD_FOLDER_LOGOS = 'static/uploads/logos'
UPLOAD_FOLDER_CATEGORIES = 'static/uploads/categories'
UPLOAD_FOLDER_PRODUCTS = 'static/uploads/products'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

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
            return redirect(url_for('admin.admin_login'))
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

def is_admin():
    if 'user_id' not in session:
        return False
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT role FROM users WHERE id = ?", (session['user_id'],))
        user = c.fetchone()
        return user and user['role'] == 'admin'

@admin_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("50 per hour")
def admin_login():
    if 'user_id' in session and session.get('role') == 'admin':
        return redirect(url_for('admin.admin_dashboard'))
    
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
                return redirect(url_for('admin.admin_dashboard'))
    
    return render_template('admin/login.html', step='username')

@admin_bp.route('/dashboard')
@require_admin_role
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('admin.admin_login'))
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) as count FROM users")
        total_users = c.fetchone()['count']
        c.execute("SELECT COUNT(*) as count FROM products")
        total_products = c.fetchone()['count']
        c.execute("SELECT COUNT(*) as count FROM orders")
        total_orders = c.fetchone()['count']
        c.execute("SELECT SUM(amount_usd) as total FROM orders WHERE status = 'completed'")
        total_sales = c.fetchone()['total'] or 0.0  # Fixed typo: 'count' -> 'total'
    return render_template('admin/dashboard.html', 
                          total_users=total_users, 
                          total_products=total_products, 
                          total_orders=total_orders, 
                          total_sales=total_sales)

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
                    return redirect(url_for('admin.admin_dashboard'))
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
def admin_categories():
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('admin.admin_login'))
    
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
            
            return redirect(url_for('admin.admin_categories'))
    
    return render_template('admin/categories.html', categories=categories)

@admin_bp.route('/edit-category/<int:category_id>', methods=['GET', 'POST'])
@limiter.limit("50 per hour")
def admin_edit_category(category_id):
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('admin.admin_login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM categories WHERE id = ?", (category_id,))
        edit_category = c.fetchone()
        if not edit_category:
            flash("Category not found.", 'error')
            return redirect(url_for('admin.admin_categories'))
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
            return redirect(url_for('admin.admin_categories'))
    
    return render_template('admin/categories.html', categories=categories, edit_category=edit_category)

@admin_bp.route('/delete-category/<int:category_id>', methods=['POST'])
@limiter.limit("50 per hour")
def admin_delete_category(category_id):
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('admin.admin_login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM categories WHERE id = ?", (category_id,))
        category = c.fetchone()
        if not category:
            flash("Category not found.", 'error')
            return redirect(url_for('admin.admin_categories'))
        
        c.execute("SELECT COUNT(*) FROM products WHERE category_id = ?", (category_id,))
        product_count = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM categories WHERE parent_id = ?", (category_id,))
        subcategory_count = c.fetchone()[0]
        
        if product_count > 0 or subcategory_count > 0:
            flash("Cannot delete category with products or subcategories.", 'error')
            return redirect(url_for('admin.admin_categories'))
        
        c.execute("DELETE FROM categories WHERE id = ?", (category_id,))
        conn.commit()
        flash("Category deleted successfully.", 'success')
    
    return redirect(url_for('admin.admin_categories'))

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
                return redirect(url_for('admin.admin_login'))
            except sqlite3.IntegrityError:
                flash("Username or public username already exists.", 'error')
                return render_template('admin/register.html', error="Username or public username already exists.")
    
    return render_template('admin/register.html')

@admin_bp.route('/products/all-products', methods=['GET', 'POST'])
@limiter.limit("50 per hour")
def admin_all_products():
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('admin.admin_login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT id, name FROM categories ORDER BY name")
        categories = [dict(row) for row in c.fetchall()]
        
        c.execute("""
            SELECT p.*, c.name as category_name 
            FROM products p 
            LEFT JOIN categories c ON p.category_id = c.id 
            WHERE p.vendor_id = ?
        """, (session['admin_id'],))
        products = [dict(row) for row in c.fetchall()]
        
        c.execute("SELECT * FROM product_images")
        product_images = [dict(row) for row in c.fetchall()]
        
        if request.method == 'POST':
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            price_usd = request.form.get('price_usd', type=float)
            original_price_usd = request.form.get('original_price_usd', type=float)
            discount_active = bool(request.form.get('discount_active'))
            stock = request.form.get('stock', type=int)
            category_id = request.form.get('category_id', type=int)
            sku = request.form.get('sku', '').strip() or None
            shipping_weight = request.form.get('shipping_weight', type=float)
            shipping_dimensions = request.form.get('shipping_dimensions', '').strip() or None
            shipping_method = request.form.get('shipping_method', '').strip() or None
            moq = request.form.get('moq', type=int, default=1)
            lead_time = request.form.get('lead_time', '').strip() or None
            packaging_details = request.form.get('packaging_details', '').strip() or None
            tags = request.form.get('tags', '').strip() or None
            status = request.form.get('status', 'active')
            featured_image = request.files.get('featured_image')
            additional_images = request.files.getlist('additional_images')
            
            if not all([title, price_usd is not None, stock is not None, category_id]):
                flash("All required fields must be filled.", 'error')
                return render_template('admin/products/all-products.html', categories=categories, products=products, product_images=product_images, error="All required fields must be filled.")
            
            if price_usd < 0 or stock < 0 or (moq and moq < 1):
                flash("Price, stock, and MOQ must be non-negative (MOQ >= 1).", 'error')
                return render_template('admin/products/all-products.html', categories=categories, products=products, product_images=product_images, error="Invalid values.")
            
            featured_image_path = None
            if featured_image and allowed_file(featured_image.filename):
                filename = secure_filename(featured_image.filename)
                featured_image_path = os.path.join('uploads/products', filename)
                featured_image.save(os.path.join(UPLOAD_FOLDER_PRODUCTS, filename))
            
            try:
                c.execute("""
                    INSERT INTO products (title, description, price_usd, original_price_usd, discount_active, stock, category_id, vendor_id, sku, shipping_weight, shipping_dimensions, shipping_method, moq, lead_time, packaging_details, tags, status, featured_image)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (title, description, price_usd, original_price_usd, discount_active, stock, category_id, session['admin_id'], sku, shipping_weight, shipping_dimensions, shipping_method, moq, lead_time, packaging_details, tags, status, featured_image_path))
                product_id = c.lastrowid
                conn.commit()
                
                for image in additional_images:
                    if image and allowed_file(image.filename):
                        filename = secure_filename(image.filename)
                        image_path = os.path.join('uploads/products', filename).replace('\\', '/')  
                        image.save(os.path.join(UPLOAD_FOLDER_PRODUCTS, filename))
                        c.execute("INSERT INTO product_images (product_id, image_path) VALUES (?, ?)", (product_id, image_path))
                conn.commit()
                
                flash("Product added successfully.", 'success')
                return redirect(url_for('admin.admin_add_products'))
            except sqlite3.IntegrityError:
                flash("Error adding product. SKU or title may already exist.", 'error')
        
        return render_template('admin/products/all-products.html', categories=categories, products=products, product_images=product_images)

@admin_bp.route('/products/add', methods=['GET', 'POST'])
@limiter.limit("50 per hour")
def admin_add_products():
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('admin.admin_login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT id, name FROM categories ORDER BY name")
        categories = [dict(row) for row in c.fetchall()]
        
        c.execute("""
            SELECT p.*, c.name as category_name 
            FROM products p 
            LEFT JOIN categories c ON p.category_id = c.id 
            WHERE p.vendor_id = ?
        """, (session['admin_id'],))
        products = [dict(row) for row in c.fetchall()]
        
        c.execute("SELECT * FROM product_images")
        product_images = [dict(row) for row in c.fetchall()]
        
        if request.method == 'POST':
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            price_usd = request.form.get('price_usd', type=float)
            original_price_usd = request.form.get('original_price_usd', type=float)
            discount_active = bool(request.form.get('discount_active'))
            stock = request.form.get('stock', type=int)
            category_id = request.form.get('category_id', type=int)
            sku = request.form.get('sku', '').strip() or None
            shipping_weight = request.form.get('shipping_weight', type=float)
            shipping_dimensions = request.form.get('shipping_dimensions', '').strip() or None
            shipping_method = request.form.get('shipping_method', '').strip() or None
            moq = request.form.get('moq', type=int, default=1)
            lead_time = request.form.get('lead_time', '').strip() or None
            packaging_details = request.form.get('packaging_details', '').strip() or None
            tags = request.form.get('tags', '').strip() or None
            status = request.form.get('status', 'active')
            featured_image = request.files.get('featured_image')
            additional_images = request.files.getlist('additional_images')
            
            if not all([title, price_usd is not None, stock is not None, category_id]):
                flash("All required fields must be filled.", 'error')
                return render_template('admin/products/add.html', categories=categories, products=products, product_images=product_images, error="All required fields must be filled.")
            
            if price_usd < 0 or stock < 0 or (moq and moq < 1):
                flash("Price, stock, and MOQ must be non-negative (MOQ >= 1).", 'error')
                return render_template('admin/products/add.html', categories=categories, products=products, product_images=product_images, error="Invalid values.")
            
            featured_image_path = None
            if featured_image and allowed_file(featured_image.filename):
                filename = secure_filename(featured_image.filename)
                featured_image_path = os.path.join('uploads/products', filename).replace('\\', '/')
                featured_image.save(os.path.join(UPLOAD_FOLDER_PRODUCTS, filename))
            
            try:
                c.execute("""
                    INSERT INTO products (title, description, price_usd, original_price_usd, discount_active, stock, category_id, vendor_id, sku, shipping_weight, shipping_dimensions, shipping_method, moq, lead_time, packaging_details, tags, status, featured_image)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (title, description, price_usd, original_price_usd, discount_active, stock, category_id, session['admin_id'], sku, shipping_weight, shipping_dimensions, shipping_method, moq, lead_time, packaging_details, tags, status, featured_image_path))
                product_id = c.lastrowid
                conn.commit()
                
                for image in additional_images:
                    if image and allowed_file(image.filename):
                        filename = secure_filename(image.filename)
                        image_path = os.path.join('uploads/products', filename).replace('\\', '/')  
                        image.save(os.path.join(UPLOAD_FOLDER_PRODUCTS, filename))
                        c.execute("INSERT INTO product_images (product_id, image_path) VALUES (?, ?)", (product_id, image_path))
                conn.commit()
                
                flash("Product added successfully.", 'success')
                return redirect(url_for('admin.admin_all_products'))
            except sqlite3.IntegrityError:
                flash("Error adding product. SKU or title may already exist.", 'error')
        
        return render_template('admin/products/add.html', categories=categories, products=products, product_images=product_images)

@admin_bp.route('/products/edit/<int:product_id>', methods=['GET', 'POST'])
@limiter.limit("50 per hour")
def admin_edit_product(product_id):
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('admin.admin_login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        # Fetch product
        c.execute("""
            SELECT p.*, c.name as category_name 
            FROM products p 
            LEFT JOIN categories c ON p.category_id = c.id 
            WHERE p.id = ? AND p.vendor_id = ?
        """, (product_id, session['admin_id']))
        product = c.fetchone()
        if not product:
            flash("Product not found or you don’t have permission to edit it.", 'error')
            return redirect(url_for('admin.admin_add_products'))
        product = dict(product)
        
        # Fetch categories for dropdown
        c.execute("SELECT id, name FROM categories ORDER BY name")
        categories = [dict(row) for row in c.fetchall()]
        
        # Fetch existing additional images
        c.execute("SELECT * FROM product_images WHERE product_id = ?", (product_id,))
        product_images = [dict(row) for row in c.fetchall()]
        
        if request.method == 'POST':
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            price_usd = request.form.get('price_usd', type=float)
            original_price_usd = request.form.get('original_price_usd', type=float)
            discount_active = bool(request.form.get('discount_active'))
            stock = request.form.get('stock', type=int)
            category_id = request.form.get('category_id', type=int)
            sku = request.form.get('sku', '').strip() or None
            shipping_weight = request.form.get('shipping_weight', type=float)
            shipping_dimensions = request.form.get('shipping_dimensions', '').strip() or None
            shipping_method = request.form.get('shipping_method', '').strip() or None
            moq = request.form.get('moq', type=int, default=1)
            lead_time = request.form.get('lead_time', '').strip() or None
            packaging_details = request.form.get('packaging_details', '').strip() or None
            tags = request.form.get('tags', '').strip() or None
            status = request.form.get('status', 'active')
            featured_image = request.files.get('featured_image')
            additional_images = request.files.getlist('additional_images')
            
            if not all([title, price_usd is not None, stock is not None, category_id]):
                flash("All required fields must be filled.", 'error')
                return render_template('admin/products/edit.html', product=product, categories=categories, product_images=product_images, error="All required fields must be filled.")
            
            if price_usd < 0 or stock < 0 or (moq and moq < 1):
                flash("Price, stock, and MOQ must be non-negative (MOQ >= 1).", 'error')
                return render_template('admin/products/edit.html', product=product, categories=categories, product_images=product_images, error="Invalid values.")
            
            # Handle featured image (only update if new file uploaded)
            featured_image_path = product['featured_image']
            if featured_image and allowed_file(featured_image.filename):
                filename = secure_filename(featured_image.filename)
                featured_image_path = os.path.join('uploads/products', filename)
                featured_image.save(os.path.join(UPLOAD_FOLDER_PRODUCTS, filename))
            
            try:
                c.execute("""
                    UPDATE products 
                    SET title = ?, description = ?, price_usd = ?, original_price_usd = ?, discount_active = ?, stock = ?, category_id = ?, sku = ?, shipping_weight = ?, shipping_dimensions = ?, shipping_method = ?, moq = ?, lead_time = ?, packaging_details = ?, tags = ?, status = ?, featured_image = ?
                    WHERE id = ? AND vendor_id = ?
                """, (title, description, price_usd, original_price_usd, discount_active, stock, category_id, sku, shipping_weight, shipping_dimensions, shipping_method, moq, lead_time, packaging_details, tags, status, featured_image_path, product_id, session['admin_id']))
                conn.commit()
                
                # Handle additional images (append new ones, keep existing unless deleted)
                for image in additional_images:
                    if image and allowed_file(image.filename):
                        filename = secure_filename(image.filename)
                        image_path = os.path.join('uploads', 'products', filename).replace('\\', '/')  
                        image.save(os.path.join(UPLOAD_FOLDER_PRODUCTS, filename))
                        c.execute("INSERT INTO product_images (product_id, image_path) VALUES (?, ?)", (product_id, image_path))
                conn.commit()
                
                flash("Product updated successfully.", 'success')
                return redirect(url_for('admin.admin_add_products'))
            except sqlite3.IntegrityError:
                flash("Error updating product. SKU may already exist.", 'error')
        
        return render_template('admin/products/edit.html', product=product, categories=categories, product_images=product_images)

@admin_bp.route('/products/delete/<int:product_id>', methods=['POST'])
@limiter.limit("50 per hour")
def admin_delete_product(product_id):
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('admin.admin_login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        # Check if product exists and belongs to admin
        c.execute("SELECT * FROM products WHERE id = ? AND vendor_id = ?", (product_id, session['admin_id']))
        product = c.fetchone()
        if not product:
            flash("Product not found or you don’t have permission to delete it.", 'error')
            return redirect(url_for('admin.admin_add_products'))
        
        # Check if product is tied to orders
        c.execute("SELECT COUNT(*) FROM orders WHERE product_id = ?", (product_id,))
        order_count = c.fetchone()[0]
        if order_count > 0:
            flash("Cannot delete product with existing orders.", 'error')
            return redirect(url_for('admin.admin_add_products'))
        
        # Delete additional images
        c.execute("DELETE FROM product_images WHERE product_id = ?", (product_id,))
        # Delete product
        c.execute("DELETE FROM products WHERE id = ? AND vendor_id = ?", (product_id, session['admin_id']))
        conn.commit()
        
        flash("Product deleted successfully.", 'success')
    return redirect(url_for('admin.admin_add_products'))

@admin_bp.route('/settings', methods=['GET', 'POST'])
@limiter.limit("50 per hour")
def admin_settings():
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('admin.admin_login'))
    
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
def admin_users():
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('admin.admin_login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT u.id, u.username, u.registered_at, u.active, u.role,
                   (SELECT COUNT(*) FROM orders WHERE orders.user_id = u.id) as order_count
            FROM users u
            WHERE u.role != 'admin'  -- Exclude admins from management
            ORDER BY u.registered_at DESC
        """)
        users = [dict(row) for row in c.fetchall()]
        
        return render_template('admin/users.html', users=users)

@admin_bp.route('/users/suspend/<int:user_id>', methods=['POST'])
@limiter.limit("50 per hour")
def admin_suspend_user(user_id):
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('admin.admin_login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT id, role FROM users WHERE id = ? AND role != 'admin'", (user_id,))
        user = c.fetchone()
        if not user:
            flash("User not found or cannot suspend an admin.", 'error')
            return redirect(url_for('admin.admin_users'))
        
        c.execute("UPDATE users SET active = 0 WHERE id = ?", (user_id,))
        conn.commit()
        flash(f"User {user_id} suspended successfully.", 'success')
        return redirect(url_for('admin.admin_users'))

@admin_bp.route('/users/reactivate/<int:user_id>', methods=['POST'])
@limiter.limit("50 per hour")
def admin_reactivate_user(user_id):
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('admin.admin_login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT id, role FROM users WHERE id = ? AND role != 'admin'", (user_id,))
        user = c.fetchone()
        if not user:
            flash("User not found or cannot reactivate an admin.", 'error')
            return redirect(url_for('admin.admin_users'))
        
        c.execute("UPDATE users SET active = 1 WHERE id = ?", (user_id,))
        conn.commit()
        flash(f"User {user_id} reactivated successfully.", 'success')
        return redirect(url_for('admin.admin_users'))

@admin_bp.route('/users/promote/<int:user_id>', methods=['POST'])
@limiter.limit("50 per hour")
def admin_promote_user(user_id):
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('admin.admin_login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT id, role FROM users WHERE id = ? AND role != 'admin'", (user_id,))
        user = c.fetchone()
        if not user:
            flash("User not found or cannot promote an admin.", 'error')
            return redirect(url_for('admin.admin_users'))
        
        new_role = 'vendor' if user['role'] == 'user' else 'user'
        c.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
        conn.commit()
        flash(f"User {user_id} {'promoted to vendor' if new_role == 'vendor' else 'demoted to user'} successfully.", 'success')
        return redirect(url_for('admin.admin_users'))
    
@admin_bp.route('/orders', methods=['GET'])
@limiter.limit("50 per hour")
def admin_orders():
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('admin.admin_login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT o.*, p.title
            FROM orders o
            JOIN products p ON o.product_id = p.id
            ORDER BY o.created_at DESC
        """)
        orders = [dict(row) for row in c.fetchall()]
        return render_template('admin/orders.html', orders=orders)

@admin_bp.route('/my_orders', methods=['GET', 'POST'])
@limiter.limit("50 per hour")
def admin_my_orders():
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('admin.admin_login'))
    
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
def admin_resolve_dispute(order_id):
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('admin.admin_login'))
    
    action = request.form.get('action')
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
        else:
            flash("Invalid action.", 'error')
        
        return redirect(url_for('admin.admin_orders'))

@admin_bp.route('/messages', methods=['GET', 'POST'])
@limiter.limit("50 per hour")
def admin_messages():
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('admin.admin_login'))
    
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

@admin_bp.route('/support', methods=['GET', 'POST'])
@limiter.limit("50 per hour")
def admin_support():
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('admin.admin_login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        
        # Search/Filter
        search_query = request.args.get('search', '').strip()
        status_filter = request.args.get('status', '')
        category_filter = request.args.get('category', '')
        
        query = """
            SELECT t.*, u.username,
                   (SELECT COUNT(*) FROM ticket_responses WHERE ticket_id = t.id) as response_count
            FROM tickets t
            JOIN users u ON t.user_id = u.id
            WHERE 1=1
        """
        params = []
        
        if search_query:
            query += " AND (t.subject LIKE ? OR u.username LIKE ?)"
            params.extend([f"%{search_query}%", f"%{search_query}%"])
        if status_filter:
            query += " AND t.status = ?"
            params.append(status_filter)
        if category_filter:
            query += " AND t.category = ?"
            params.append(category_filter)
        
        query += " ORDER BY t.updated_at DESC"
        c.execute(query, params)
        tickets = [dict(row) for row in c.fetchall()]
        
        if request.method == 'POST':
            ticket_id = request.form.get('ticket_id', type=int)
            action = request.form.get('action')
            body = request.form.get('body', '').strip()
            
            c.execute("SELECT t.*, u.pgp_key FROM tickets t JOIN users u ON t.user_id = u.id WHERE t.id = ?", (ticket_id,))
            ticket = c.fetchone()
            if not ticket:
                flash("Ticket not found.", 'error')
                return redirect(url_for('admin.admin_support'))
            
            if action == 'reply':
                if not body:
                    flash("Response cannot be empty.", 'error')
                    return redirect(url_for('admin.admin_support'))
                
                # PGP Encryption if user has a key
                settings = get_settings()
                admin_pgp_key = settings.get('pgp_key', '')
                user_pgp_key = ticket['pgp_key']
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
                        return redirect(url_for('admin.admin_support'))
                
                c.execute("""
                    INSERT INTO ticket_responses (ticket_id, sender_id, body, encrypted_body)
                    VALUES (?, ?, ?, ?)
                """, (ticket_id, session['admin_id'], plaintext_body, encrypted_body))
                c.execute("UPDATE tickets SET updated_at = CURRENT_TIMESTAMP, status = 'in_progress' WHERE id = ?", (ticket_id,))
                
                # Notify user
                c.execute("""
                    INSERT INTO messages (sender_id, recipient_type, recipient_id, subject, body)
                    VALUES (?, ?, ?, ?, ?)
                """, (session['admin_id'], 'user', ticket['user_id'], f"Update on Ticket #{ticket_id}", f"Admin replied: {body[:50]}..."))
                conn.commit()
                flash("Response sent successfully.", 'success')
            
            elif action in ['resolve', 'close']:
                new_status = 'resolved' if action == 'resolve' else 'closed'
                c.execute("UPDATE tickets SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (new_status, ticket_id))
                
                # Notify user
                c.execute("""
                    INSERT INTO messages (sender_id, recipient_type, recipient_id, subject, body)
                    VALUES (?, ?, ?, ?, ?)
                """, (session['admin_id'], 'user', ticket['user_id'], f"Ticket #{ticket_id} {new_status}", f"Your ticket has been {new_status}."))
                conn.commit()
                flash(f"Ticket {ticket_id} marked as {new_status}.", 'success')
            
            return redirect(url_for('admin.admin_support'))
        
        return render_template('admin/support.html', tickets=tickets, search_query=search_query, status_filter=status_filter, category_filter=category_filter)

@admin_bp.route('/support/ticket/<int:ticket_id>', methods=['GET'])
@limiter.limit("50 per hour")
def admin_view_ticket(ticket_id):
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('admin.admin_login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT t.*, u.username FROM tickets t JOIN users u ON t.user_id = u.id WHERE t.id = ?", (ticket_id,))
        ticket = c.fetchone()
        if not ticket:
            flash("Ticket not found.", 'error')
            return redirect(url_for('admin.admin_support'))
        
        c.execute("SELECT * FROM ticket_responses WHERE ticket_id = ? ORDER BY created_at", (ticket_id,))
        responses = [dict(row) for row in c.fetchall()]
        
        return render_template('admin/support.html', ticket=dict(ticket), responses=responses)

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
    return redirect(url_for('admin.admin_login'))