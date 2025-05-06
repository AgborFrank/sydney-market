from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from utils.database import get_db_connection
from utils.security import validate_csrf_token
from utils.auth import has_active_subscription
from routes import require_role
from werkzeug.utils import secure_filename
import logging
import os

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

vendor_bp = Blueprint('vendor', __name__)
# Directory for category images
UPLOAD_FOLDER = 'static/uploads/categories'
UPLOAD_FOLDER_LOGOS = 'static/uploads/logos'
UPLOAD_FOLDER_CATEGORIES = 'static/uploads/categories'
UPLOAD_FOLDER_PRODUCTS = 'static/uploads/products'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

ADMIN_BTC_ADDRESS = "YOUR_BTC_ADDRESS"
ADMIN_XMR_ADDRESS = "YOUR_XMR_ADDRESS"

def get_crypto_price(currency):
    url = "https://api.coingecko.com/api/v3/simple/price"
    params = {"ids": "bitcoin,monero", "vs_currencies": "usd"}
    try:
        response = requests.get(url, params=params, timeout=5)
        data = response.json()
        return data["bitcoin"]["usd"] if currency == "BTC" else data["monero"]["usd"] if currency == "XMR" else None
    except Exception:
        return None

# Ensure upload folders exist
for folder in [UPLOAD_FOLDER_CATEGORIES, UPLOAD_FOLDER, UPLOAD_FOLDER_PRODUCTS, UPLOAD_FOLDER_LOGOS]:
    if not os.path.exists(folder):
        os.makedirs(folder)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def require_vendor_role(func):
    def wrapper(*args, **kwargs):
        if 'role' not in session or session['role'] != 'vendor':
            flash("You must be a vendor to access this page.", 'error')
            return redirect(url_for('user.dashboard'))
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

def calculate_vendor_level(vendor_id):
    with get_db_connection() as conn:
        c = conn.cursor()
        
        # Total sales (delivered orders)
        c.execute("SELECT COUNT(*) FROM orders WHERE vendor_id = ? AND status = 'delivered'", (vendor_id,))
        sales = c.fetchone()[0]
        
        # Total orders
        c.execute("SELECT COUNT(*) FROM orders WHERE vendor_id = ?", (vendor_id,))
        total_orders = c.fetchone()[0] or 1  # Avoid division by zero
        
        # Positive reviews (rating 4 or 5)
        c.execute("""
            SELECT COUNT(*) 
            FROM reviews r
            JOIN products p ON r.product_id = p.id
            WHERE p.vendor_id = ? AND r.rating >= 4
        """, (vendor_id,))
        positive_reviews = c.fetchone()[0]
        
        # Negative reviews (rating 1 or 2)
        c.execute("""
            SELECT COUNT(*) 
            FROM reviews r
            JOIN products p ON r.product_id = p.id
            WHERE p.vendor_id = ? AND r.rating <= 2
        """, (vendor_id,))
        negative_reviews = c.fetchone()[0]
        
        # Order completion rate
        completion_rate = (sales / total_orders) * 100 if total_orders > 0 else 0

        # Determine level
        level = 1  # Default
        if sales >= 100 and positive_reviews >= 50 and negative_reviews < 15 and completion_rate > 90:
            level = 5
        elif sales >= 51 and positive_reviews >= 30 and negative_reviews < 10 and completion_rate > 85:
            level = 4
        elif sales >= 21 and positive_reviews >= 15 and negative_reviews < 5 and completion_rate > 80:
            level = 3
        elif sales >= 6 and positive_reviews >= 5 and negative_reviews < 2:
            level = 2

        # Update vendor level in database
        c.execute("UPDATE users SET level = ? WHERE id = ?", (level, vendor_id))
        conn.commit()
        
        return level

@vendor_bp.route('/dashboard')
@require_vendor_role
def vendor_dashboard():
    if 'user_id' not in session:
        flash("Please log in to view your dashboard.", 'error')
        return redirect(url_for('user.login'))
    
    vendor_id = session['user_id']
    
    with get_db_connection() as conn:
        c = conn.cursor()
        
        # Fetch vendor's details from users and vendor_settings
        c.execute("""
            SELECT u.pusername, u.level, u.avatar, vs.logo, vs.shipping_location 
            FROM users u
            LEFT JOIN vendor_settings vs ON u.id = vs.user_id
            WHERE u.id = ?
        """, (vendor_id,))
        vendor_data = c.fetchone()
        vendor_name = vendor_data['pusername']
        vendor_level = calculate_vendor_level(vendor_id)
        avatar = vendor_data['avatar'] or None
        logo = vendor_data['logo'] or None
        shipping_location = vendor_data['shipping_location'] or "Not specified"
        
        # Market Stats
        c.execute("SELECT COUNT(*) FROM orders WHERE vendor_id = ?", (vendor_id,))
        total_orders = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM orders WHERE vendor_id = ? AND status = 'shipped'", (vendor_id,))
        total_shipped = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM orders WHERE vendor_id = ? AND status = 'delivered'", (vendor_id,))
        total_sales = c.fetchone()[0]
        
        c.execute("SELECT SUM(amount_usd) FROM orders WHERE vendor_id = ? AND status = 'delivered'", (vendor_id,))
        revenue = c.fetchone()[0] or 0.0
        
        # Positive and Negative Feedbacks
        c.execute("""
            SELECT COUNT(*) 
            FROM reviews r
            JOIN products p ON r.product_id = p.id
            WHERE p.vendor_id = ? AND r.rating >= 4
        """, (vendor_id,))
        positive_feedbacks = c.fetchone()[0]
        
        c.execute("""
            SELECT COUNT(*) 
            FROM reviews r
            JOIN products p ON r.product_id = p.id
            WHERE p.vendor_id = ? AND r.rating <= 2
        """, (vendor_id,))
        negative_feedbacks = c.fetchone()[0]
        
        # Recent Orders
        c.execute("""
            SELECT o.id, o.amount_usd, o.status, o.created_at, p.title, u.pusername as buyer_username
            FROM orders o
            JOIN products p ON o.product_id = p.id
            JOIN users u ON o.user_id = u.id
            WHERE o.vendor_id = ?
            ORDER BY o.created_at DESC LIMIT 5
        """, (vendor_id,))
        recent_orders = [dict(row) for row in c.fetchall()]
        
        # Recent Reviews
        c.execute("""
            SELECT r.id, r.rating, r.comment, r.created_at, u.pusername as reviewer, p.title
            FROM reviews r
            JOIN products p ON r.product_id = p.id
            JOIN users u ON r.user_id = u.id
            WHERE p.vendor_id = ?
            ORDER BY r.created_at DESC LIMIT 5
        """, (vendor_id,))
        recent_reviews = [dict(row) for row in c.fetchall()]
        
        # Recent Messages
        c.execute("""
            SELECT m.id, m.subject, m.body, m.sent_at, u.pusername as sender
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE m.recipient_id = ? AND m.recipient_type = 'vendor'
            ORDER BY m.sent_at DESC LIMIT 5
        """, (vendor_id,))
        recent_messages = [dict(row) for row in c.fetchall()]

    stats = {
        'total_orders': total_orders,
        'total_shipped': total_shipped,
        'total_sales': total_sales,
        'revenue': revenue,
        'level': vendor_level,
        'positive_feedbacks': positive_feedbacks,
        'negative_feedbacks': negative_feedbacks,
        'shipping_location': shipping_location,
        'avatar': avatar,
        'logo': logo
    }
    
    return render_template('user/vendor_dashboard.html', vendor_name=vendor_name, stats=stats, recent_orders=recent_orders, recent_reviews=recent_reviews, recent_messages=recent_messages, title="Vendor Dashboard - DarkVault")

@vendor_bp.route('/business-details', methods=['GET', 'POST'])
@require_role('vendor')
def business_details():
    user_id = session['user_id']
    
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
                    print("Saving vendor settings:", user_id, business_name, shipping_location, shipping_destinations)
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
                    """, (user_id, business_name, description, support_contact, min_order_amount,
                          warehouse_address, shipping_details, processing_time, shipping_zones,
                          shipping_location, shipping_destinations, shipping_policy, return_policy, rules))
                    conn.commit()
                    flash("Vendor settings updated successfully!", 'success')
                    return redirect(url_for('user.dashboard'))
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
        """, (user_id,))
        settings = c.fetchone()
        settings = dict(settings) if settings else {
            'business_name': '', 'description': '', 'support_contact': '', 'min_order_amount': 0.0,
            'warehouse_address': '', 'shipping_details': '', 'processing_time': '', 'shipping_zones': '',
            'shipping_location': '', 'shipping_destinations': '', 'shipping_policy': '', 'return_policy': '', 'rules': ''
        }

    return render_template('user/business_details.html', vendor=settings, title="Vendor Settings")

@vendor_bp.route('/reviews')
@require_vendor_role
def vendor_reviews():
    if 'user_id' not in session:
        flash("Please log in to view your reviews.", 'error')
        return redirect(url_for('user.login'))
    
    vendor_id = session['user_id']
    
    with get_db_connection() as conn:
        c = conn.cursor()
        
        # Fetch vendor's public username
        c.execute("SELECT pusername FROM users WHERE id = ?", (vendor_id,))
        vendor_name = c.fetchone()['pusername']
        
        # Fetch all reviews for vendor's products
        c.execute("""
            SELECT r.id, r.rating, r.comment, r.created_at, u.pusername as reviewer, p.title
            FROM reviews r
            JOIN products p ON r.product_id = p.id
            JOIN users u ON r.user_id = u.id
            WHERE p.vendor_id = ?
            ORDER BY r.created_at DESC
        """, (vendor_id,))
        reviews = [dict(row) for row in c.fetchall()]

    return render_template('vendor/reviews.html', vendor_name=vendor_name, reviews=reviews, title="Vendor Reviews")

@vendor_bp.route('/products')
@require_vendor_role
def products_index():
    if 'user_id' not in session:
        flash("Please log in to view your products.", 'error')
        return redirect(url_for('user.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT p.*
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            WHERE vendor_id = ?
            ORDER BY created_at DESC
        """, (session['user_id'],))
        products = [dict(row) for row in c.fetchall()]
    
    return render_template('user/products/index.html', products=products, title="Your Products - DarkVault")

@vendor_bp.route('/products/create', methods=['GET', 'POST'])
@require_vendor_role
def products_create():
    
    if 'user_id' not in session:
        flash("Please log in to create a product.", 'error')
        return redirect(url_for('user.login'))
    
    #if 'user_id' not in session or not has_active_subscription(session['user_id']):
    #    flash("You must have an active subscription to post products.", 'error')
    #    return redirect(url_for('vendor.subscribe'))
    
    if request.method == 'POST':
        validate_csrf_token()
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        price_usd = request.form.get('price_usd', '').strip()
        original_price_usd = request.form.get('original_price_usd', '').strip()
        discount_active = 'discount_active' in request.form
        stock = request.form.get('stock', '').strip()
        category_id = request.form.get('category_id', '').strip()
        sku = request.form.get('sku', '').strip()
        shipping_weight = request.form.get('shipping_weight', '').strip()
        shipping_dimensions = request.form.get('shipping_dimensions', '').strip()
        shipping_method = request.form.get('shipping_method', '').strip()
        moq = request.form.get('moq', '').strip()
        lead_time = request.form.get('lead_time', '').strip()
        packaging_details = request.form.get('packaging_details', '').strip()
        tags = request.form.get('tags', '').strip()
        status = request.form.get('status', '').strip()
        featured_image = request.files.get('featured_image')
        additional_images = request.files.getlist('additional_images')

        if not all([title, price_usd, stock, category_id]):
            flash("Required fields are missing.", 'error')
            return render_template('user/products/create.html', form_data=request.form.to_dict())
        
        featured_image_path = None
        if featured_image and allowed_file(featured_image.filename):
            filename = secure_filename(featured_image.filename)
            featured_image_path = os.path.join('uploads/products', filename).replace('\\', '/')
            featured_image.save(os.path.join(UPLOAD_FOLDER_PRODUCTS, filename))
            
        try:
            price_usd = float(price_usd)
            stock = int(stock)
            category_id = int(category_id)
            original_price_usd = float(original_price_usd) if original_price_usd else None
            shipping_weight = float(shipping_weight) if shipping_weight else None
            moq = int(moq) if moq else 1
            if price_usd <= 0 or stock < 0 or (original_price_usd is not None and original_price_usd <= 0) or (shipping_weight is not None and shipping_weight < 0) or moq < 1:
                raise ValueError("Invalid numeric values")
        except ValueError:
            flash("Numeric fields must be valid and positive (except stock can be 0).", 'error')
            return render_template('user/products/create.html', form_data=request.form.to_dict())

        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO products (title, description, price_usd, original_price_usd, discount_active, stock, category_id, vendor_id, sku, shipping_weight, shipping_dimensions, shipping_method, moq, lead_time, packaging_details, tags, status, featured_image)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (title, description, price_usd, original_price_usd, discount_active, stock, category_id, session['user_id'], sku, shipping_weight, shipping_dimensions, shipping_method, moq, lead_time, packaging_details, tags, status, featured_image_path))
            product_id = c.lastrowid
            conn.commit()
            
            for image in additional_images:
                    if image and allowed_file(image.filename):
                        filename = secure_filename(image.filename)
                        image_path = os.path.join('uploads/products', filename).replace('\\', '/')  
                        image.save(os.path.join(UPLOAD_FOLDER_PRODUCTS, filename))
                        c.execute("INSERT INTO product_images (product_id, image_path) VALUES (?, ?)", (product_id, image_path))
            conn.commit()
                
            flash("Product created successfully!", 'success')
            return redirect(url_for('vendor.products_index'))

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT id, name FROM categories")
        categories = [dict(row) for row in c.fetchall()]
    
    return render_template('user/products/create.html', categories=categories, title="Create Product - DarkVault")

@vendor_bp.route('/products/edit/<int:product_id>', methods=['GET', 'POST'])
@require_vendor_role
def products_edit(product_id):
    if 'user_id' not in session:
        flash("Please log in to edit a product.", 'error')
        return redirect(url_for('user.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM products WHERE id = ? AND vendor_id = ?", (product_id, session['user_id']))
        product = c.fetchone()
        if not product:
            flash("Product not found or you don’t have permission to edit it.", 'error')
            return redirect(url_for('vendor.products_index'))

        if request.method == 'POST':
            validate_csrf_token()
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

            if not all([title, price_usd, stock, category_id]):
                flash("Required fields are missing.", 'error')
                return render_template('user/products/edit.html', product=dict(product), form_data=request.form.to_dict())

            # Handle featured image (only update if new file uploaded)
            featured_image_path = product['featured_image']
            if featured_image and allowed_file(featured_image.filename):
                filename = secure_filename(featured_image.filename)
                featured_image_path = os.path.join('uploads/products', filename)
                featured_image.save(os.path.join(UPLOAD_FOLDER_PRODUCTS, filename))
                
            try:
                price_usd = float(price_usd)
                stock = int(stock)
                category_id = int(category_id)
                original_price_usd = float(original_price_usd) if original_price_usd else None
                shipping_weight = float(shipping_weight) if shipping_weight else None
                moq = int(moq) if moq else 1
                if price_usd <= 0 or stock < 0 or (original_price_usd is not None and original_price_usd <= 0) or (shipping_weight is not None and shipping_weight < 0) or moq < 1:
                    raise ValueError("Invalid numeric values")
            except ValueError:
                flash("Numeric fields must be valid and positive (except stock can be 0).", 'error')
                return render_template('user/products/edit.html', product=dict(product), form_data=request.form.to_dict())

            c.execute("""
                    UPDATE products 
                    SET title = ?, description = ?, price_usd = ?, original_price_usd = ?, discount_active = ?, stock = ?, category_id = ?, sku = ?, shipping_weight = ?, shipping_dimensions = ?, shipping_method = ?, moq = ?, lead_time = ?, packaging_details = ?, tags = ?, status = ?, featured_image = ?
                    WHERE id = ? AND vendor_id = ?
                """, (title, description, price_usd, original_price_usd, discount_active, stock, category_id, sku, shipping_weight, shipping_dimensions, shipping_method, moq, lead_time, packaging_details, tags, status, featured_image_path, product_id, session['user_id']))
            conn.commit()
            # Handle additional images (append new ones, keep existing unless deleted)
            for image in additional_images:
                if image and allowed_file(image.filename):
                    filename = secure_filename(image.filename)
                    image_path = os.path.join('uploads', 'products', filename).replace('\\', '/')  
                    image.save(os.path.join(UPLOAD_FOLDER_PRODUCTS, filename))
                    c.execute("INSERT INTO product_images (product_id, image_path) VALUES (?, ?)", (product_id, image_path))
            conn.commit()
                
            flash("Product updated successfully!", 'success')
            return redirect(url_for('vendor.products_index'))

        c.execute("SELECT id, name FROM categories")
        categories = [dict(row) for row in c.fetchall()]
    
    return render_template('user/products/edit.html', product=dict(product), categories=categories, title="Edit Product - DarkVault")

@vendor_bp.route('/products/delete/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session:
        flash("You must be a vendor to access this page.", 'error')
        return redirect(url_for('user.login'))
    
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT image_path FROM products WHERE id = ? AND vendor_id = ?", (product_id, session['user_id']))
        product = c.fetchone()
        if not product:
            flash("Product not found or you don’t have permission.", 'error')
            return redirect(url_for('vendor.products_index'))
        
        if product['image_path'] and os.path.exists(product['image_path']):
            os.remove(product['image_path'])
        
        c.execute("DELETE FROM products WHERE id = ? AND vendor_id = ?", (product_id, session['user_id']))
        conn.commit()
        flash("Product deleted successfully.", 'success')
        return redirect(url_for('vendor.products_index'))
    
@vendor_bp.route('/orders')
@require_vendor_role
def vendor_orders():
    if 'user_id' not in session:
        flash("Please log in to view your orders.", 'error')
        return redirect(url_for('user.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT o.id, o.user_id, o.product_id, o.amount_usd, o.amount_btc, o.status, o.escrow_status, o.created_at, p.title, u.pusername as buyer_username
            FROM orders o
            JOIN products p ON o.product_id = p.id
            JOIN users u ON o.user_id = u.id
            WHERE o.vendor_id = ?
            ORDER BY o.created_at DESC
        """, (session['user_id'],))
        orders = [dict(row) for row in c.fetchall()]
    
    return render_template('user/orders/index.html', orders=orders, title="Vendor Orders - DarkVault")

@vendor_bp.route('/orders/<int:order_id>', methods=['GET', 'POST'])
@require_vendor_role
def vendor_order_detail(order_id):
    if 'user_id' not in session:
        flash("Please log in to view order details.", 'error')
        return redirect(url_for('user.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT o.*, p.title, u.pusername as buyer_username
            FROM orders o
            JOIN products p ON o.product_id = p.id
            JOIN users u ON o.user_id = u.id
            WHERE o.id = ? AND o.vendor_id = ?
        """, (order_id, session['user_id']))
        order = c.fetchone()
        if not order:
            flash("Order not found or you don’t have permission to view it.", 'error')
            return redirect(url_for('vendor.vendor_orders'))

        if request.method == 'POST':
            validate_csrf_token()
            status = request.form.get('status', '').strip()
            escrow_status = request.form.get('escrow_status', '').strip()

            valid_statuses = ['pending', 'shipped', 'delivered', 'cancelled']
            valid_escrow_statuses = ['held', 'released', 'refunded']
            if status not in valid_statuses or escrow_status not in valid_escrow_statuses:
                flash("Invalid status or escrow status selected.", 'error')
                return render_template('user/orders/detail.html', order=dict(order))

            c.execute("""
                UPDATE orders 
                SET status = ?, escrow_status = ?
                WHERE id = ? AND vendor_id = ?
            """, (status, escrow_status, order_id, session['user_id']))
            conn.commit()
            flash("Order updated successfully!", 'success')
            return redirect(url_for('vendor.vendor_orders'))

    return render_template('user/orders/detail.html', order=dict(order), title="Order Details - DarkVault")

def verify_btc_payment(txid, amount_btc, address):
    url = f"https://blockchain.info/rawtx/{txid}"
    try:
        response = requests.get(url, timeout=5)
        data = response.json()
        total_btc = sum(out['value'] for out in data['out'] if out['addr'] == address) / 100000000  # Convert satoshis to BTC
        return total_btc >= amount_btc * 0.95  # Allow 5% variance for fees
    except Exception as e:
        print(f"Error verifying BTC payment: {str(e)}")
        return False

def verify_xmr_payment(txid, amount_xmr, address):
    # Requires Monero RPC setup (replace with your RPC details)
    try:
        wallet = MoneroWallet(JSONRPCWallet(host="localhost", port=18082, user="your_rpc_username", password="your_rpc_password"))
        tx = wallet.get_transaction(txid)
        return tx.amount >= amount_xmr * 0.95 and address in [dest.address for dest in tx.destinations]
    except Exception as e:
        print(f"Error verifying XMR payment: {str(e)}")
        return False

@vendor_bp.route('/vendor/subscribe', methods=['GET', 'POST'])
def subscribe():
    if 'user_id' not in session:
        flash("Please log in.", 'error')
        return redirect(url_for('auth.login'))

    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT role FROM users WHERE id = ?", (session['user_id'],))
            user = c.fetchone()
            if not user or user['role'] != 'vendor':
                flash("Only vendors can subscribe.", 'error')
                return redirect(url_for('public.index'))

            c.execute("SELECT * FROM vendor_subscriptions WHERE vendor_id = ? AND status = 'active'", (session['user_id'],))
            active_sub = c.fetchone()

            if request.method == 'POST':
                package_id = request.form.get('package_id', type=int)
                crypto_currency = request.form.get('crypto_currency')

                if not package_id or crypto_currency not in ['BTC', 'XMR']:
                    flash("Invalid package or currency.", 'error')
                    return redirect(url_for('vendor.subscribe'))

                c.execute("SELECT * FROM packages WHERE id = ?", (package_id,))
                package = c.fetchone()
                if not package:
                    flash("Package not found.", 'error')
                    return redirect(url_for('vendor.subscribe'))

                package = dict(package)
                crypto_price = get_crypto_price(crypto_currency)
                if not crypto_price:
                    flash("Unable to fetch crypto price. Try again later.", 'error')
                    return redirect(url_for('vendor.subscribe'))

                crypto_amount = package['price_usd'] / crypto_price
                wallet_address = ADMIN_BTC_ADDRESS if crypto_currency == "BTC" else ADMIN_XMR_ADDRESS

                expires_at = datetime.datetime.now() + datetime.timedelta(days=30)
                c.execute("""
                    INSERT INTO vendor_subscriptions (vendor_id, package_id, status, expires_at, payment_txid)
                    VALUES (?, ?, 'pending', ?, ?)
                """, (session['user_id'], package_id, expires_at, None))
                conn.commit()

                flash(f"Please send {crypto_amount:.6f} {crypto_currency} to {wallet_address} and provide the TXID below.", 'info')
                return redirect(url_for('vendor.confirm_payment', package_id=package_id, crypto_currency=crypto_currency))

            c.execute("SELECT * FROM packages")
            packages = [dict(row) for row in c.fetchall()]
            btc_price = get_crypto_price("BTC")
            xmr_price = get_crypto_price("XMR")

            return render_template('vendor/subscribe.html', packages=packages, active_sub=active_sub, 
                                 btc_price=btc_price, xmr_price=xmr_price)
    except Exception as e:
        print(f"Error in subscribe: {str(e)}")
        flash("An error occurred.", 'error')
        return redirect(url_for('public.index'))

@vendor_bp.route('/vendor/confirm_payment/<int:package_id>/<crypto_currency>', methods=['GET', 'POST'])
def confirm_payment(package_id, crypto_currency):
    if 'user_id' not in session:
        flash("Please log in.", 'error')
        return redirect(url_for('auth.login'))

    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT role FROM users WHERE id = ?", (session['user_id'],))
            user = c.fetchone()
            if not user or user['role'] != 'vendor':
                flash("Only vendors can confirm payment.", 'error')
                return redirect(url_for('public.index'))

            c.execute("SELECT * FROM packages WHERE id = ?", (package_id,))
            package = dict(c.fetchone())
            crypto_price = get_crypto_price(crypto_currency)
            crypto_amount = package['price_usd'] / crypto_price if crypto_price else 0
            wallet_address = ADMIN_BTC_ADDRESS if crypto_currency == "BTC" else ADMIN_XMR_ADDRESS

            if request.method == 'POST':
                txid = request.form.get('txid')
                if not txid:
                    flash("Please provide a transaction ID.", 'error')
                else:
                    # Verify payment
                    verified = (crypto_currency == "BTC" and verify_btc_payment(txid, crypto_amount, wallet_address)) or \
                               (crypto_currency == "XMR" and verify_xmr_payment(txid, crypto_amount, wallet_address))
                    
                    if verified:
                        c.execute("""
                            UPDATE vendor_subscriptions 
                            SET payment_txid = ?, status = 'active'
                            WHERE vendor_id = ? AND package_id = ? AND status = 'pending'
                        """, (txid, session['user_id'], package_id))
                        if c.rowcount > 0:
                            conn.commit()
                            flash("Payment verified! Subscription activated.", 'success')
                            return redirect(url_for('public.index'))
                        else:
                            flash("No pending subscription found.", 'error')
                    else:
                        flash("Payment verification failed. Check TXID or contact support.", 'error')

            return render_template('vendor/confirm_payment.html', package=package, crypto_currency=crypto_currency,
                                 crypto_amount=crypto_amount, wallet_address=wallet_address)
    except Exception as e:
        print(f"Error in confirm_payment: {str(e)}")
        flash("An error occurred.", 'error')
        return redirect(url_for('public.index'))