from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from utils.database import get_db_connection, get_settings
#from utils.security import validate_csrf_token
from utils.auth import has_active_subscription
from routes import require_role
from werkzeug.utils import secure_filename
from flask_wtf.csrf import generate_csrf
import logging
import os
import datetime
import requests
import re

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

vendor_bp = Blueprint('vendor', __name__)

@vendor_bp.context_processor
def inject_csrf_token():
    return {'csrf_token': generate_csrf}

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

        # Determine level (10 levels)
        level = 1  # Default
        if sales >= 2000 and positive_reviews >= 200 and negative_reviews < 50 and completion_rate > 95:
            level = 10
        elif sales >= 1000 and positive_reviews >= 150 and negative_reviews < 40 and completion_rate > 94:
            level = 9
        elif sales >= 500 and positive_reviews >= 100 and negative_reviews < 30 and completion_rate > 93:
            level = 8
        elif sales >= 250 and positive_reviews >= 75 and negative_reviews < 25 and completion_rate > 92:
            level = 7
        elif sales >= 100 and positive_reviews >= 50 and negative_reviews < 15 and completion_rate > 90:
            level = 6
        elif sales >= 51 and positive_reviews >= 30 and negative_reviews < 10 and completion_rate > 85:
            level = 5
        elif sales >= 25 and positive_reviews >= 20 and negative_reviews < 8 and completion_rate > 82:
            level = 4
        elif sales >= 21 and positive_reviews >= 15 and negative_reviews < 5 and completion_rate > 80:
            level = 3
        elif sales >= 6 and positive_reviews >= 5 and negative_reviews < 2:
            level = 2

        # Update vendor level in database
        c.execute("UPDATE users SET level = ? WHERE id = ?", (level, vendor_id))
        conn.commit()
        
        return level

@vendor_bp.route('/support', methods=['GET', 'POST'])
@require_vendor_role
def vendor_support():
    """Vendor support page to submit and view tickets."""
    try:
        from utils.support import secure_support
        
        user_id = session.get('user_id')
        if not user_id:
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
            elif category not in ['Vendor Support', 'Account', 'Payment', 'Dispute', 'Technical']:
                flash("Invalid category.", 'error')
            elif priority not in ['Low', 'Medium', 'High']:
                flash("Invalid priority.", 'error')
            else:
                # Create secure ticket
                ticket_id = secure_support.create_secure_ticket(
                    user_id, subject, description, category, priority, 'vendor'
                )
                
                if ticket_id:
                    flash("Secure support ticket submitted successfully.", 'success')
                    logger.info(f"Vendor {user_id} submitted secure ticket: {subject}")
                    return redirect(url_for('vendor.vendor_support'))
                else:
                    flash("Failed to create ticket. Please try again.", 'error')

        # Fetch vendor's tickets using secure system
        tickets = secure_support.get_user_tickets(user_id, 'vendor')

        # Available options for form
        categories = ['Vendor Support', 'Account', 'Payment', 'Dispute', 'Technical']
        priorities = ['Low', 'Medium', 'High']

        logger.info(f"Vendor support page loaded successfully for vendor {user_id}")
        
        return render_template('vendor/support.html',
                             tickets=tickets,
                             categories=categories,
                             priorities=priorities,
                             settings=get_settings())
                             
    except Exception as e:
        logger.error(f"Error in vendor support: {str(e)}")
        flash("An error occurred. Please try again.", 'error')
        return redirect(url_for('vendor.dashboard'))

@vendor_bp.route('/support/ticket/<int:ticket_id>', methods=['GET', 'POST'])
@require_vendor_role
def vendor_view_ticket_details(ticket_id):
    """View and respond to a specific support ticket."""
    try:
        from utils.support import secure_support
        
        user_id = session.get('user_id')
        if not user_id:
            flash("Please log in to view tickets.", 'error')
            return redirect(url_for('user.login'))
        
        # Get ticket with responses using secure system
        ticket, responses = secure_support.get_ticket_with_responses(ticket_id, user_id, 'vendor')
        
        if not ticket:
            flash("Ticket not found or access denied.", 'error')
            return redirect(url_for('vendor.vendor_support'))
        
        # Verify vendor owns this ticket
        if ticket['user_id'] != user_id:
            flash("Access denied.", 'error')
            return redirect(url_for('vendor.vendor_support'))

        if request.method == 'POST':
            response_body = request.form.get('response_body', '').strip()
            if not response_body:
                flash("Response body is required.", 'error')
            elif len(response_body) > 2000:
                flash("Response is too long.", 'error')
            else:
                # Add secure response
                success = secure_support.add_secure_response(
                    ticket_id, user_id, response_body, 'vendor'
                )
                
                if success:
                    flash("Secure response submitted successfully.", 'success')
                    logger.info(f"Vendor {user_id} responded to secure ticket #{ticket_id}")
                    return redirect(url_for('vendor.vendor_view_ticket_details', ticket_id=ticket_id))
                else:
                    flash("Failed to submit response. Please try again.", 'error')

        return render_template('vendor/ticket_details.html',
                             ticket=ticket,
                             responses=responses,
                             settings=get_settings())
    except Exception as e:
        logger.error(f"Error handling vendor ticket #{ticket_id}: {str(e)}")
        flash("An error occurred. Please try again.", 'error')
        return redirect(url_for('vendor.vendor_support'))

@vendor_bp.route('/stats')
@require_vendor_role
def vendor_stats():
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
            SELECT m.id, m.content, m.created_at, u.pusername as sender
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE m.recipient_id = ? AND m.trashed = 0
            ORDER BY m.created_at DESC LIMIT 5
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
    
    return render_template('user/vendor_dashboard.html', vendor_name=vendor_name, stats=stats, recent_orders=recent_orders, recent_reviews=recent_reviews, recent_messages=recent_messages, title="Vendor Dashboard - Sydney")

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
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

    # Check if user is actually a vendor in the database
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT role, is_vendor FROM users WHERE id = ?", (session['user_id'],))
        user_data = c.fetchone()
        
        if not user_data:
            flash("User not found. Please log in again.", 'error')
            session.clear()
            return redirect(url_for('user.login'))
        
        if user_data['role'] != 'vendor' and not user_data['is_vendor']:
            flash("You must be a vendor to access this page.", 'error')
            return redirect(url_for('user.dashboard'))

    # Get filter parameters
    status_filter = request.args.get('status', 'all')
    category_id_filter = request.args.get('category_id', 'all')

    # Validate status filter
    valid_statuses = ['all', 'pending', 'active', 'rejected', 'disabled']
    if status_filter not in valid_statuses:
        flash("Invalid status filter.", 'error')
        status_filter = 'all'
    
    logger.info(f"Vendor products request - user_id: {session['user_id']}, role: {session.get('role')}, status_filter: {status_filter}, category_filter: {category_id_filter}")

    try:
        with get_db_connection() as conn:
            c = conn.cursor()

            # Check if categories table exists and has data
            try:
                c.execute("SELECT id, name FROM categories ORDER BY name")
                categories = [dict(row) for row in c.fetchall()]
            except Exception as cat_error:
                logger.warning(f"Categories table error: {str(cat_error)}")
                categories = []

            # Build query with better error handling
            try:
                # Query with categories JOIN to get category names
                query = """
                    SELECT p.id, p.title, p.price_usd, p.stock, p.status, p.created_at, p.rejection_reason,
                           p.featured_image, c.name as category_name
                    FROM products p
                    LEFT JOIN categories c ON p.category_id = c.id
                    WHERE p.vendor_id = ?
                """
                params = [session['user_id']]

                # Apply filters
                if status_filter != 'all':
                    query += " AND p.status = ?"
                    params.append(status_filter)
                if category_id_filter != 'all':
                    try:
                        category_id = int(category_id_filter)
                        query += " AND p.category_id = ?"
                        params.append(category_id)
                    except ValueError:
                        flash("Invalid category filter.", 'error')
                        category_id_filter = 'all'

                query += " ORDER BY p.created_at DESC"
                logger.info(f"Executing query: {query} with params: {params}")
                c.execute(query, params)
                products = [dict(row) for row in c.fetchall()]
                
                # Set category_name to 'Uncategorized' if it's None
                for product in products:
                    if product['category_name'] is None:
                        product['category_name'] = 'Uncategorized'
                
                logger.info(f"Successfully loaded {len(products)} products for vendor {session['user_id']}")
                if products:
                    logger.info(f"Sample product: {products[0]}")
                else:
                    # Check if there are any products for this vendor at all
                    c.execute("SELECT COUNT(*) FROM products WHERE vendor_id = ?", [session['user_id']])
                    total_count = c.fetchone()[0]
                    logger.warning(f"No products found for vendor {session['user_id']}, but there are {total_count} products total for this vendor")
                    
                    # Check what products exist for this vendor
                    c.execute("SELECT id, title, status FROM products WHERE vendor_id = ?", [session['user_id']])
                    all_vendor_products = c.fetchall()
                    logger.warning(f"All products for vendor {session['user_id']}: {all_vendor_products}")
                
            except Exception as query_error:
                logger.error(f"Products query error: {str(query_error)}")
                # Fallback to simpler query with categories
                try:
                    c.execute("""
                        SELECT p.id, p.title, p.price_usd, p.stock, p.status, p.created_at, p.rejection_reason,
                               p.featured_image, c.name as category_name
                        FROM products p
                        LEFT JOIN categories c ON p.category_id = c.id
                        WHERE p.vendor_id = ?
                        ORDER BY p.created_at DESC
                    """, [session['user_id']])
                    products = [dict(row) for row in c.fetchall()]
                    # Set category_name to 'Uncategorized' if it's None
                    for product in products:
                        if product['category_name'] is None:
                            product['category_name'] = 'Uncategorized'
                    logger.info(f"Fallback query loaded {len(products)} products")
                except Exception as fallback_error:
                    logger.error(f"Fallback query error: {str(fallback_error)}")
                    products = []

    except Exception as e:
        logger.error(f"Database connection error: {str(e)}")
        flash("Unable to load products due to a database error. Please try again.", 'error')
        products = []
        categories = []

    return render_template(
        'user/products/index.html',
        products=products,
        categories=categories,
        status_filter=status_filter,
        category_id_filter=category_id_filter,
        title="Your Products - Sydney"
    )

@vendor_bp.route('/debug')
def debug_info():
    """Debug route to check current user info"""
    if 'user_id' not in session:
        return "Not logged in"
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT id, username, role, is_vendor FROM users WHERE id = ?", (session['user_id'],))
        user = c.fetchone()
        
        if not user:
            return "User not found"
        
        # Check products for this user
        c.execute("SELECT id, title, status FROM products WHERE vendor_id = ?", (session['user_id'],))
        products = c.fetchall()
        
        # Test the exact query from the vendor products route
        try:
            c.execute("""
                SELECT p.id, p.title, p.price_usd, p.stock, p.status, p.created_at, p.rejection_reason
                FROM products p
                WHERE p.vendor_id = ?
                ORDER BY p.created_at DESC
            """, (session['user_id'],))
            route_products = c.fetchall()
        except Exception as e:
            route_products = []
            error_msg = str(e)
        
        return f"""
        <h2>Debug Info</h2>
        <p>Session User ID: {session['user_id']}</p>
        <p>Username: {user['username']}</p>
        <p>Role: {user['role']}</p>
        <p>Is Vendor: {user['is_vendor']}</p>
        <p>Products for this user: {len(products)}</p>
        <ul>
        {''.join([f'<li>ID: {p[0]}, Title: {p[1]}, Status: {p[2]}</li>' for p in products])}
        </ul>
        
        <h3>Route Query Test</h3>
        <p>Products from route query: {len(route_products)}</p>
        <ul>
        {''.join([f'<li>ID: {p[0]}, Title: {p[1][:30]}..., Status: {p[4]}</li>' for p in route_products]) if route_products else f'<li>Error: {error_msg}</li>'}
        </ul>
        
        <p><a href="/vendor/products">Go to Vendor Products Page</a></p>
        """
@vendor_bp.route('/products/create', methods=['GET', 'POST'])
# Do NOT use @require_vendor_role here; we want to redirect non-vendors to the vendor subscription page, not the dashboard.
def products_create():
    if 'user_id' not in session:
        flash("Please log in to create a product.", 'error')
        return redirect(url_for('user.login'))

    user_id = session['user_id']
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT role FROM users WHERE id = ?", (user_id,))
        user = c.fetchone()
        user_role = user['role'] if user else None

    # If not vendor or no active subscription, redirect to subscribe
    from utils.auth import has_active_subscription
    if user_role != 'vendor' or not has_active_subscription(user_id):
        flash("You must be a vendor with an active subscription to create products.", 'error')
        return redirect(url_for('vendor.subscribe'))
    
    # Check if vendor has PGP key set in vendor settings
    c.execute("SELECT pgp_public_key FROM vendor_settings WHERE user_id = ?", (user_id,))
    vendor_settings = c.fetchone()
    if not vendor_settings or not vendor_settings['pgp_public_key']:
        flash("You must set a PGP public key in your vendor settings before creating products.", 'error')
        return redirect(url_for('vendor.vendor_settings'))

    if request.method == 'POST':
        # Form fields
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        price_usd = request.form.get('price_usd', '').strip()
        original_price_usd = request.form.get('original_price_usd', '').strip()
        discount_active = 'discount_active' in request.form
        stock = request.form.get('stock', '').strip()
        category_id = request.form.get('category_id', '').strip()
        sku = request.form.get('sku', '').strip()
        weight_grams = request.form.get('weight_grams', '').strip()
        shipping_dimensions = request.form.get('shipping_dimensions', '').strip()
        shipping_methods = request.form.get('shipping_methods', '').strip()
        shipping_origin = request.form.get('shipping_origin', '').strip()
        shipping_destinations = request.form.get('shipping_destinations', '').strip()
        moq = request.form.get('moq', '').strip()
        lead_time = request.form.get('lead_time', '').strip()
        packaging_details = request.form.get('packaging_details', '').strip()
        tags = request.form.get('tags', '').strip()
        product_type = request.form.get('product_type', '').strip()
        return_policy = request.form.get('return_policy', '').strip()
        origin_country = request.form.get('origin_country', '').strip()
        featured_image = request.files.get('featured_image')
        additional_images = request.files.getlist('additional_images')

        # Validation
        if not all([title, price_usd, stock, category_id, shipping_destinations, product_type]):
            flash("Required fields (title, price, stock, category, shipping destinations, product type) are missing.", 'error')
            return render_template('user/products/create.html', form_data=request.form.to_dict())

        # Validate no URLs (Rule #10)
        if re.search(r'\bhttp[s]?://|www\.|\.com\b', description + tags, re.I):
            flash("Description and tags cannot contain URLs or promotional content.", 'error')
            return render_template('user/products/create.html', form_data=request.form.to_dict())

        # Validate numeric fields
        try:
            price_usd = float(price_usd)
            stock = int(stock)
            category_id = int(category_id)
            original_price_usd = float(original_price_usd) if original_price_usd else None
            weight_grams = float(weight_grams) if weight_grams and product_type == 'physical' else None
            moq = int(moq) if moq else 1
            if price_usd <= 0 or stock < 0 or (original_price_usd and original_price_usd <= 0) or (weight_grams and weight_grams < 0) or moq < 1:
                raise ValueError("Invalid numeric values")
        except ValueError:
            flash("Numeric fields must be valid and positive (except stock can be 0).", 'error')
            return render_template('user/products/create.html', form_data=request.form.to_dict())

        # Validate product type
        if product_type not in ['physical', 'digital']:
            flash("Product type must be physical or digital.", 'error')
            return render_template('user/products/create.html', form_data=request.form.to_dict())

        # Calculate crypto prices
        btc_rate = get_crypto_price('BTC') or 70000  # Fallback rate
        xmr_rate = get_crypto_price('XMR') or 150    # Fallback rate
        price_btc = price_usd / btc_rate
        price_xmr = price_usd / xmr_rate

        # Handle featured image
        featured_image_path = None
        if featured_image and allowed_file(featured_image.filename):
            filename = secure_filename(f"{session['user_id']}_{featured_image.filename}")
            featured_image_path = f"uploads/products/{filename}"
            featured_image.save(os.path.join(UPLOAD_FOLDER_PRODUCTS, filename))

        # Insert product
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO products (
                    title, description, price_usd, price_btc, price_xmr, original_price_usd, origin_country,
                    discount_active, stock, category_id, vendor_id, sku, weight_grams, shipping_dimensions,
                    shipping_methods, shipping_origin, shipping_destinations, moq, lead_time, packaging_details, tags,
                    product_type, return_policy, status, featured_image
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                title, description, price_usd, price_btc, price_xmr, original_price_usd, origin_country,
                discount_active, stock, category_id, session['user_id'], sku, weight_grams, shipping_dimensions,
                shipping_methods, shipping_origin, shipping_destinations, moq, lead_time, packaging_details, tags,
                product_type, return_policy, 'pending', featured_image_path
            ))
            product_id = c.lastrowid

            # Handle additional images
            for image in additional_images:
                if image and allowed_file(image.filename):
                    filename = secure_filename(f"{session['user_id']}_{image.filename}")
                    image_path = f"uploads/products/{filename}"
                    image.save(os.path.join(UPLOAD_FOLDER_PRODUCTS, filename))
                    c.execute("INSERT INTO product_images (product_id, image_path) VALUES (?, ?)", (product_id, image_path))

            conn.commit()

        flash("Product created and is pending admin approval.", 'success')
        return redirect(url_for('vendor.products_index'))

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT id, name FROM categories ORDER BY name")
        categories = [dict(row) for row in c.fetchall()]

    return render_template('user/products/create.html', categories=categories, title="Create Product - Sydney")

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
            flash("Product not found or you don't have permission to edit it.", 'error')
            return redirect(url_for('vendor.products_index'))

        if request.method == 'POST':
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            price_usd = request.form.get('price_usd', type=float)
            original_price_usd = request.form.get('original_price_usd', type=float)
            discount_active = bool(request.form.get('discount_active'))
            stock = request.form.get('stock', type=int)
            category_id = request.form.get('category_id', type=int)
            sku = request.form.get('sku', '').strip() or None
            weight_grams = request.form.get('weight_grams', type=float)
            shipping_dimensions = request.form.get('shipping_dimensions', '').strip() or None
            shipping_methods = request.form.get('shipping_methods', '').strip() or None
            moq = request.form.get('moq', type=int, default=1)
            lead_time = request.form.get('lead_time', '').strip() or None
            packaging_details = request.form.get('packaging_details', '').strip() or None
            tags = request.form.get('tags', '').strip() or None
            origin_country = request.form.get('origin_country', '').strip() or None
            return_policy = request.form.get('return_policy', '').strip() or None
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
                weight_grams = float(weight_grams) if weight_grams else None
                moq = int(moq) if moq else 1
                if price_usd <= 0 or stock < 0 or (original_price_usd is not None and original_price_usd <= 0) or (weight_grams is not None and weight_grams < 0) or moq < 1:
                    raise ValueError("Invalid numeric values")
            except ValueError:
                flash("Numeric fields must be valid and positive (except stock can be 0).", 'error')
                return render_template('user/products/edit.html', product=dict(product), form_data=request.form.to_dict())

            c.execute("""
                    UPDATE products 
                    SET title = ?, description = ?, price_usd = ?, original_price_usd = ?, origin_country = ?, discount_active = ?, stock = ?, category_id = ?, sku = ?, weight_grams = ?, shipping_dimensions = ?, shipping_methods = ?, moq = ?, lead_time = ?, packaging_details = ?, tags = ?, return_policy = ?, status = ?, featured_image = ?
                    WHERE id = ? AND vendor_id = ?
                """, (title, description, price_usd, original_price_usd, origin_country, discount_active, stock, category_id, sku, weight_grams, shipping_dimensions, shipping_methods, moq, lead_time, packaging_details, tags, return_policy, status, featured_image_path, product_id, session['user_id']))
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
    
    return render_template('user/products/edit.html', product=dict(product), categories=categories, title="Edit Product - Sydney")

@vendor_bp.route('/products/delete/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session:
        flash("You must be a vendor to access this page.", 'error')
        return redirect(url_for('user.login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        # Get product details including featured image
        c.execute("SELECT featured_image FROM products WHERE id = ? AND vendor_id = ?", (product_id, session['user_id']))
        product = c.fetchone()
        if not product:
            flash("Product not found or you don't have permission.", 'error')
            return redirect(url_for('vendor.products_index'))
        
        # Delete featured image file if it exists
        if product['featured_image']:
            try:
                featured_image_path = os.path.join(UPLOAD_FOLDER_PRODUCTS, os.path.basename(product['featured_image']))
                if os.path.exists(featured_image_path):
                    os.remove(featured_image_path)
            except OSError:
                pass  # File might not exist, continue with deletion
        
        # Get and delete additional images
        c.execute("SELECT image_path FROM product_images WHERE product_id = ?", (product_id,))
        additional_images = c.fetchall()
        for img in additional_images:
            try:
                image_path = os.path.join(UPLOAD_FOLDER_PRODUCTS, os.path.basename(img['image_path']))
                if os.path.exists(image_path):
                    os.remove(image_path)
            except OSError:
                pass  # File might not exist, continue with deletion
        
        # Delete additional images from database
        c.execute("DELETE FROM product_images WHERE product_id = ?", (product_id,))
        
        # Delete the product
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
    
    return render_template('user/orders/index.html', orders=orders, title="Vendor Orders - Sydney")

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
            flash("Order not found or you don't have permission to view it.", 'error')
            return redirect(url_for('vendor.vendor_orders'))

        if request.method == 'POST':
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

    return render_template('user/orders/detail.html', order=dict(order), title="Order Details - Sydney")

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
        return redirect(url_for('user.login'))

    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT role FROM users WHERE id = ?", (session['user_id'],))
            user = c.fetchone()
            if not user or user['role'] != 'vendor':
                flash("You must be a vendor to access the subscription page.", 'error')
                return redirect(url_for('user.become_vendor'))

            c.execute("SELECT * FROM vendor_subscriptions WHERE vendor_id = ? AND status = 'active'", (session['user_id'],))
            active_sub = c.fetchone()

            if request.method == 'POST':
                package_id = request.form.get('package_id', type=int)
                c.execute("SELECT * FROM packages WHERE id = ?", (package_id,))
                package = c.fetchone()
                if not package:
                    flash("Package not found.", 'error')
                    return redirect(url_for('vendor.subscribe'))
                package = dict(package)
                if package.get('free', 0) == 1:
                    # Free package: activate immediately
                    expires_at = datetime.datetime.now() + datetime.timedelta(days=30)
                    c.execute("""
                        INSERT INTO vendor_subscriptions (vendor_id, package_id, status, expires_at, payment_txid)
                        VALUES (?, ?, 'active', ?, NULL)
                    """, (session['user_id'], package_id, expires_at))
                    conn.commit()
                    flash("Free package activated! You now have an active subscription.", 'success')
                    return redirect(url_for('vendor.products_index'))
                # Paid package: require crypto selection and payment
                crypto_currency = request.form.get('crypto_currency')
                if crypto_currency not in ['BTC', 'XMR']:
                    flash("Invalid currency.", 'error')
                    return redirect(url_for('vendor.subscribe'))
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
        return redirect(url_for('user.become_vendor'))

@vendor_bp.route('/vendor/confirm_payment/<int:package_id>/<crypto_currency>', methods=['GET', 'POST'])
def confirm_payment(package_id, crypto_currency):
    if 'user_id' not in session:
        flash("Please log in.", 'error')
        return redirect(url_for('user.login'))

    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT role FROM users WHERE id = ?", (session['user_id'],))
            user = c.fetchone()
            if not user or user['role'] != 'vendor':
                flash("You must be a vendor to confirm payment.", 'error')
                return redirect(url_for('user.become_vendor'))

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
                            return redirect(url_for('vendor.products_index'))
                        else:
                            flash("No pending subscription found.", 'error')
                    else:
                        flash("Payment verification failed. Check TXID or contact support.", 'error')

            return render_template('vendor/confirm_payment.html', package=package, crypto_currency=crypto_currency,
                                 crypto_amount=crypto_amount, wallet_address=wallet_address)
    except Exception as e:
        print(f"Error in confirm_payment: {str(e)}")
        flash("An error occurred.", 'error')
        return redirect(url_for('user.become_vendor'))

@vendor_bp.route('/messages', methods=['GET', 'POST'])
@require_vendor_role
def vendor_messages():
    """Vendor messages - view and respond to messages from users"""
    if 'user_id' not in session:
        flash("Please log in to view messages.", 'error')
        return redirect(url_for('user.login'))
    
    vendor_id = session['user_id']
    
    with get_db_connection() as conn:
        c = conn.cursor()
        
        # Get vendor's PGP key
        c.execute("SELECT pgp_public_key FROM vendor_settings WHERE user_id = ?", (vendor_id,))
        vendor_pgp = c.fetchone()
        vendor_has_pgp = bool(vendor_pgp and vendor_pgp['pgp_public_key'])
        
        if request.method == 'POST':
            message_id = request.form.get('message_id', type=int)
            response = request.form.get('response', '').strip()
            
            if not message_id or not response:
                flash("Message ID and response are required.", 'error')
                return redirect(url_for('vendor.vendor_messages'))
            
            # Verify the message belongs to this vendor
            c.execute("SELECT id FROM messages WHERE id = ? AND recipient_id = ?", (message_id, vendor_id))
            message = c.fetchone()
            if not message:
                flash("Message not found or access denied.", 'error')
                return redirect(url_for('vendor.vendor_messages'))
            
            # Get sender's PGP key for encryption
            c.execute("SELECT sender_id FROM messages WHERE id = ?", (message_id,))
            sender_info = c.fetchone()
            if sender_info:
                c.execute("SELECT pgp_public_key FROM users WHERE id = ?", (sender_info['sender_id'],))
                sender_pgp = c.fetchone()
                sender_has_pgp = bool(sender_pgp and sender_pgp['pgp_public_key'])
                
                # Encrypt response if both parties have PGP keys
                response_content = response
                if vendor_has_pgp and sender_has_pgp:
                    try:
                        from utils.pgp_utils import pgp_utils
                        encrypted_content = pgp_utils.encrypt_message(sender_pgp['pgp_public_key'], response_content)
                        if encrypted_content != response_content:
                            response_content = encrypted_content
                        else:
                            flash("Encryption failed, sending as plain text.", 'warning')
                    except Exception as e:
                        logger.error(f"PGP encryption error: {e}")
                        flash("Encryption failed, sending as plain text.", 'warning')
                elif not vendor_has_pgp and not sender_has_pgp:
                    pass  # Both parties don't have PGP - send as plain text
                else:
                    flash("One party doesn't have PGP key, sending as plain text.", 'info')
                
                # Store response
                c.execute("""
                    INSERT INTO messages (sender_id, recipient_id, content, created_at)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                """, (vendor_id, sender_info['sender_id'], response_content))
                conn.commit()
                
                flash("Response sent successfully!", 'success')
                return redirect(url_for('vendor.vendor_messages'))
        
        # Get messages for this vendor
        c.execute("""
            SELECT m.id, m.content, m.created_at, u.pusername as sender_name
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE m.recipient_id = ? AND m.sender_id != ?
            ORDER BY m.created_at DESC
        """, (vendor_id, vendor_id))
        messages = [dict(row) for row in c.fetchall()]
        
        return render_template('vendor/messages.html', 
                             messages=messages, 
                             vendor_has_pgp=vendor_has_pgp)

@vendor_bp.route('/settings', methods=['GET', 'POST'])
@require_vendor_role
def vendor_settings():
    if 'user_id' not in session:
        flash("Please log in to access vendor settings.", 'error')
        return redirect(url_for('user.login'))
    user_id = session['user_id']
    with get_db_connection() as conn:
        c = conn.cursor()
        # Fetch vendor info (all fields)
        c.execute("""
            SELECT business_name, description, logo, banner, pgp_public_key, bond_status, verification_status, shipping_methods, vacation_mode, notify_orders, notify_messages, notify_disputes, btc_address, xmr_address, refund_policy
            FROM vendor_settings WHERE user_id = ?
        """, (user_id,))
        vendor = c.fetchone()
        if not vendor:
            vendor = {
                'business_name': '', 'description': '', 'logo': '', 'banner': '',
                'pgp_public_key': '', 'bond_status': 'Not posted', 'verification_status': 'Unverified',
                'shipping_methods': '', 'vacation_mode': 'off',
                'notify_orders': 1, 'notify_messages': 1, 'notify_disputes': 1,
                'btc_address': '', 'xmr_address': '', 'refund_policy': ''
            }
        else:
            vendor = dict(vendor)
        if request.method == 'POST':
            # Get form data
            business_name = request.form.get('store_name', '').strip()
            description = request.form.get('store_description', '').strip()
            refund_policy = request.form.get('refund_policy', '').strip()
            pgp_public_key = request.form.get('pgp_public_key', '').strip()
            shipping_methods = request.form.get('shipping_methods', '').strip()
            vacation_mode = request.form.get('vacation_mode', 'off')
            notify_orders = 1 if request.form.get('notify_orders') else 0
            notify_messages = 1 if request.form.get('notify_messages') else 0
            notify_disputes = 1 if request.form.get('notify_disputes') else 0
            btc_address = request.form.get('btc_address', '').strip()
            xmr_address = request.form.get('xmr_address', '').strip()
            # File uploads (logo/banner)
            logo_file = request.files.get('store_logo')
            banner_file = request.files.get('store_banner')
            logo = vendor.get('logo', '')
            banner = vendor.get('banner', '')
            if logo_file and logo_file.filename:
                filename = secure_filename(logo_file.filename)
                logo_path = os.path.join('static/uploads/avatar', filename)
                logo_file.save(logo_path)
                logo = filename
            if banner_file and banner_file.filename:
                filename = secure_filename(banner_file.filename)
                banner_path = os.path.join('static/uploads/avatar', filename)
                banner_file.save(banner_path)
                banner = filename
            # Update or insert
            c.execute("SELECT id FROM vendor_settings WHERE user_id = ?", (user_id,))
            exists = c.fetchone()
            if exists:
                c.execute("""
                    UPDATE vendor_settings SET business_name=?, description=?, refund_policy=?, logo=?, banner=?, pgp_public_key=?, shipping_methods=?, vacation_mode=?, notify_orders=?, notify_messages=?, notify_disputes=?, btc_address=?, xmr_address=? WHERE user_id=?
                """, (business_name, description, refund_policy, logo, banner, pgp_public_key, shipping_methods, vacation_mode, notify_orders, notify_messages, notify_disputes, btc_address, xmr_address, user_id))
            else:
                c.execute("""
                    INSERT INTO vendor_settings (user_id, business_name, description, refund_policy, logo, banner, pgp_public_key, shipping_methods, vacation_mode, notify_orders, notify_messages, notify_disputes, btc_address, xmr_address)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (user_id, business_name, description, refund_policy, logo, banner, pgp_public_key, shipping_methods, vacation_mode, notify_orders, notify_messages, notify_disputes, btc_address, xmr_address))
            conn.commit()
            flash('Settings saved.', 'success')
            # Refresh vendor dict
            c.execute("""
                SELECT business_name, description, logo, banner, pgp_public_key, bond_status, verification_status, shipping_methods, vacation_mode, notify_orders, notify_messages, notify_disputes, btc_address, xmr_address, refund_policy
                FROM vendor_settings WHERE user_id = ?
            """, (user_id,))
            vendor = dict(c.fetchone())
        settings = get_settings()
        return render_template('user/vendor_settings.html', vendor=vendor, settings=settings)