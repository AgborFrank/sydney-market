from flask import Blueprint, render_template, request, session, redirect, url_for, flash
from utils.database import get_db_connection, get_product_count, get_featured_products, get_random_products, get_settings
#from utils.security import validate_csrf_token
from datetime import datetime, timedelta
from utils.bitcoin import check_payment, send_btc, ESCROW_KEY, generate_btc_address
from flask_login import login_required, current_user, login_user
#from utils.monero import send_monero
from utils.database import get_user_profile_data
from utils.crypto import get_exchange_rates
import traceback
import logging
from pytz import timezone
import json
from utils.monero import generate_monero_address
from utils.database import send_notification_with_email
from flask_wtf.csrf import generate_csrf
from config import Config

public_bp = Blueprint('public', __name__, url_prefix='')
logger = logging.getLogger(__name__)

@public_bp.context_processor
def inject_csrf_token():
    return {'csrf_token': generate_csrf}

def get_product_rating(product_id, cursor):
    """Fetch average rating and review count for a product."""
    cursor.execute("""
        SELECT AVG(rating) as avg_rating, COUNT(*) as review_count 
        FROM reviews 
        WHERE product_id = ?
    """, (product_id,))
    result = cursor.fetchone()
    return {'avg_rating': round(result['avg_rating'] or 0, 1), 'review_count': result['review_count']}

@public_bp.route('/')
@login_required
def index():
    # Fetch featured and random products
    featured_products = get_featured_products(limit=6)
    random_products = get_random_products(limit=6)

    logger.info(f"Index route: {len(featured_products)} featured, {len(random_products)} random products")

    # Add favorite status to products
    user_id = session['user_id']
    with get_db_connection() as conn:
        c = conn.cursor()
        for product in featured_products + random_products:
            c.execute("SELECT id FROM favorites WHERE user_id = ? AND product_id = ?", (user_id, product['id']))
            product['is_favorited'] = c.fetchone() is not None

    # Fetch user profile data
    profile_data, error = get_user_profile_data(session['user_id'])
    if error:
        flash(error, 'error')

    # Exchange rates
    rates = get_exchange_rates()
    if not rates:
        flash("Unable to fetch exchange rates.", 'error')
        rates = {"bitcoin": {}, "monero": {}}

    return render_template('index.html',
                         featured_products=featured_products,
                         random_products=random_products,
                         profile_data=profile_data,
                         rates=rates)
@public_bp.route('/product/<int:product_id>')
@login_required
def product_detail(product_id):
    db = get_db_connection()

    # Fetch product details
    product = db.execute(
        "SELECT p.*, u.pusername as vendor_username, c.name as category_name "
        "FROM products p "
        "LEFT JOIN users u ON p.vendor_id = u.id "
        "LEFT JOIN categories c ON p.category_id = c.id "
        "WHERE p.id = ?",
        (product_id,)
    ).fetchone()

    if not product:
        db.close()
        return render_template('error.html', message="Product not found"), 404

    # Convert product to dict
    product_dict = dict(product)
    rates = get_exchange_rates() 
    price_usd = product_dict.get('price_usd', 0.0)

    btc_usd_rate = rates.get('BTC/USD', {}).get('rate', 0)
    xmr_usd_rate = rates.get('XMR/USD', {}).get('rate', 0)

    product_dict['dynamic_price_btc'] = (price_usd / btc_usd_rate) if btc_usd_rate > 0 else 0
    product_dict['dynamic_price_xmr'] = (price_usd / xmr_usd_rate) if xmr_usd_rate > 0 else 0
    # Fetch product images
    images = db.execute(
        "SELECT image_path FROM product_images WHERE product_id = ? ORDER BY created_at DESC",
        (product_id,)
    ).fetchall()
    product_dict['images'] = [img['image_path'] for img in images] if images else []
   
    # Fetch reviews for rating
    reviews = db.execute(
        "SELECT rating FROM reviews WHERE product_id = ?",
        (product_id,)
    ).fetchall()
    product_rating = sum(r['rating'] for r in reviews) / len(reviews) if reviews else 0.0
    product_dict['rating'] = product_rating
    product_dict['reviews_count'] = len(reviews)

    # Fetch sales count for the product
    product_sales_count = db.execute(
        "SELECT COUNT(*) as count FROM orders WHERE product_id = ? AND status = 'completed'",
        (product_id,)
    ).fetchone()['count']
    product_dict['sales_count'] = product_sales_count

    # Convert created_at to datetime and adjust to WAT
    try:
        product_dict['created_at'] = datetime.strptime(product_dict['created_at'], '%Y-%m-%d %H:%M:%S')
        product_dict['created_at'] = product_dict['created_at'].replace(tzinfo=timezone('UTC')).astimezone(timezone('Africa/Lagos'))
    except ValueError as e:
        logger.error(f"Failed to parse created_at: {e}")
        product_dict['created_at'] = datetime.now(tz=timezone('Africa/Lagos'))

    # Fetch vendor details
    vendor = db.execute(
        "SELECT id, pusername as username, last_login, level, avatar "
        "FROM users WHERE id = ?",
        (product_dict['vendor_id'],)
    ).fetchone()

    if not vendor:
        db.close()
        return render_template('error.html', message="Vendor not found"), 404

    # Convert vendor to dict for easier manipulation
    vendor_dict = dict(vendor)

    # Fetch vendor PGP key from vendor_settings
    vendor_settings = db.execute("SELECT pgp_key FROM vendor_settings WHERE user_id = ?", (product_dict['vendor_id'],)).fetchone()
    vendor_dict['pgp_public_key'] = vendor_settings['pgp_key'] if vendor_settings and vendor_settings['pgp_key'] else None

    # Avatar URL logic
    if vendor_dict.get('avatar'):
        vendor_dict['avatar_url'] = url_for('static', filename=f"uploads/avatar/{vendor_dict['avatar']}")
    else:
        vendor_dict['avatar_url'] = url_for('static', filename='avatars/default.png')

    # PGP fingerprint logic
    vendor_dict['pgp_fingerprint'] = None
    if vendor_dict.get('pgp_public_key'):
        try:
            from utils.pgp_utils import pgp_utils
            vendor_dict['pgp_fingerprint'] = pgp_utils.get_key_fingerprint(vendor_dict['pgp_public_key'])
        except Exception as e:
            logger.error(f"Failed to parse PGP key for vendor {vendor_dict['id']}: {e}")
            vendor_dict['pgp_fingerprint'] = None

    # Fetch sales count for the vendor from completed orders
    vendor_sales_count = db.execute(
        "SELECT COUNT(*) as count FROM orders WHERE vendor_id = ? AND status = 'completed'",
        (product_dict['vendor_id'],)
    ).fetchone()['count']
    vendor_dict['sales_count'] = vendor_sales_count

    # Fetch all reviews for the vendor's products to calculate feedback_positive_percentage
    vendor_reviews = db.execute(
        "SELECT r.rating "
        "FROM reviews r "
        "JOIN products p ON r.product_id = p.id "
        "WHERE p.vendor_id = ?",
        (product_dict['vendor_id'],)
    ).fetchall()

    # Calculate feedback_positive_percentage
    if vendor_reviews:
        positive_reviews = sum(1 for r in vendor_reviews if r['rating'] >= 4)
        total_reviews = len(vendor_reviews)
        vendor_dict['feedback_positive_percentage'] = (positive_reviews / total_reviews) * 100
    else:
        vendor_dict['feedback_positive_percentage'] = 0.0

    # Calculate trust_level based on sales and feedback
    base_trust_level = 1  # Starting level
    trust_level = base_trust_level
    trust_level += vendor_sales_count // 100  # Add 1 level for every 100 sales
    if vendor_dict['feedback_positive_percentage'] > 95:
        trust_level += 1
    vendor_dict['trust_level'] = min(trust_level, 10)  # Cap at 10

    # Mock external marketplace fields (since they're not in the database)
    vendor_dict['external_market_count'] = 0  # No external marketplace data
    vendor_dict['external_sales_count'] = 0
    vendor_dict['external_feedback_percentage'] = 0.0

    # Convert last_login to datetime and adjust to WAT
    if vendor_dict['last_login'] is not None:
        try:
            vendor_dict['last_login'] = datetime.strptime(vendor_dict['last_login'], '%Y-%m-%d %H:%M:%S')
            vendor_dict['last_login'] = vendor_dict['last_login'].replace(tzinfo=timezone('UTC')).astimezone(timezone('Africa/Lagos'))
        except ValueError as e:
            logger.error(f"Failed to parse vendor last_login: {e}")
            vendor_dict['last_login'] = datetime.now(tz=timezone('Africa/Lagos'))
    else:
        logger.warning(f"last_login is None for vendor {vendor_dict['id']}")
        vendor_dict['last_login'] = datetime.now(tz=timezone('Africa/Lagos'))

    # Fetch detailed feedback with pagination
    page = request.args.get('pg', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page

    feedback = db.execute(
        "SELECT r.rating, r.comment, r.created_at, u.pusername as buyer_username "
        "FROM reviews r "
        "LEFT JOIN users u ON r.user_id = u.id "
        "WHERE r.product_id = ? "
        "ORDER BY r.created_at DESC "
        "LIMIT ? OFFSET ?",
        (product_id, per_page, offset)
    ).fetchall()

    # Calculate feedback stats
    feedback_stats = db.execute(
        "SELECT "
        "SUM(CASE WHEN rating >= 4 THEN 1 ELSE 0 END) as positive, "
        "SUM(CASE WHEN rating = 3 THEN 1 ELSE 0 END) as neutral, "
        "SUM(CASE WHEN rating < 3 THEN 1 ELSE 0 END) as negative "
        "FROM reviews WHERE product_id = ?",
        (product_id,)
    ).fetchone()

    feedback_stats = {
        'positive': feedback_stats['positive'] or 0,
        'neutral': feedback_stats['neutral'] or 0,
        'negative': feedback_stats['negative'] or 0,
        'total': len(reviews),
        'positive_percentage': (feedback_stats['positive'] / len(reviews) * 100) if reviews else 0.0
    }
    # Check if product is favorited by current user
    product_favorite_status = db.execute(
        "SELECT id FROM favorites WHERE user_id = ? AND product_id = ?",
        (session['user_id'], product_id)
    ).fetchone() is not None
    product_dict['is_favorited'] = product_favorite_status
    
    # Check if vendor is favorited by current user
    vendor_favorite_status = db.execute(
        "SELECT id FROM favorite_vendors WHERE user_id = ? AND vendor_id = ?",
        (session['user_id'], product_dict['vendor_id'])
    ).fetchone() is not None
    # Convert feedback to list of dicts and parse created_at to WAT
    feedback_list = []
    for f in feedback:
        f_dict = dict(f)
        try:
            f_dict['created_at'] = datetime.strptime(f_dict['created_at'], '%Y-%m-%d %H:%M:%S')
            f_dict['created_at'] = f_dict['created_at'].replace(tzinfo=timezone('UTC')).astimezone(timezone('Africa/Lagos'))
        except ValueError:
            f_dict['created_at'] = datetime.now(tz=timezone('Africa/Lagos'))
        feedback_list.append(f_dict)

    # Calculate pagination
    total_pages = (len(reviews) + per_page - 1) // per_page

    # Fetch user profile data
    profile_data, error = get_user_profile_data(session['user_id'])
    if not profile_data:
        db.close()
        return render_template('error.html', message="User not found"), 404

    # Fetch vendor refund policy from vendor_settings
    vendor_settings = db.execute("SELECT return_policy FROM vendor_settings WHERE user_id = ?", (product_dict['vendor_id'],)).fetchone()
    vendor_refund_policy = vendor_settings['return_policy'] if vendor_settings and vendor_settings['return_policy'] else None

    # Fetch similar products by the same vendor (excluding this product)
    similar_products = db.execute(
        "SELECT p.*, u.pusername as vendor_username, c.name as category_name FROM products p "
        "LEFT JOIN users u ON p.vendor_id = u.id "
        "LEFT JOIN categories c ON p.category_id = c.id "
        "WHERE p.vendor_id = ? AND p.id != ? AND p.status = 'active' "
        "ORDER BY p.created_at DESC LIMIT 6",
        (product_dict['vendor_id'], product_id)
    ).fetchall()
    similar_products = [dict(row) for row in similar_products] if similar_products else []

    db.close()
    return render_template(
        'product_detail.html',
        product=product_dict,
        vendor=vendor_dict,
        feedback_list=feedback_list,
        feedback_stats=feedback_stats,
        total_pages=total_pages,
        page=page,
        profile_data=profile_data,
        vendor_refund_policy=vendor_refund_policy,
        vendor_favorite_status=vendor_favorite_status,
        similar_products=similar_products
    )


@public_bp.route('/vendor/<int:vendor_id>')
@login_required
def vendor_profile(vendor_id):
    db = get_db_connection()

    # Fetch vendor details
    vendor = db.execute(
        "SELECT id, pusername as username, last_login, level, avatar "
        "FROM users WHERE id = ?",
        (vendor_id,)
    ).fetchone()

    if not vendor:
        db.close()
        return render_template('error.html', message="Vendor not found"), 404

    # Convert vendor to dict for easier manipulation
    vendor_dict = dict(vendor)

    # Fetch vendor PGP key from vendor_settings
    vendor_settings = db.execute("SELECT pgp_key FROM vendor_settings WHERE user_id = ?", (vendor_id,)).fetchone()
    vendor_dict['pgp_public_key'] = vendor_settings['pgp_key'] if vendor_settings and vendor_settings['pgp_key'] else None

    # Avatar URL logic
    if vendor_dict.get('avatar'):
        vendor_dict['avatar_url'] = url_for('static', filename=f"uploads/avatar/{vendor_dict['avatar']}")
    else:
        vendor_dict['avatar_url'] = url_for('static', filename='avatars/default.png')

    # PGP fingerprint logic
    vendor_dict['pgp_fingerprint'] = None
    if vendor_dict.get('pgp_public_key'):
        try:
            from utils.pgp_utils import pgp_utils
            vendor_dict['pgp_fingerprint'] = pgp_utils.get_key_fingerprint(vendor_dict['pgp_public_key'])
        except Exception as e:
            logger.error(f"Failed to parse PGP key for vendor {vendor_dict['id']}: {e}")
            vendor_dict['pgp_fingerprint'] = None

    favorite_status = db.execute(
        "SELECT id FROM favorite_vendors WHERE user_id = ? AND vendor_id = ?",
        (session['user_id'], vendor_id)
    ).fetchone() is not None
    # Fetch sales count for the vendor from completed orders
    vendor_sales_count = db.execute(
        "SELECT COUNT(*) as count FROM orders WHERE vendor_id = ? AND status = 'completed'",
        (vendor_id,)
    ).fetchone()['count']
    vendor_dict['sales_count'] = vendor_sales_count

    # Fetch all reviews for the vendor's products to calculate feedback_positive_percentage
    vendor_reviews = db.execute(
        "SELECT r.rating "
        "FROM reviews r "
        "JOIN products p ON r.product_id = p.id "
        "WHERE p.vendor_id = ?",
        (vendor_id,)
    ).fetchall()

    # Calculate feedback_positive_percentage
    if vendor_reviews:
        positive_reviews = sum(1 for r in vendor_reviews if r['rating'] >= 4)
        total_reviews = len(vendor_reviews)
        vendor_dict['feedback_positive_percentage'] = (positive_reviews / total_reviews) * 100
    else:
        vendor_dict['feedback_positive_percentage'] = 0.0

    # Calculate trust_level based on sales and feedback
    base_trust_level = 1  # Starting level
    trust_level = base_trust_level
    trust_level += vendor_sales_count // 100  # Add 1 level for every 100 sales
    if vendor_dict['feedback_positive_percentage'] > 95:
        trust_level += 1
    vendor_dict['trust_level'] = min(trust_level, 10)  # Cap at 10

    # Mock external marketplace fields (since they're not in the database)
    vendor_dict['external_market_count'] = 0
    vendor_dict['external_sales_count'] = 0
    vendor_dict['external_feedback_percentage'] = 0.0

    # Convert last_login to datetime and adjust to WAT
    if vendor_dict['last_login'] is not None:
        try:
            vendor_dict['last_login'] = datetime.strptime(vendor_dict['last_login'], '%Y-%m-%d %H:%M:%S')
            vendor_dict['last_login'] = vendor_dict['last_login'].replace(tzinfo=timezone('UTC')).astimezone(timezone('Africa/Lagos'))
        except ValueError as e:
            logger.error(f"Failed to parse vendor last_login: {e}")
            vendor_dict['last_login'] = datetime.now(tz=timezone('Africa/Lagos'))
    else:
        logger.warning(f"last_login is None for vendor {vendor_dict['id']}")
        vendor_dict['last_login'] = datetime.now(tz=timezone('Africa/Lagos'))

    # Fetch all active products by the vendor
    products = db.execute(
        "SELECT p.*, "
        "(SELECT COUNT(*) FROM reviews r WHERE r.product_id = p.id) as reviews_count, "
        "(SELECT AVG(r.rating) FROM reviews r WHERE r.product_id = p.id) as avg_rating, "
        "c.name as category_name "
        "FROM products p "
        "LEFT JOIN categories c ON p.category_id = c.id "
        "WHERE p.vendor_id = ? AND p.status = 'active' "
        "ORDER BY p.created_at DESC",
        (vendor_id,)
    ).fetchall()

    # Convert products to list of dicts and process dates
    products_list = []
    for prod in products:
        prod_dict = dict(prod)
        # Convert created_at to datetime and adjust to WAT
        if prod_dict['created_at'] is not None:
            try:
                prod_dict['created_at'] = datetime.strptime(prod_dict['created_at'], '%Y-%m-%d %H:%M:%S')
                prod_dict['created_at'] = prod_dict['created_at'].replace(tzinfo=timezone('UTC')).astimezone(timezone('Africa/Lagos'))
            except ValueError as e:
                logger.error(f"Failed to parse product created_at: {e}")
                prod_dict['created_at'] = datetime.now(tz=timezone('Africa/Lagos'))
        else:
            prod_dict['created_at'] = datetime.now(tz=timezone('Africa/Lagos'))

        # Fetch product images (first image only for preview)
        first_image = db.execute(
            "SELECT image_path FROM product_images WHERE product_id = ? ORDER BY created_at ASC LIMIT 1",
            (prod_dict['id'],)
        ).fetchone()
        prod_dict['first_image'] = first_image['image_path'] if first_image else None

        products_list.append(prod_dict)

    # Fetch user profile data
    profile_data, error = get_user_profile_data(session['user_id'])
    if not profile_data:
        db.close()
        return render_template('error.html', message="User not found"), 404

    db.close()
    return render_template(
        'vendor_profile_full.html',
        vendor=vendor_dict,
        products=products_list,
        profile_data=profile_data,
        favorite_status=favorite_status
    )
@public_bp.route('/favorite_vendor/<int:vendor_id>', methods=['GET'])
@login_required
def favorite_vendor(vendor_id):
    db = get_db_connection()
    user_id = session['user_id']

    # Check if the vendor is already favorited
    existing_favorite = db.execute(
        "SELECT id FROM favorite_vendors WHERE user_id = ? AND vendor_id = ?",
        (user_id, vendor_id)
    ).fetchone()

    if existing_favorite:
        # Remove favorite
        db.execute(
            "DELETE FROM favorite_vendors WHERE user_id = ? AND vendor_id = ?",
            (user_id, vendor_id)
        )
        flash('Vendor removed from favorite_vendors.', 'success')
    else:
        # Add favorite
        db.execute(
            "INSERT INTO favorite_vendors (user_id, vendor_id) VALUES (?, ?)",
            (user_id, vendor_id)
        )
        flash('Vendor added to favorite_vendors.', 'success')

    db.commit()
    db.close()

    # Redirect back to the referring page (e.g., product detail or vendor profile)
    referer = request.headers.get('Referer')
    if referer:
        return redirect(referer)
    return redirect(url_for('public.index'))

@public_bp.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    db = get_db_connection()
    user = db.execute(
        "SELECT id, pusername, role, created_at, last_login, last_logout "
        "FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()
    
    if not user:
        return render_template('error.html', message="User not found"), 404
    
    products = db.execute(
        "SELECT * FROM products WHERE vendor_id = ? AND stock > 0",
        (user_id,)
    ).fetchall()
    
    return render_template('profile.html', user=user, products=products)
  
@public_bp.route('/category/<int:category_id>')
@login_required
def category_products(category_id):
    if 'user_id' not in session:
        flash('Please log in to access this category.', 'error')
        return redirect(url_for('user.login'))
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            # Fetch category details
            c.execute("SELECT * FROM categories WHERE id = ?", (category_id,))
            category = c.fetchone()
            if not category:
                flash("Category not found.", 'error')
                return redirect(url_for('public.index'))
            category = dict(category)
            
            # Fetch products in this category (including subcategories if desired)
            c.execute("""
                WITH RECURSIVE category_tree AS (
                    SELECT id FROM categories WHERE id = ?
                    UNION ALL
                    SELECT c.id FROM categories c
                    JOIN category_tree ct ON c.parent_id = ct.id
                )
                SELECT p.*, u.pusername as vendor_username, c.name as category_name,
                       vl.level as vendor_level, vl.sales_count, vl.positive_feedback_percentage
                FROM products p 
                LEFT JOIN users u ON p.vendor_id = u.id 
                LEFT JOIN categories c ON p.category_id = c.id
                LEFT JOIN vendor_levels vl ON p.vendor_id = vl.vendor_id
                WHERE p.category_id IN (SELECT id FROM category_tree) AND p.stock > 0
            """, (category_id,))
            products = [dict(row) for row in c.fetchall()]
            
            # Add favorite status to products
            user_id = session['user_id']
            for product in products:
                c.execute("SELECT id FROM favorites WHERE user_id = ? AND product_id = ?", (user_id, product['id']))
                product['is_favorited'] = c.fetchone() is not None
            
            # Fetch all categories for sidebar (optional, if you want to keep the sidebar)
            c.execute("SELECT * FROM categories")
            categories = [dict(row) for row in c.fetchall()]
            category_tree = {cat['id']: dict(cat, subcategories=[]) for cat in categories}
            for cat in categories:
                if cat['parent_id']:
                    category_tree[cat['parent_id']]['subcategories'].append(category_tree[cat['id']])
            top_level_categories = [cat for cat in category_tree.values() if not cat['parent_id']]
            
            for cat in top_level_categories:
                cat['product_count'] = get_product_count(cat['id'], category_tree, c)

    except Exception as e:
        flash(f"Error loading category: {str(e)}", 'error')
        return redirect(url_for('public.index'))

    return render_template('category.html', category=category, products=products, 
                         top_level_categories=top_level_categories, sponsored_products=[], settings=get_settings())

@public_bp.route('/advertise')
def advertise():
    if 'user_id' not in session:
        flash('Please log in to access the marketplace.', 'error')
        return redirect(url_for('user.login'))
    return render_template('advertise.html')

@public_bp.route('/faqs')
def faqs():
    if 'user_id' not in session:
        flash('Please log in to access the marketplace.', 'error')
        return redirect(url_for('user.login'))
    return render_template('faqs.html')
@public_bp.route('/escrow')
def escrow():
    if 'user_id' not in session:
        flash('Please log in to access the marketplace.', 'error')
        return redirect(url_for('user.login'))
    return render_template('escrow.html', title="Multisig Escrow - Sydney",
                          description="Learn how our multisig escrow system ensures secure transactions.")


@public_bp.route('/search')
def search_products():
    if 'user_id' not in session:
        flash('Please log in to access the marketplace.', 'error')
        return redirect(url_for('user.login'))
    
    try:
        query = request.args.get('q', '').strip()
        # Handle both category_id and fcats[] parameters
        category_id = request.args.get('category_id', type=int)
        if category_id is None:
            fcats = request.args.getlist('fcats[]')
            if fcats:
                try:
                    category_id = int(fcats[0])  # Use the first category if multiple are selected
                except (ValueError, IndexError):
                    category_id = None
        
        min_price = request.args.get('min_price', type=float)
        max_price = request.args.get('max_price', type=float)
        min_rating = request.args.get('min_rating', type=float)
        sort_by = request.args.get('sort_by', 'relevance')
    
        with get_db_connection() as conn:
            c = conn.cursor()
            sql = """
                SELECT p.*, AVG(r.rating) as avg_rating,
                       vl.level as vendor_level,
                       vl.positive_feedback_percentage as vendor_positive_feedback_percentage,
                       vl.sales_count as vendor_sales_count,
                       c.name as category_name,
                       u.pusername as vendor_username
                FROM products p
                LEFT JOIN reviews r ON p.id = r.product_id
                LEFT JOIN vendor_levels vl ON p.vendor_id = vl.vendor_id
                LEFT JOIN categories c ON p.category_id = c.id
                LEFT JOIN users u ON p.vendor_id = u.id
                WHERE p.stock > 0
            """
            params = []
            
            if query:
                sql += " AND (p.title LIKE ? OR p.description LIKE ?)"
                params.extend([f"%{query}%", f"%{query}%"])
            
            if category_id:
                sql += " AND p.category_id = ?"
                params.append(category_id)
            
            if min_price is not None:
                sql += " AND p.price_usd >= ?"
                params.append(min_price)
            
            if max_price is not None:
                sql += " AND p.price_usd <= ?"
                params.append(max_price)
            
            if min_rating is not None:
                sql += " AND (AVG(r.rating) >= ? OR AVG(r.rating) IS NULL)"
                params.append(min_rating)
            
            sql += " GROUP BY p.id"
            
            if sort_by == 'price_asc':
                sql += " ORDER BY p.price_usd ASC"
            elif sort_by == 'price_desc':
                sql += " ORDER BY p.price_usd DESC"
            elif sort_by == 'rating_desc':
                sql += " ORDER BY avg_rating DESC NULLS LAST"
            else:
                sql += " ORDER BY p.created_at DESC"
            
            c.execute(sql, params)
            products = [dict(row) for row in c.fetchall()]
            
            # Add favorite status for each product
            user_id = session['user_id']
            for product in products:
                # Check if product is favorited
                c.execute("SELECT id FROM favorites WHERE user_id = ? AND product_id = ?", (user_id, product['id']))
                product['is_favorited'] = c.fetchone() is not None
                
                # Ensure price_usd is not None
                if product.get('price_usd') is None:
                    product['price_usd'] = 0.0
        
        rates_flat = get_exchange_rates()
        # Convert to nested dict for template compatibility
        rates = {
            'bitcoin': {'usd': rates_flat.get('BTC/USD', {}).get('rate', 0)},
            'monero': {'usd': rates_flat.get('XMR/USD', {}).get('rate', 0)}
        }
        return render_template('search_results.html', products=products, query=query, filters=request.args, rates=rates)
    except Exception as e:
        logger.error(f"Search error: {str(e)}")
        flash("An error occurred while searching. Please try again.", 'error')
        return render_template('search_results.html', products=[], query=query, filters=request.args, rates={})

@public_bp.route('/privacy-policy')
def privacy_policy():
    if 'user_id' not in session:
        flash('Please log in to access the marketplace.', 'error')
        return redirect(url_for('user.login'))
    return render_template('privacy_policy.html')

@public_bp.route('/marketplace-rules')
def marketplace_rules():
    if 'user_id' not in session:
        flash('Please log in to access the marketplace.', 'error')
        return redirect(url_for('user.login'))
    dated = datetime.now() - timedelta(days=15)
    return render_template('marketplace_rules.html', dated=dated)

@public_bp.route('/shipping-policy')
def shipping_policy():
    return render_template('shipping_policy.html')

@public_bp.route('/how-to-pay')
def how_to_pay():
    return render_template('how_to_pay.html')

@public_bp.route('/place_order/<int:product_id>', methods=['GET', 'POST'])
def place_order(product_id):
    if 'user_id' not in session:
        flash("Please log in to place an order.", 'error')
        return redirect(url_for('user.login'))
    
    from utils.bitcoin import generate_btc_address
    from utils.monero import generate_monero_address
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM products WHERE id = ?", (product_id,))
            product = c.fetchone()
            if not product or product['stock'] <= 0:
                flash("Product not available.", 'error')
                return redirect(url_for('public.product_detail', product_id=product_id))
            product = dict(product)

        # Prevent vendor from ordering their own product
        if session['user_id'] == product['vendor_id']:
            flash("Vendors cannot place orders for their own products.", 'error')
            return redirect(url_for('public.product_detail', product_id=product_id))
        
        # Allow vendors to order from other vendors (this is normal marketplace behavior)
        # The restriction above only prevents self-ordering
        
        # Debug logging
        logger.info(f"User {session['user_id']} attempting to order product {product_id} from vendor {product['vendor_id']}")
        logger.info(f"User role: {session.get('role', 'unknown')}")
        logger.info(f"Request method: {request.method}")
        logger.info(f"Request args: {dict(request.args)}")
        logger.info(f"Request form: {dict(request.form)}")

        # Check cryptocurrency availability
        btc_available = True
        monero_available = True
        
        try:
            # Test BTC address generation
            test_btc_address = generate_btc_address(session['user_id'])
            btc_available = test_btc_address is not None
        except Exception as e:
            logger.warning(f"BTC address generation failed: {str(e)}")
            btc_available = False
        
        try:
            # Test Monero address generation
            test_monero_address = generate_monero_address(session['user_id'])
            monero_available = test_monero_address is not None
        except Exception as e:
            logger.warning(f"Monero address generation failed: {str(e)}")
            monero_available = False

        if request.method == 'POST':
            quantity = int(request.form.get('quantity', 1))
            currency = request.form.get('currency', 'BTC')
            
            if quantity < 1 or quantity > product['stock']:
                flash("Invalid quantity.", 'error')
                return redirect(url_for('public.product_detail', product_id=product_id))
            
            # Validate currency availability
            if currency == 'BTC' and not btc_available:
                flash("Bitcoin payments are currently unavailable. Please try again later or contact support.", 'error')
                return redirect(url_for('public.product_detail', product_id=product_id))
            elif currency == 'XMR' and not monero_available:
                flash("Monero payments are currently unavailable. Please try again later or contact support.", 'error')
                return redirect(url_for('public.product_detail', product_id=product_id))
            
            # Calculate price
            settings = get_settings()
            escrow_fee_percent = float(settings.get('escrow_fee_percent', 2.5))
            price_usd = product['price_usd'] * quantity
            logger.info(f"Price calculation: product_price={product['price_usd']}, quantity={quantity}, total_price_usd={price_usd}")
            
            # Get exchange rates
            try:
                rates = get_exchange_rates()
                logger.info(f"Exchange rates: {rates}")
                if not rates:
                    logger.error("No exchange rates returned")
                    flash("Unable to fetch exchange rates. Please try again later.", 'error')
                    return redirect(url_for('public.product_detail', product_id=product_id))
                
                btc_usd_rate = rates.get('BTC/USD', {}).get('rate', 0)
                xmr_usd_rate = rates.get('XMR/USD', {}).get('rate', 0)
                logger.info(f"Rates: BTC={btc_usd_rate}, XMR={xmr_usd_rate}")
                
                if btc_usd_rate <= 0 or xmr_usd_rate <= 0:
                    logger.error(f"Invalid exchange rates: BTC={btc_usd_rate}, XMR={xmr_usd_rate}")
                    flash("Exchange rates are currently unavailable. Please try again later.", 'error')
                    return redirect(url_for('public.product_detail', product_id=product_id))
                
                amount_btc = price_usd / btc_usd_rate
                amount_xmr = price_usd / xmr_usd_rate
                logger.info(f"Calculated amounts: BTC={amount_btc}, XMR={amount_xmr}")
            except Exception as e:
                logger.error(f"Error fetching exchange rates: {str(e)}")
                logger.error(f"Exception type: {type(e).__name__}")
                flash("Unable to calculate cryptocurrency amounts. Please try again later.", 'error')
                return redirect(url_for('public.product_detail', product_id=product_id))
            
            # Generate payment address
            payment_address = None
            try:
                logger.info(f"Generating {currency} address for user {session['user_id']}")
                if currency == 'BTC':
                    payment_address = generate_btc_address(session['user_id'])
                    logger.info(f"Generated BTC address: {payment_address}")
                elif currency == 'XMR':
                    payment_address = generate_monero_address(session['user_id'])
                    logger.info(f"Generated XMR address: {payment_address}")
                
                if not payment_address:
                    logger.error(f"Failed to generate {currency} address for user {session['user_id']}")
                    flash(f"Unable to generate {currency} payment address. Please try again later.", 'error')
                    return redirect(url_for('public.product_detail', product_id=product_id))
            except Exception as e:
                logger.error(f"Error generating {currency} address: {str(e)}")
                logger.error(f"Exception type: {type(e).__name__}")
                flash(f"Unable to generate {currency} payment address. Please try again later.", 'error')
                return redirect(url_for('public.product_detail', product_id=product_id))
            
            # Create order and escrow records
            try:
                logger.info(f"Creating order for user {session['user_id']}, product {product_id}, vendor {product['vendor_id']}")
                logger.info(f"Order details: quantity={quantity}, currency={currency}, price_usd={price_usd}")
                logger.info(f"Amounts: BTC={amount_btc}, XMR={amount_xmr}")
                
                with get_db_connection() as conn:
                    c = conn.cursor()
                    # For orders table, we store the amount in the selected currency
                    # If BTC, store in amount_btc, if XMR, we'll store 0 in amount_btc and the XMR amount in escrow table
                    order_amount_btc = amount_btc if currency == 'BTC' else 0
                    
                    c.execute("""
                        INSERT INTO orders (user_id, product_id, vendor_id, amount_usd, amount_btc, status, escrow_status, crypto_currency, item_count, created_at)
                        VALUES (?, ?, ?, ?, ?, 'pending', 'pending', ?, ?, datetime('now'))
                    """, (session['user_id'], product_id, product['vendor_id'], price_usd, order_amount_btc, currency, quantity))
                    order_id = c.lastrowid
                    
                    # Generate addresses for escrow - per-order payment destination
                    buyer_address = payment_address
                    
                    # For vendor address, try to generate one, but fall back to None (no admin direct payments)
                    try:
                        vendor_address = generate_btc_address(product['vendor_id']) if currency == 'BTC' else generate_monero_address(product['vendor_id'])
                        logger.info(f"Generated vendor {currency} address: {vendor_address}")
                    except Exception as e:
                        logger.warning(f"Failed to generate vendor {currency} address: {str(e)}")
                        vendor_address = None
                    
                    # Create the actual escrow deposit address for this order
                    escrow_address = None
                    multisig_or_deposit_address = None
                    if currency == 'BTC':
                        from utils.bitcoin import generate_btc_escrow_address
                        multisig_or_deposit_address = generate_btc_escrow_address(order_id)
                        escrow_address = multisig_or_deposit_address
                    else:
                        # For XMR, use buyer payment subaddress as deposit address (RPC wallet will segregate funds)
                        multisig_or_deposit_address = buyer_address
                        escrow_address = buyer_address
                    
                    c.execute("""
                        INSERT INTO escrow (order_id, multisig_address, buyer_address, vendor_address, escrow_address, amount_usd, amount_btc, amount_xmr, crypto_currency, status, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', datetime('now'))
                    """, (order_id, multisig_or_deposit_address, buyer_address, vendor_address or '', escrow_address, price_usd, amount_btc, amount_xmr, currency))
                    conn.commit()
                
                logger.info(f"Order created successfully! Order ID: {order_id}")
                flash("Order created successfully! Please proceed to payment.", 'success')
                return redirect(url_for('public.order_payment', order_id=order_id))
                
            except Exception as e:
                logger.error(f"Error creating order: {str(e)}")
                logger.error(f"Exception type: {type(e).__name__}")
                logger.error(f"Exception details: {e}")
                flash("An error occurred while creating the order. Please try again.", 'error')
                return redirect(url_for('public.product_detail', product_id=product_id))
        
        # GET: Show order form with pre-filled values from query parameters
        quantity = request.args.get('quantity', 1, type=int)
        currency = request.args.get('currency', 'BTC')
        
        # Validate quantity
        if quantity < 1 or quantity > product['stock']:
            quantity = 1
        
        # Validate currency
        if currency not in ['BTC', 'XMR']:
            currency = 'BTC'
        
        return render_template('order.html', 
                             product=product, 
                             btc_available=btc_available,
                             monero_available=monero_available,
                             pre_filled_quantity=quantity,
                             pre_filled_currency=currency)
                             
    except Exception as e:
        logger.error(f"Error in place_order: {str(e)}")
        flash("An error occurred while processing your request. Please try again later.", 'error')
        return redirect(url_for('public.product_detail', product_id=product_id))

# Add order_payment route for order confirmation/payment instructions
@public_bp.route('/order/payment/<int:order_id>')
def order_payment(order_id):
    if 'user_id' not in session:
        flash("Please log in to view your order.", 'error')
        return redirect(url_for('user.login'))
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT o.*, e.multisig_address, e.escrow_address, e.amount_btc, e.amount_xmr, e.crypto_currency as escrow_crypto_currency FROM orders o JOIN escrow e ON o.id = e.order_id WHERE o.id = ? AND o.user_id = ?", (order_id, session['user_id']))
            order = c.fetchone()
            if not order:
                flash("Order not found.", 'error')
                return redirect(url_for('user.orders'))
            product = c.execute("SELECT * FROM products WHERE id = ?", (order['product_id'],)).fetchone()
        logger.info(f"Rendering order_payment template for order {order_id}")
        logger.info(f"Order data: {dict(order) if order else 'None'}")
        logger.info(f"Product data: {dict(product) if product else 'None'}")
        return render_template('order_payment.html', order=order, product=product)
    except Exception as e:
        print(f"Error in order_payment: {str(e)}")
        flash("An error occurred while loading the order.", 'error')
        return redirect(url_for('user.orders'))

@public_bp.route('/review_product/<int:product_id>', methods=['GET', 'POST'])
def review_product(product_id):
    if 'user_id' not in session:
        flash("Please log in to write a review.", 'error')
        return redirect(url_for('user.login'))
    
    if request.method == 'POST':
        rating = request.form.get('rating', type=int)
        comment = request.form.get('comment', '').strip()
        if not rating or rating < 1 or rating > 5:
            flash("Please provide a valid rating (1-5).", 'error')
        else:
            try:
                with get_db_connection() as conn:
                    c = conn.cursor()
                    
                    # Get vendor_id for this product
                    c.execute("SELECT vendor_id FROM products WHERE id = ?", (product_id,))
                    product = c.fetchone()
                    if not product:
                        flash("Product not found.", 'error')
                        return redirect(url_for('public.index'))
                    
                    vendor_id = product['vendor_id']
                    
                    # Insert review
                    c.execute("""
                        INSERT INTO reviews (product_id, user_id, rating, comment, created_at)
                        VALUES (?, ?, ?, ?, datetime('now'))
                    """, (product_id, session['user_id'], rating, comment))
                    
                    # Also insert vendor rating
                    c.execute("""
                        INSERT INTO vendor_ratings (vendor_id, order_id, rating, comment, created_at)
                        VALUES (?, ?, ?, ?, datetime('now'))
                    """, (vendor_id, 0, rating, comment))  # order_id set to 0 for now
                    
                    conn.commit()
                    
                    # Update vendor metrics
                    from routes.admin import recalculate_vendor_metrics
                    recalculate_vendor_metrics(vendor_id)
                    
                flash("Review submitted successfully!", 'success')
                return redirect(url_for('public.product_detail', product_id=product_id))
            except Exception as e:
                print(f"Error in review_product: {str(e)}")
                flash("An error occurred while submitting your review.", 'error')
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT title FROM products WHERE id = ?", (product_id,))
            product = c.fetchone()
            if not product:
                flash("Product not found.", 'error')
                return redirect(url_for('public.index'))
        return render_template('review_product.html', product_id=product_id, product_title=product['title'])
    except Exception as e:
        print(f"Error in review_product: {str(e)}")
        flash("An error occurred.", 'error')
        return redirect(url_for('public.product_detail', product_id=product_id))

@public_bp.route('/report_vendor/<int:vendor_id>', methods=['GET', 'POST'])
def report_vendor(vendor_id):
    if 'user_id' not in session:
        flash("Please log in to report a vendor.", 'error')
        return redirect(url_for('user.login'))
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT id, pusername as username, avatar FROM users WHERE id = ? AND role = 'vendor'", (vendor_id,))
            vendor = c.fetchone()
            if not vendor:
                flash("Vendor not found.", 'error')
                return redirect(url_for('public.index'))
            
            vendor = dict(vendor)
            
            # Add avatar URL
            if vendor.get('avatar'):
                vendor['avatar_url'] = url_for('static', filename=f"uploads/avatar/{vendor['avatar']}")
            else:
                vendor['avatar_url'] = url_for('static', filename='avatars/default.png')
        
        if request.method == 'POST':
            reason = request.form.get('reason', '').strip()
            evidence = request.form.get('evidence', '').strip()
            
            if not reason:
                flash("Reason is required.", 'error')
                return render_template('user/report_vendor.html', vendor=vendor)
            
            # Insert report into database
            c.execute("""
                INSERT INTO reports (user_id, vendor_id, vendor_username, reason, evidence, status)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (session['user_id'], vendor_id, vendor['username'], reason, evidence, 'pending'))
            conn.commit()
            
            flash("Vendor reported successfully. Our team will review your report.", 'success')
            return redirect(url_for('public.vendor_shop', vendor_id=vendor_id))
        
        return render_template('user/report_vendor.html', vendor=vendor)
        
    except Exception as e:
        logger.error(f"Error in report_vendor: {str(e)}")
        flash("An error occurred while reporting the vendor.", 'error')
        return redirect(url_for('public.index'))

@public_bp.route('/report_vendor', methods=['GET', 'POST'])
def old_report_vendor():
    if 'user_id' not in session:
        flash("Please log in to report a vendor.", 'error')
        return redirect(url_for('user.login'))
    
    if request.method == 'POST':
       # validate_csrf_token()
        vendor_username = request.form.get('vendor_username', '').strip()
        reason = request.form.get('reason', '').strip()
        evidence = request.form.get('evidence', '').strip()
        
        if not vendor_username or not reason:
            flash("Vendor username and reason are required.", 'error')
            return render_template('user/report_vendor.html')
        
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT id FROM vendors WHERE username = ?", (vendor_username,))
            vendor = c.fetchone()
            if not vendor:
                flash("Vendor not found.", 'error')
                return render_template('user/report_vendor.html')
            
            c.execute("""
                INSERT INTO reports (user_id, vendor_id, vendor_username, reason, evidence)
                VALUES (?, ?, ?, ?, ?)
            """, (session['user_id'], vendor['id'], vendor_username, reason, evidence))
            conn.commit()
        
        flash("Vendor reported successfully.", 'success')
        return redirect(url_for('public.report_vendor'))
    
    return render_template('user/report_vendor.html')

@public_bp.route('/how-to-sell')
def how_to_sell():
    if 'user_id' not in session:
        flash('Please log in to access the marketplace.', 'error')
        return redirect(url_for('user.login'))
    dated = datetime.now() - timedelta(days=15)
    
    return render_template('how_to_sell.html', dated=dated)

@public_bp.route('/how-to-pgp')
def how_to_pgp():
    if 'user_id' not in session:
        flash('Please log in to access the marketplace.', 'error')
        return redirect(url_for('user.login'))
    return render_template('how_to_pgp.html')

@public_bp.route('/reload-balance')
def reload_balance():
    return render_template('reload_balance.html')

@public_bp.route('/vendor-shop/<int:vendor_id>')
@login_required
def vendor_shop(vendor_id):
    db = get_db_connection()

    # Fetch vendor details
    vendor = db.execute(
        "SELECT id, pusername as username, last_login, level, avatar "
        "FROM users WHERE id = ? AND role = 'vendor'",
        (vendor_id,)
    ).fetchone()

    if not vendor:
        db.close()
        return render_template('error.html', message="Vendor not found"), 404

    # Convert vendor to dict for easier manipulation
    vendor_dict = dict(vendor)

    # Fetch vendor PGP key from vendor_settings
    vendor_settings = db.execute("SELECT pgp_key FROM vendor_settings WHERE user_id = ?", (vendor_id,)).fetchone()
    vendor_dict['pgp_public_key'] = vendor_settings['pgp_key'] if vendor_settings and vendor_settings['pgp_key'] else None

    # Avatar URL logic
    if vendor_dict.get('avatar'):
        vendor_dict['avatar_url'] = url_for('static', filename=f"uploads/avatar/{vendor_dict['avatar']}")
    else:
        vendor_dict['avatar_url'] = url_for('static', filename='avatars/default.png')

    # PGP fingerprint logic
    vendor_dict['pgp_fingerprint'] = None
    if vendor_dict.get('pgp_public_key'):
        try:
            from utils.pgp_utils import pgp_utils
            vendor_dict['pgp_fingerprint'] = pgp_utils.get_key_fingerprint(vendor_dict['pgp_public_key'])
        except Exception as e:
            logger.error(f"Failed to parse PGP key for vendor {vendor_dict['id']}: {e}")
            vendor_dict['pgp_fingerprint'] = None

    # Check if vendor is favorited by current user
    favorite_status = db.execute(
        "SELECT id FROM favorite_vendors WHERE user_id = ? AND vendor_id = ?",
        (session['user_id'], vendor_id)
    ).fetchone() is not None

    # Fetch sales count for the vendor from completed orders
    vendor_sales_count = db.execute(
        "SELECT COUNT(*) as count FROM orders WHERE vendor_id = ? AND status = 'completed'",
        (vendor_id,)
    ).fetchone()['count']
    vendor_dict['sales_count'] = vendor_sales_count

    # Fetch all reviews for the vendor's products to calculate feedback_positive_percentage
    vendor_reviews = db.execute(
        "SELECT r.rating "
        "FROM reviews r "
        "JOIN products p ON r.product_id = p.id "
        "WHERE p.vendor_id = ?",
        (vendor_id,)
    ).fetchall()

    # Calculate feedback_positive_percentage
    if vendor_reviews:
        positive_reviews = sum(1 for r in vendor_reviews if r['rating'] >= 4)
        total_reviews = len(vendor_reviews)
        vendor_dict['feedback_positive_percentage'] = (positive_reviews / total_reviews) * 100
    else:
        vendor_dict['feedback_positive_percentage'] = 0.0

    # Calculate trust_level based on sales and feedback
    base_trust_level = 1  # Starting level
    trust_level = base_trust_level
    trust_level += vendor_sales_count // 100  # Add 1 level for every 100 sales
    if vendor_dict['feedback_positive_percentage'] > 95:
        trust_level += 1
    vendor_dict['trust_level'] = min(trust_level, 10)  # Cap at 10

    # Convert last_login to datetime and adjust to WAT
    if vendor_dict['last_login'] is not None:
        try:
            vendor_dict['last_login'] = datetime.strptime(vendor_dict['last_login'], '%Y-%m-%d %H:%M:%S')
            vendor_dict['last_login'] = vendor_dict['last_login'].replace(tzinfo=timezone('UTC')).astimezone(timezone('Africa/Lagos'))
        except ValueError as e:
            logger.error(f"Failed to parse vendor last_login: {e}")
            vendor_dict['last_login'] = datetime.now(tz=timezone('Africa/Lagos'))
    else:
        logger.warning(f"last_login is None for vendor {vendor_dict['id']}")
        vendor_dict['last_login'] = datetime.now(tz=timezone('Africa/Lagos'))

    # Fetch all active products by the vendor
    products = db.execute(
        "SELECT p.*, "
        "(SELECT COUNT(*) FROM reviews r WHERE r.product_id = p.id) as reviews_count, "
        "(SELECT AVG(r.rating) FROM reviews r WHERE r.product_id = p.id) as avg_rating, "
        "c.name as category_name "
        "FROM products p "
        "LEFT JOIN categories c ON p.category_id = c.id "
        "WHERE p.vendor_id = ? AND p.status = 'active' "
        "ORDER BY p.created_at DESC",
        (vendor_id,)
    ).fetchall()

    # Convert products to list of dicts and process dates
    products_list = []
    for prod in products:
        prod_dict = dict(prod)
        # Convert created_at to datetime and adjust to WAT
        if prod_dict['created_at'] is not None:
            try:
                prod_dict['created_at'] = datetime.strptime(prod_dict['created_at'], '%Y-%m-%d %H:%M:%S')
                prod_dict['created_at'] = prod_dict['created_at'].replace(tzinfo=timezone('UTC')).astimezone(timezone('Africa/Lagos'))
            except ValueError as e:
                logger.error(f"Failed to parse product created_at: {e}")
                prod_dict['created_at'] = datetime.now(tz=timezone('Africa/Lagos'))
        else:
            prod_dict['created_at'] = datetime.now(tz=timezone('Africa/Lagos'))

        # Use featured_image directly (no need for complex image processing)
        prod_dict['first_image'] = prod_dict.get('featured_image')

        # Check if product is favorited by current user
        product_favorite_status = db.execute(
            "SELECT id FROM favorites WHERE user_id = ? AND product_id = ?",
            (session['user_id'], prod_dict['id'])
        ).fetchone() is not None
        prod_dict['is_favorited'] = product_favorite_status

        products_list.append(prod_dict)

    db.close()
    return render_template(
        'vendor_shop.html',
        vendor=vendor_dict,
        products=products_list,
        favorite_status=favorite_status
    )


@public_bp.route('/test-tor')
def test_tor():
    """Test Tor detection and CSRF functionality."""
    from config import Config
    from flask_wtf.csrf import generate_csrf
    
    # Check if request is coming from Tor
    is_tor_request = request.headers.get('X-Forwarded-For', '').endswith('.onion') or \
                    request.headers.get('Host', '').endswith('.onion') or \
                    '.onion' in request.headers.get('Host', '')
    
    config = Config()
    
    return {
        'is_tor_request': is_tor_request,
        'headers': dict(request.headers),
        'host': request.headers.get('Host', ''),
        'x_forwarded_for': request.headers.get('X-Forwarded-For', ''),
        'csrf_token': generate_csrf(),
        'tor_csrf_disabled': config.TOR_CSRF_DISABLED,
        'tor_csrf_lenient': config.TOR_CSRF_LENIENT,
        'session_id': session.get('_id', 'No session ID')
    }

@public_bp.route('/test_csrf', methods=['GET', 'POST'])
def test_csrf():
    from config import Config
    from flask_wtf.csrf import generate_csrf, validate_csrf
    
    if request.method == 'POST':
        try:
            validate_csrf(request.form.get('csrf_token'))
            flash("CSRF token is working correctly!", 'success')
            return render_template('test_csrf.html', message="CSRF token validation successful!", config=Config)
        except Exception as e:
            flash(f"CSRF validation failed: {str(e)}", 'error')
            return render_template('test_csrf.html', error=f"CSRF validation failed: {str(e)}", config=Config)
    
    # Debug information
    debug_info = {
        'csrf_token': generate_csrf(),
        'session_id': session.get('_id', 'No session ID'),
        'secret_key_configured': bool(Config.SECRET_KEY),
        'csrf_enabled': True
    }
    
    return render_template('test_csrf.html', config=Config, debug_info=debug_info)

@public_bp.route('/order/confirm/<int:order_id>', methods=['POST'])
def confirm_order(order_id):
    if 'user_id' not in session:
        return redirect(url_for('user.login'))
    
    from utils.bitcoin import check_payment
    from utils.monero import check_monero_payment
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM orders WHERE id = ? AND user_id = ?", (order_id, session['user_id']))
            order = c.fetchone()
            if not order or order['escrow_status'] != 'pending':
                flash("Invalid order or order not in pending status", 'error')
                return redirect(url_for('user.orders'))
            
            c.execute("SELECT * FROM escrow WHERE order_id = ?", (order_id,))
            escrow = c.fetchone()
            if not escrow:
                flash("Escrow information not found", 'error')
                return redirect(url_for('user.orders'))
            
            txid = None
            try:
                if escrow['crypto_currency'] == 'BTC':
                    if not escrow['multisig_address']:
                        raise ValueError('Missing BTC escrow address for order')
                    txid = check_payment(escrow['multisig_address'], escrow['amount_btc'])
                elif escrow['crypto_currency'] == 'XMR':
                    if not escrow['multisig_address'] and not escrow['escrow_address']:
                        raise ValueError('Missing XMR escrow address for order')
                    # Prefer multisig_address field; fallback to escrow_address if needed
                    xmr_addr = escrow['multisig_address'] or escrow['escrow_address']
                    txid = check_monero_payment(xmr_addr, escrow.get('amount_xmr', 0))
                else:
                    flash("Unsupported cryptocurrency", 'error')
                    return redirect(url_for('user.orders'))
            except Exception as e:
                logger.error(f"Error checking payment for order {order_id}: {str(e)}")
                flash("Unable to verify payment at this time. Please try again later or contact support.", 'error')
                return redirect(url_for('user.orders'))
            
            if txid:
                c.execute("UPDATE orders SET status = 'paid', escrow_status = 'held' WHERE id = ?", (order_id,))
                c.execute("UPDATE escrow SET status = 'held', txid = ?, created_at = CURRENT_TIMESTAMP WHERE order_id = ?", (txid, order_id))
                conn.commit()
                flash("Payment confirmed, order in escrow", 'success')
                return redirect(url_for('user.orders'))
            else:
                flash("Payment not received. Please ensure you have sent the correct amount to the provided address.", 'error')
                return redirect(url_for('user.orders'))
    except Exception as e:
        logger.error(f"Error in confirm_order for order {order_id}: {str(e)}")
        flash("An error occurred while processing your request. Please try again later.", 'error')
        return redirect(url_for('user.orders'))

@public_bp.route('/release_escrow/<int:order_id>', methods=['POST'])
def release_escrow(order_id):
    """Buyer confirms receipt and releases escrow funds to vendor"""
    if 'user_id' not in session:
        return redirect(url_for('user.login'))
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT o.*, e.status as escrow_status, e.amount_btc, e.vendor_address, e.crypto_currency
            FROM orders o
            JOIN escrow e ON o.id = e.order_id
            WHERE o.id = ? AND o.user_id = ? AND o.status = 'shipped'
        """, (order_id, session['user_id']))
        order = c.fetchone()
        if not order:
            flash("Order not found or not eligible for release", 'error')
            return redirect(url_for('user.orders'))
        if order['escrow_status'] != 'held':
            flash("Escrow is not in held status", 'error')
            return redirect(url_for('user.orders'))
        # Check if vendor is trusted for early finalization
        c.execute("""
            SELECT vl.level, vl.positive_feedback_percentage, vl.sales_count
            FROM vendor_levels vl
            WHERE vl.vendor_id = ?
        """, (order['vendor_id'],))
        vendor_level = c.fetchone()
        is_trusted_vendor = (vendor_level and 
                           vendor_level['level'] >= 8 and 
                           vendor_level['positive_feedback_percentage'] >= 97.0 and
                           vendor_level['sales_count'] >= 500)
        if is_trusted_vendor:
            # Auto-finalize for trusted vendors
            c.execute("UPDATE orders SET status = 'completed', escrow_status = 'released' WHERE id = ?", (order_id,))
            c.execute("UPDATE escrow SET status = 'released' WHERE order_id = ?", (order_id,))
            # Add vendor balance
            fee_percentage = 0.05  # 5% platform fee
            net_amount = order['amount_btc'] * (1 - fee_percentage)
            c.execute("""
                UPDATE balances 
                SET balance_btc = balance_btc + ?, last_updated = CURRENT_TIMESTAMP
                WHERE user_id = ?
            """, (net_amount, order['vendor_id']))
            conn.commit()
            # Notifications
            send_notification_with_email(order['user_id'], f'Order #{order_id} has been finalized and escrow released to vendor.', 'success', subject='Order Finalized & Escrow Released')
            send_notification_with_email(order['vendor_id'], f'Order #{order_id} has been finalized and funds released to your balance.', 'success', subject='Order Finalized & Funds Released')
            send_notification_with_email(1, f'Order #{order_id} finalized for trusted vendor. Escrow released.', 'info', subject='Order Finalized')
            flash("Order completed! Funds released to trusted vendor automatically.", 'success')
        else:
            # Regular escrow release
            c.execute("UPDATE orders SET escrow_status = 'pending_release' WHERE id = ?", (order_id,))
            c.execute("UPDATE escrow SET status = 'pending_release' WHERE order_id = ?", (order_id,))
            conn.commit()
            # Notifications
            send_notification_with_email(order['user_id'], f'You have requested escrow release for order #{order_id}. Admin will review soon.', 'info', subject='Escrow Release Requested')
            send_notification_with_email(order['vendor_id'], f'Buyer has requested escrow release for order #{order_id}. Awaiting admin review.', 'info', subject='Escrow Release Requested')
            send_notification_with_email(1, f'Escrow release requested for order #{order_id}. Please review.', 'info', subject='Escrow Release Requested')
            flash("Escrow release requested. Admin will review and finalize within 24 hours.", 'success')
        return redirect(url_for('user.orders'))

@public_bp.route('/dispute_order/<int:order_id>', methods=['POST'])
def dispute_order(order_id):
    """Buyer creates a dispute for an order"""
    if 'user_id' not in session:
        return redirect(url_for('user.login'))
    reason = request.form.get('reason', '').strip()
    if not reason:
        flash("Please provide a reason for the dispute", 'error')
        return redirect(url_for('user.orders'))
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT o.*, e.status as escrow_status, e.crypto_currency
            FROM orders o
            JOIN escrow e ON o.id = e.order_id
            WHERE o.id = ? AND o.user_id = ? AND e.status = 'held'
        """, (order_id, session['user_id']))
        order = c.fetchone()
        if not order:
            flash("Order not found or not eligible for dispute", 'error')
            return redirect(url_for('user.orders'))
        # Check if dispute already exists
        c.execute("SELECT id FROM disputes WHERE order_id = ?", (order_id,))
        existing_dispute = c.fetchone()
        if existing_dispute:
            flash("Dispute already exists for this order", 'error')
            return redirect(url_for('user.orders'))
        # Create dispute
        c.execute("""
            INSERT INTO disputes (order_id, submitted_by, reason, status, created_at)
            VALUES (?, ?, ?, 'open', CURRENT_TIMESTAMP)
        """, (order_id, session['user_id'], reason))
        # Update order and escrow status
        c.execute("UPDATE orders SET status = 'disputed', dispute_status = 'open' WHERE id = ?", (order_id,))
        c.execute("UPDATE escrow SET status = 'disputed' WHERE order_id = ?", (order_id,))
        conn.commit()
        # Notifications
        send_notification_with_email(order['user_id'], f'You have opened a dispute for order #{order_id}. Admin will review and resolve.', 'info', subject='Dispute Created')
        send_notification_with_email(order['vendor_id'], f'A dispute has been opened for order #{order_id} by the buyer.', 'warning', subject='Dispute Created')
        send_notification_with_email(1, f'Dispute opened for order #{order_id}. Please review and resolve.', 'info', subject='Dispute Created')
        flash("Dispute created successfully. Admin will review and resolve.", 'success')
        return redirect(url_for('user.orders'))
    
def check_expired_orders():
    from utils.database import send_notification_with_email
    with get_db_connection() as conn:
        c = conn.cursor()
        expiry_time = datetime.utcnow() - timedelta(days=14)
        c.execute("""
            SELECT o.id, o.user_id, o.vendor_id, e.multisig_address, e.buyer_address, e.amount_btc, e.amount_usd, e.crypto_currency
            FROM orders o
            JOIN escrow e ON o.id = e.order_id
            WHERE o.status = 'paid' AND e.created_at < ? AND o.dispute_status IS NULL
        """, (expiry_time,))
        expired_orders = [dict(row) for row in c.fetchall()]
        for order in expired_orders:
            if order['crypto_currency'] == 'BTC':
                buyer_key = Key(order['buyer_address'], network='testnet')
                txid = send_btc(buyer_key, order['buyer_address'], order['amount_btc'])
                if txid:
                    c.execute("UPDATE orders SET status = 'refunded', escrow_status = 'refunded' WHERE id = ?", (order['id'],))
                    c.execute("UPDATE escrow SET status = 'refunded', txid = ? WHERE order_id = ?", (txid, order['id']))
                    conn.commit()
                    # Notifications
                    send_notification_with_email(order['user_id'], f'Order #{order["id"]} has been automatically refunded after expiration.', 'info', subject='Order Refunded')
                    send_notification_with_email(order['vendor_id'], f'Order #{order["id"]} has been refunded to the buyer after expiration.', 'info', subject='Order Refunded')
                    send_notification_with_email(1, f'Order #{order["id"]} was auto-refunded after expiration.', 'info', subject='Order Refunded')
                    print(f"Automatically refunded order {order['id']} in BTC")
            # Skip Monero orders
            else:
                print(f"Skipping refund for order {order['id']} (Monero disabled)")
                continue

def auto_finalize_trusted_vendor_orders():
    from utils.database import send_notification_with_email
    with get_db_connection() as conn:
        c = conn.cursor()
        auto_finalize_time = datetime.utcnow() - timedelta(hours=24)
        c.execute("""
            SELECT o.id, o.user_id, o.vendor_id, e.amount_btc, vl.level, vl.positive_feedback_percentage, vl.sales_count
            FROM orders o
            JOIN escrow e ON o.id = e.order_id
            LEFT JOIN vendor_levels vl ON o.vendor_id = vl.vendor_id
            WHERE o.escrow_status = 'pending_release' 
            AND e.status = 'pending_release'
            AND e.created_at < ?
            AND vl.level >= 8 
            AND vl.positive_feedback_percentage >= 97.0
            AND vl.sales_count >= 500
        """, (auto_finalize_time,))
        trusted_orders = c.fetchall()
        for order in trusted_orders:
            c.execute("UPDATE orders SET status = 'completed', escrow_status = 'released' WHERE id = ?", (order['id'],))
            c.execute("UPDATE escrow SET status = 'released' WHERE order_id = ?", (order['id'],))
            fee_percentage = 0.05  # 5% platform fee
            net_amount = order['amount_btc'] * (1 - fee_percentage)
            c.execute("SELECT user_id FROM balances WHERE user_id = ?", (order['vendor_id'],))
            if not c.fetchone():
                c.execute("INSERT INTO balances (user_id, balance_btc, balance_xmr, last_updated) VALUES (?, 0, 0, CURRENT_TIMESTAMP)", (order['vendor_id'],))
            c.execute("""
                UPDATE balances 
                SET balance_btc = balance_btc + ?, last_updated = CURRENT_TIMESTAMP
                WHERE user_id = ?
            """, (net_amount, order['vendor_id']))
            c.execute("""
                UPDATE vendor_levels
                SET sales_count = sales_count + 1, updated_at = CURRENT_TIMESTAMP
                WHERE vendor_id = ?
            """, (order['vendor_id'],))
            conn.commit()
            # Notifications
            send_notification_with_email(order['user_id'], f'Order #{order["id"]} has been auto-finalized and escrow released to vendor.', 'success', subject='Order Auto-Finalized')
            send_notification_with_email(order['vendor_id'], f'Order #{order["id"]} has been auto-finalized and funds released to your balance.', 'success', subject='Order Auto-Finalized')
            send_notification_with_email(1, f'Order #{order["id"]} was auto-finalized for trusted vendor. Escrow released.', 'info', subject='Order Auto-Finalized')
            print(f"Auto-finalized order {order['id']} for trusted vendor {order['vendor_id']}")