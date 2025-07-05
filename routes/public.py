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

public_bp = Blueprint('public', __name__, url_prefix='')
logger = logging.getLogger(__name__)

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
        "SELECT p.*, u.pusername as vendor_username "
        "FROM products p "
        "LEFT JOIN users u ON p.vendor_id = u.id "
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

    btc_usd_rate = rates.get('bitcoin', {}).get('usd', 0)
    xmr_usd_rate = rates.get('monero', {}).get('usd', 0)

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
        "SELECT id, pusername as username, last_login, level, pgp_key, pgp_public_key, avatar "
        "FROM users WHERE id = ?",
        (product_dict['vendor_id'],)
    ).fetchone()

    if not vendor:
        db.close()
        return render_template('error.html', message="Vendor not found"), 404

    # Convert vendor to dict for easier manipulation
    vendor_dict = dict(vendor)

    # Avatar URL logic
    if vendor_dict.get('avatar'):
        vendor_dict['avatar_url'] = url_for('static', filename=f"uploads/avatar/{vendor_dict['avatar']}")
    else:
        vendor_dict['avatar_url'] = url_for('static', filename='avatars/default.png')

    # PGP fingerprint logic
    vendor_dict['pgp_fingerprint'] = None
    if vendor_dict.get('pgp_public_key'):
        try:
            import pgpy
            key, _ = pgpy.PGPKey.from_blob(vendor_dict['pgp_public_key'])
            vendor_dict['pgp_fingerprint'] = str(key.fingerprint)
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
        "SELECT p.*, u.pusername as vendor_username FROM products p "
        "LEFT JOIN users u ON p.vendor_id = u.id "
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
        "SELECT id, pusername as username, last_login, level, pgp_key, pgp_public_key, avatar "
        "FROM users WHERE id = ?",
        (vendor_id,)
    ).fetchone()

    if not vendor:
        db.close()
        return render_template('error.html', message="Vendor not found"), 404

    # Convert vendor to dict for easier manipulation
    vendor_dict = dict(vendor)

    # Avatar URL logic
    if vendor_dict.get('avatar'):
        vendor_dict['avatar_url'] = url_for('static', filename=f"uploads/avatar/{vendor_dict['avatar']}")
    else:
        vendor_dict['avatar_url'] = url_for('static', filename='avatars/default.png')

    # PGP fingerprint logic
    vendor_dict['pgp_fingerprint'] = None
    if vendor_dict.get('pgp_public_key'):
        try:
            import pgpy
            key, _ = pgpy.PGPKey.from_blob(vendor_dict['pgp_public_key'])
            vendor_dict['pgp_fingerprint'] = str(key.fingerprint)
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
        "(SELECT AVG(r.rating) FROM reviews r WHERE r.product_id = p.id) as avg_rating "
        "FROM products p "
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
                SELECT p.*, u.pusername as vendor_username 
                FROM products p 
                LEFT JOIN users u ON p.vendor_id = u.id 
                WHERE p.category_id IN (SELECT id FROM category_tree) AND p.stock > 0
            """, (category_id,))
            products = [dict(row) for row in c.fetchall()]
            
            # Add favorite status and images to products
            user_id = session['user_id']
            for product in products:
                c.execute("SELECT id FROM favorites WHERE user_id = ? AND product_id = ?", (user_id, product['id']))
                product['is_favorited'] = c.fetchone() is not None
                
                # Add first image for each product
                c.execute("SELECT image_path FROM product_images WHERE product_id = ? ORDER BY created_at ASC LIMIT 1", (product['id'],))
                img = c.fetchone()
                if img and img['image_path']:
                    product['image_url'] = url_for('static', filename=img['image_path'])
                else:
                    product['image_url'] = url_for('static', filename='images/logo.png')
            
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
                         top_level_categories=top_level_categories)

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
    
    query = request.args.get('q', '').strip()
    category_id = request.args.get('category_id', type=int)
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
                   vl.sales_count as vendor_sales_count
            FROM products p
            LEFT JOIN reviews r ON p.id = r.product_id
            LEFT JOIN vendor_levels vl ON p.vendor_id = vl.vendor_id
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
        
        # Add first image and favorite status for each product
        user_id = session['user_id']
        for product in products:
            c.execute("SELECT image_path FROM product_images WHERE product_id = ? ORDER BY created_at ASC LIMIT 1", (product['id'],))
            img = c.fetchone()
            if img and img['image_path']:
                product['image_url'] = url_for('static', filename=img['image_path'])
            else:
                product['image_url'] = url_for('static', filename='images/logo.png')  # fallback image
            
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
        return redirect(url_for('auth.login'))
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

        # Check Monero health
        monero_address = generate_monero_address(session['user_id'])
        monero_available = monero_address is not None

        if request.method == 'POST':
            quantity = int(request.form.get('quantity', 1))
            currency = request.form.get('currency', 'BTC')
            if quantity < 1 or quantity > product['stock']:
                flash("Invalid quantity.", 'error')
                return redirect(url_for('public.product_detail', product_id=product_id))
            # Calculate price
            settings = get_settings()
            btc_escrow_wallet = settings.get('btc_escrow_wallet', '')
            xmr_escrow_wallet = settings.get('xmr_escrow_wallet', '')
            escrow_fee_percent = float(settings.get('escrow_fee_percent', 2.5))
            price_usd = product['price_usd'] * quantity
            rates = get_exchange_rates()
            btc_usd_rate = rates.get('bitcoin', {}).get('usd', 0)
            xmr_usd_rate = rates.get('monero', {}).get('usd', 0)
            amount_btc = price_usd / btc_usd_rate if btc_usd_rate > 0 else 0
            amount_xmr = price_usd / xmr_usd_rate if xmr_usd_rate > 0 else 0
            # Generate payment address
            if currency == 'BTC':
                payment_address = generate_btc_address(session['user_id'])
            elif currency == 'XMR' and monero_available:
                payment_address = monero_address
            else:
                flash("Selected currency is not available.", 'error')
                return redirect(url_for('public.product_detail', product_id=product_id))
            # Create order and escrow records (simplified, add more fields as needed)
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("""
                    INSERT INTO orders (user_id, product_id, vendor_id, amount_usd, status, escrow_status, crypto_currency, item_count, created_at)
                    VALUES (?, ?, ?, ?, 'pending', 'pending', ?, ?, datetime('now'))
                """, (session['user_id'], product_id, product['vendor_id'], price_usd, currency, quantity))
                order_id = c.lastrowid
                c.execute("""
                    INSERT INTO escrow (order_id, status, amount_btc, amount_xmr, multisig_address, created_at)
                    VALUES (?, 'pending', ?, ?, ?, datetime('now'))
                """, (order_id, amount_btc, amount_xmr, payment_address))
                conn.commit()
            return redirect(url_for('public.order_payment', order_id=order_id))
        # GET: Show order form
        return render_template('order.html', product=product, monero_available=monero_available)
    except Exception as e:
        print(f"Error in place_order: {str(e)}")
        flash("An error occurred while placing the order.", 'error')
        return redirect(url_for('public.product_detail', product_id=product_id))

# Add order_payment route for order confirmation/payment instructions
@public_bp.route('/order/payment/<int:order_id>')
def order_payment(order_id):
    if 'user_id' not in session:
        flash("Please log in to view your order.", 'error')
        return redirect(url_for('auth.login'))
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT o.*, e.multisig_address, e.amount_btc, e.amount_xmr FROM orders o JOIN escrow e ON o.id = e.order_id WHERE o.id = ? AND o.user_id = ?", (order_id, session['user_id']))
            order = c.fetchone()
            if not order:
                flash("Order not found.", 'error')
                return redirect(url_for('public.orders'))
            product = c.execute("SELECT * FROM products WHERE id = ?", (order['product_id'],)).fetchone()
        return render_template('order_payment.html', order=order, product=product)
    except Exception as e:
        print(f"Error in order_payment: {str(e)}")
        flash("An error occurred while loading the order.", 'error')
        return redirect(url_for('public.orders'))

@public_bp.route('/review_product/<int:product_id>', methods=['GET', 'POST'])
def review_product(product_id):
    if 'user_id' not in session:
        flash("Please log in to write a review.", 'error')
        return redirect(url_for('auth.login'))
    
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
        "SELECT id, pusername as username, last_login, level, pgp_key, pgp_public_key, avatar "
        "FROM users WHERE id = ? AND role = 'vendor'",
        (vendor_id,)
    ).fetchone()

    if not vendor:
        db.close()
        return render_template('error.html', message="Vendor not found"), 404

    # Convert vendor to dict for easier manipulation
    vendor_dict = dict(vendor)

    # Avatar URL logic
    if vendor_dict.get('avatar'):
        vendor_dict['avatar_url'] = url_for('static', filename=f"uploads/avatar/{vendor_dict['avatar']}")
    else:
        vendor_dict['avatar_url'] = url_for('static', filename='avatars/default.png')

    # PGP fingerprint logic
    vendor_dict['pgp_fingerprint'] = None
    if vendor_dict.get('pgp_public_key'):
        try:
            import pgpy
            key, _ = pgpy.PGPKey.from_blob(vendor_dict['pgp_public_key'])
            vendor_dict['pgp_fingerprint'] = str(key.fingerprint)
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
        "(SELECT AVG(r.rating) FROM reviews r WHERE r.product_id = p.id) as avg_rating "
        "FROM products p "
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


@public_bp.route('/order/confirm/<int:order_id>', methods=['POST'])
def confirm_order(order_id):
    if 'user_id' not in session:
        return redirect(url_for('user.login'))
    from utils.bitcoin import check_payment
    from utils.monero import check_monero_payment
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM orders WHERE id = ? AND user_id = ?", (order_id, session['user_id']))
        order = c.fetchone()
        if not order or order['escrow_status'] != 'pending':
            return redirect(url_for('public.orders', error="Invalid order"))
        c.execute("SELECT * FROM escrow WHERE order_id = ?", (order_id,))
        escrow = c.fetchone()
        txid = None
        if order['crypto_currency'] == 'BTC':
            txid = check_payment(escrow['multisig_address'], escrow['amount_btc'])
        elif order['crypto_currency'] == 'XMR':
            txid = check_monero_payment(escrow['multisig_address'], escrow['amount_xmr'])
        if txid:
            c.execute("UPDATE orders SET status = 'paid', escrow_status = 'held' WHERE id = ?", (order_id,))
            c.execute("UPDATE escrow SET status = 'held', txid = ?, created_at = CURRENT_TIMESTAMP WHERE order_id = ?", (txid, order_id))
            conn.commit()
            flash("Payment confirmed, order in escrow", 'success')
            return redirect(url_for('public.orders'))
        flash("Payment not received", 'error')
        return redirect(url_for('public.orders'))

@public_bp.route('/release_escrow/<int:order_id>', methods=['POST'])
def release_escrow(order_id):
    """Buyer confirms receipt and releases escrow funds to vendor"""
    if 'user_id' not in session:
        return redirect(url_for('user.login'))
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT o.*, e.status as escrow_status, e.amount_btc, e.vendor_address
            FROM orders o
            JOIN escrow e ON o.id = e.order_id
            WHERE o.id = ? AND o.user_id = ? AND o.status = 'shipped'
        """, (order_id, session['user_id']))
        order = c.fetchone()
        if not order:
            flash("Order not found or not eligible for release", 'error')
            return redirect(url_for('public.orders'))
        if order['escrow_status'] != 'held':
            flash("Escrow is not in held status", 'error')
            return redirect(url_for('public.orders'))
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
        return redirect(url_for('public.orders'))

@public_bp.route('/dispute_order/<int:order_id>', methods=['POST'])
def dispute_order(order_id):
    """Buyer creates a dispute for an order"""
    if 'user_id' not in session:
        return redirect(url_for('user.login'))
    reason = request.form.get('reason', '').strip()
    if not reason:
        flash("Please provide a reason for the dispute", 'error')
        return redirect(url_for('public.orders'))
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT o.*, e.status as escrow_status
            FROM orders o
            JOIN escrow e ON o.id = e.order_id
            WHERE o.id = ? AND o.user_id = ? AND e.status = 'held'
        """, (order_id, session['user_id']))
        order = c.fetchone()
        if not order:
            flash("Order not found or not eligible for dispute", 'error')
            return redirect(url_for('public.orders'))
        # Check if dispute already exists
        c.execute("SELECT id FROM disputes WHERE order_id = ?", (order_id,))
        existing_dispute = c.fetchone()
        if existing_dispute:
            flash("Dispute already exists for this order", 'error')
            return redirect(url_for('public.orders'))
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
        return redirect(url_for('public.orders'))
    
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