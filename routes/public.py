from flask import Blueprint, render_template, request, session, redirect, url_for, flash
from utils.database import get_db_connection, get_product_count, get_featured_products, get_random_products
#from utils.security import validate_csrf_token
from datetime import datetime, timedelta
from utils.bitcoin import check_payment, send_btc, ESCROW_KEY
from flask_login import login_required, current_user, login_user
#from utils.monero import send_monero
from utils.database import get_user_profile_data
from utils.crypto import get_exchange_rates
import traceback
import logging
from pytz import timezone
import json

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
        "SELECT id, pusername as username, last_login, level, pgp_public_key, pgp_public_key "
        "FROM users WHERE id = ?",
        (product_dict['vendor_id'],)
    ).fetchone()

    if not vendor:
        db.close()
        return render_template('error.html', message="Vendor not found"), 404

    # Convert vendor to dict for easier manipulation
    vendor_dict = dict(vendor)

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
    favorite_status = db.execute(
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

    # Fetch exchange rates
    rates = get_exchange_rates()
    if not rates:
        flash("Unable to fetch exchange rates.", 'error')
        rates = {"bitcoin": {}, "monero": {}}

    db.close()
    return render_template(
        'product_detail.html',
        product=product_dict,
        vendor=vendor_dict,
        profile_data=profile_data,
        rates=rates,
        feedback=feedback_list,
        feedback_stats=feedback_stats,
        page=page,
        favorite_status=favorite_status,
        total_pages=total_pages,
        per_page=per_page
    )


@public_bp.route('/vendor/<int:vendor_id>')
@login_required
def vendor_profile(vendor_id):
    db = get_db_connection()

    # Fetch vendor details
    vendor = db.execute(
        "SELECT id, pusername as username, last_login, level, pgp_key, pgp_public_key "
        "FROM users WHERE id = ?",
        (vendor_id,)
    ).fetchone()

    if not vendor:
        db.close()
        return render_template('error.html', message="Vendor not found"), 404

    # Convert vendor to dict for easier manipulation
    vendor_dict = dict(vendor)
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

    # Fetch all published products by the vendor
    products = db.execute(
        "SELECT p.*, "
        "(SELECT COUNT(*) FROM reviews r WHERE r.product_id = p.id) as reviews_count, "
        "(SELECT AVG(r.rating) FROM reviews r WHERE r.product_id = p.id) as avg_rating "
        "FROM products p "
        "WHERE p.vendor_id = ? AND p.published = 1 "
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
            SELECT p.*, AVG(r.rating) as avg_rating
            FROM products p
            LEFT JOIN reviews r ON p.id = r.product_id
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
    
    return render_template('search_results.html', products=products, query=query, filters=request.args)

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

@public_bp.route('/place_order/<int:product_id>')
def place_order(product_id):
    if 'user_id' not in session:
        flash("Please log in to place an order.", 'error')
        return redirect(url_for('auth.login'))
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM products WHERE id = ?", (product_id,))
            product = c.fetchone()
            if not product or product['stock'] <= 0:
                flash("Product not available.", 'error')
                return redirect(url_for('public.product_detail', product_id=product_id))
            product = dict(product)
        
        # Placeholder: Redirect to a checkout page (to be implemented)
        flash("Proceeding to checkout (placeholder).", 'info')
        return redirect(url_for('public.product_detail', product_id=product_id))  # Replace with checkout route later
    except Exception as e:
        print(f"Error in place_order: {str(e)}")
        flash("An error occurred while placing the order.", 'error')
        return redirect(url_for('public.product_detail', product_id=product_id))

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
                    c.execute("""
                        INSERT INTO reviews (product_id, user_id, rating, comment, created_at)
                        VALUES (?, ?, ?, ?, datetime('now'))
                    """, (product_id, session['user_id'], rating, comment))
                    conn.commit()
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

@public_bp.route('/report_vendor/<int:vendor_id>')
def report_vendor(vendor_id):
    if 'user_id' not in session:
        flash("Please log in to report a vendor.", 'error')
        return redirect(url_for('auth.login'))
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT username, btc_balance FROM users WHERE id = ?", (vendor_id,))
            vendor = c.fetchone()
            if not vendor:
                flash("Vendor not found.", 'error')
                return redirect(url_for('public.index'))
        
        # Placeholder: Redirect with a message (implement reporting later)
        flash(f"Reported vendor {vendor['username']} (placeholder).", 'info')
        return redirect(url_for('public.index'))
    except Exception as e:
        print(f"Error in report_vendor: {str(e)}")
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


@public_bp.route('/order/confirm/<int:order_id>', methods=['POST'])
def confirm_order(order_id):
    if 'user_id' not in session:
        return redirect(url_for('user.login'))
    
    #validate_csrf_token()
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM orders WHERE id = ? AND buyer_id = ?", (order_id, session['user_id']))
        order = c.fetchone()
        if not order or order['escrow_status'] != 'pending':
            return redirect(url_for('public.orders', error="Invalid order"))
        
        c.execute("SELECT * FROM escrow WHERE order_id = ?", (order_id,))
        escrow = c.fetchone()
        txid = check_payment(escrow['multisig_address'], escrow['btc_amount'])
        if txid:
            c.execute("UPDATE orders SET status = 'paid', escrow_status = 'locked' WHERE id = ?", (order_id,))
            c.execute("UPDATE escrow SET status = 'locked', txid = ?, created_at = CURRENT_TIMESTAMP WHERE id = ?", (txid, escrow['id']))
            conn.commit()
            flash("Payment confirmed, order in escrow", 'success')
            return redirect(url_for('public.orders'))
        flash("Payment not received", 'error')
        return redirect(url_for('public.orders'))

@public_bp.route('/order/dispute/<int:order_id>', methods=['POST'])
def dispute_order(order_id):
    if 'user_id' not in session:
        return redirect(url_for('user.login'))
    
    #validate_csrf_token()
    reason = request.form.get('reason', '').strip()
    if not reason:
        flash("Dispute reason is required", 'error')
        return redirect(url_for('public.orders'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM orders WHERE id = ? AND buyer_id = ?", (order_id, session['user_id']))
        order = c.fetchone()
        if not order or order['escrow_status'] != 'locked':
            flash("Cannot dispute this order", 'error')
            return redirect(url_for('public.orders'))
        
        c.execute("UPDATE orders SET dispute_status = 'pending' WHERE id = ?", (order_id,))
        c.execute("INSERT INTO reports (user_id, vendor_id, reason, evidence, created_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
                  (session['user_id'], order['vendor_id'], reason, "Dispute from order"))
        conn.commit()
        flash("Dispute submitted, awaiting admin resolution", 'success')
        return redirect(url_for('public.orders'))
    
def check_expired_orders():
    with get_db_connection() as conn:
        c = conn.cursor()
        expiry_time = datetime.utcnow() - timedelta(days=14)
        c.execute("""
            SELECT o.id, e.multisig_address, e.buyer_address, e.amount_btc, e.amount_usd, e.crypto_currency
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
                    print(f"Automatically refunded order {order['id']} in BTC")
            # Skip Monero orders
            else:
                print(f"Skipping refund for order {order['id']} (Monero disabled)")
                continue