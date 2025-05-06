from flask import Blueprint, render_template, request, session, redirect, url_for, flash
from utils.database import get_db_connection, get_product_count
from utils.security import validate_csrf_token
from datetime import datetime, timedelta
from utils.bitcoin import check_payment, send_btc, ESCROW_KEY
import traceback

public_bp = Blueprint('public', __name__, url_prefix='')
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
def index():
    if 'user_id' not in session:
        flash('Please log in to access the marketplace.', 'error')
        return redirect(url_for('user.login'))
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            # Fetch all products in stock with vendor settings
            c.execute("""
                SELECT p.*, u.pusername as vendor_username, vs.business_name, vs.shipping_location, vs.shipping_destinations
                FROM products p 
                LEFT JOIN users u ON p.vendor_id = u.id 
                LEFT JOIN vendor_settings vs ON p.vendor_id = vs.user_id
                WHERE p.stock > 0
            """)
            products = [dict(row) for row in c.fetchall()]
            
            # Fetch featured products from vendors with 'admin' role with vendor settings
            c.execute("""
                SELECT p.*, u.pusername as vendor_username, vs.shipping_location, vs.shipping_destinations
                FROM products p 
                LEFT JOIN users u ON p.vendor_id = u.id 
                LEFT JOIN vendor_settings vs ON p.vendor_id = vs.user_id
                WHERE u.role = 'admin' AND p.stock > 0
            """)
            featured_products = [dict(row) for row in c.fetchall()]
            
            # Fetch all categories
            c.execute("SELECT * FROM categories")
            categories = [dict(row) for row in c.fetchall()]
            
            # Fetch featured categories
            c.execute("""
                SELECT * 
                FROM categories 
                WHERE parent_id IS NULL AND image_path IS NOT NULL AND featured = 1 
                LIMIT 3
            """)
            featured_categories = [dict(row) for row in c.fetchall()]
            
            # Build category tree
            category_tree = {cat['id']: dict(cat, subcategories=[]) for cat in categories}
            for cat in categories:
                if cat['parent_id']:
                    category_tree[cat['parent_id']]['subcategories'].append(category_tree[cat['id']])
            top_level_categories = [cat for cat in category_tree.values() if not cat['parent_id']]
            
            for category in top_level_categories:
                category['product_count'] = get_product_count(category['id'], category_tree, c)
    
    except Exception as e:
        flash(f"Error loading marketplace: {str(e)}", 'error')
        return redirect(url_for('user.login'))

    return render_template('index.html', products=products, featured_products=featured_products, 
                         categories=categories, top_level_categories=top_level_categories, 
                         featured_categories=featured_categories)
    
@public_bp.route('/category/<int:category_id>')
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
@public_bp.route('/product/<int:product_id>')
def product_detail(product_id):
    if 'user_id' not in session:
        flash('Please log in to access the marketplace.', 'error')
        return redirect(url_for('user.login'))
    try:
        print(f"Attempting to load product ID: {product_id}")
        with get_db_connection() as conn:
            c = conn.cursor()
            # Fetch product
            c.execute("SELECT * FROM products WHERE id = ?", (product_id,))
            product = c.fetchone()
            if not product:
                print(f"Product ID {product_id} not found in products table.")
                flash("Product not found.", 'error')
                return redirect(url_for('public.index'))
            product = dict(product)
            print(f"Product found: {product['title']}")

            # Fetch vendor details for main product
            c.execute("""
                SELECT u.username, u.id as vendor_id, vs.business_name, vs.min_order_amount, vs.shipping_location, 
                       vs.shipping_destinations, vs.shipping_policy, vs.return_policy, vs.support_contact
                FROM users u
                LEFT JOIN vendor_settings vs ON u.id = vs.user_id
                WHERE u.id = ?
            """, (product['vendor_id'],))
            vendor = c.fetchone()
            if not vendor:
                print(f"No vendor found for vendor_id: {product['vendor_id']}")
            vendor = dict(vendor) if vendor else {
                'username': 'Admin', 'vendor_id': None, 'business_name': 'Admin', 'min_order_amount': 0.0,
                'shipping_location': 'Not specified', 'shipping_destinations': 'Not specified',
                'shipping_policy': '', 'return_policy': '', 'support_contact': ''
            }
            print(f"Vendor: {vendor['username']}")

            # Calculate vendor level
            c.execute("SELECT COUNT(*) FROM orders WHERE vendor_id = ? AND status = 'completed'", (product['vendor_id'],))
            result = c.fetchone()
            sales = result[0] if result else 0
            vendor['level'] = 'Gold' if sales > 1000 else 'Silver' if sales > 500 else 'Bronze' if sales > 100 else 'Level 1' if sales < 1 else 'Level 1'
            print(f"Vendor sales: {sales}, level: {vendor['level']}")

            # Fetch vendor feedback
            c.execute("""
                SELECT COUNT(*) 
                FROM reviews r
                JOIN products p ON r.product_id = p.id
                WHERE p.vendor_id = ? AND r.rating >= 4
            """, (product['vendor_id'],))
            result = c.fetchone()
            positive = result[0] if result else 0
            c.execute("""
                SELECT COUNT(*) 
                FROM reviews r
                JOIN products p ON r.product_id = p.id
                WHERE p.vendor_id = ? AND r.rating < 4
            """, (product['vendor_id'],))
            result = c.fetchone()
            negative = result[0] if result else 0
            vendor_feedback = {'positive': positive, 'negative': negative}
            print(f"Vendor feedback: positive={positive}, negative={negative}")

            # Fetch additional data
            c.execute("SELECT * FROM product_images WHERE product_id = ?", (product_id,))
            additional_images = [dict(row) for row in c.fetchall()] or []
            c.execute("SELECT * FROM reviews WHERE product_id = ?", (product_id,))
            reviews = [dict(row) for row in c.fetchall()] or []
            c.execute("SELECT * FROM categories WHERE id = ?", (product['category_id'],))
            result = c.fetchone()
            category = dict(result) if result else {'name': 'Unknown Category'}
            print(f"Category: {category['name']}")

            # Fetch related products with vendor details
            c.execute("""
                SELECT p.*, 
                       u.username, vs.business_name, vs.min_order_amount, vs.shipping_location, 
                       vs.shipping_destinations, vs.shipping_policy, vs.return_policy, vs.support_contact
                FROM products p
                LEFT JOIN users u ON p.vendor_id = u.id
                LEFT JOIN vendor_settings vs ON u.id = vs.user_id
                WHERE p.category_id = ? AND p.stock > 0 AND p.id != ?
            """, (product['category_id'], product_id))
            related_products_raw = c.fetchall()
            related_products = []
            for row in related_products_raw:
                product_dict = dict(row)
                # Extract vendor details into a nested dict
                vendor_dict = {
                    'username': product_dict.pop('username', 'Admin'),
                    'business_name': product_dict.pop('business_name', 'Admin'),
                    'min_order_amount': product_dict.pop('min_order_amount', 0.0),
                    'shipping_location': product_dict.pop('shipping_location', 'Not specified'),
                    'shipping_destinations': product_dict.pop('shipping_destinations', 'Not specified'),
                    'shipping_policy': product_dict.pop('shipping_policy', ''),
                    'return_policy': product_dict.pop('return_policy', ''),
                    'support_contact': product_dict.pop('support_contact', '')
                }
                # Calculate level for this vendor
                c.execute("SELECT COUNT(*) FROM orders WHERE vendor_id = ? AND status = 'completed'", (product_dict['vendor_id'],))
                sales = c.fetchone()[0] or 0
                vendor_dict['level'] = 'Gold' if sales > 1000 else 'Silver' if sales > 500 else 'Bronze' if sales > 100 else 'Level 1' if sales < 1 else 'Level 1'
                product_dict['vendor'] = vendor_dict
                related_products.append(product_dict)
            print(f"Related products found: {len(related_products)}")

        print("Rendering product_detail.html")
        return render_template('product_detail.html', product=product, vendor=vendor, vendor_feedback=vendor_feedback,
                              additional_images=additional_images, reviews=reviews, category=category,
                              related_products=related_products)
    except Exception as e:
        print(f"Error in product_detail: {str(e)}")
        print(traceback.format_exc())
        flash(f"An error occurred while loading the product page: {str(e)}", 'error')
        return redirect(url_for('public.index'))
    
  
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
    return render_template('escrow.html', title="Multisig Escrow - DarkVault",
                          description="Learn how our multisig escrow system ensures secure transactions.")

@public_bp.route('/search')
def search_products():
    if 'user_id' not in session:
        flash('Please log in to access the marketplace.', 'error')
        return redirect(url_for('user.login'))
    
    query = request.args.get('q', '').strip()
    if not query:
        return redirect(url_for('public.index'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM products WHERE title LIKE ? OR description LIKE ?",
                  (f"%{query}%", f"%{query}%"))
        products = c.fetchall()
    
    return render_template('search_results.html', products=products, query=query)

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
            c.execute("SELECT username FROM users WHERE id = ?", (vendor_id,))
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
        validate_csrf_token()
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

@public_bp.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('vendor_id', None)
    return redirect(url_for('public.index'))

@public_bp.route('/order/confirm/<int:order_id>', methods=['POST'])
def confirm_order(order_id):
    if 'user_id' not in session:
        return redirect(url_for('user.login'))
    
    validate_csrf_token()
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
    
    validate_csrf_token()
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
        expiry_time = datetime.utcnow() - timedelta(days=7)
        c.execute("SELECT o.id, e.multisig_address, e.buyer_address, e.btc_amount FROM orders o JOIN escrow e ON o.id = e.order_id WHERE o.status = 'paid' AND e.created_at < ?", (expiry_time,))
        expired_orders = c.fetchall()
        
        for order in expired_orders:
            buyer_key = Key(order['buyer_address'], network='testnet')
            txid = send_btc(buyer_key, order['buyer_address'], order['btc_amount'])  # Simplified refund
            if txid:
                c.execute("UPDATE orders SET status = 'refunded', escrow_status = 'refunded' WHERE id = ?", (order['id'],))
                c.execute("UPDATE escrow SET status = 'refunded', txid = ? WHERE order_id = ?", (txid, order['id']))
                conn.commit()
                print(f"Automatically refunded order {order['id']}")