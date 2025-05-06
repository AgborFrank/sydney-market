from flask import Blueprint, render_template, request, session, jsonify, flash, redirect, url_for
from utils.database import get_db_connection

cart_bp = Blueprint('cart', __name__)

@cart_bp.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please log in to add to cart.'}), 401
    
    data = request.get_json()
    product_id = data.get('product_id')
    quantity = data.get('quantity', 1)

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT stock, price_usd FROM products WHERE id = ?", (product_id,))
        product = c.fetchone()
        if not product or product['stock'] < quantity:
            return jsonify({'success': False, 'message': 'Insufficient stock.'}), 400
        
        # Add to cart (stored in session or database)
        c.execute("""
            INSERT INTO cart (user_id, product_id, quantity)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id, product_id) DO UPDATE SET quantity = quantity + ?
        """, (session['user_id'], product_id, quantity, quantity))
        conn.commit()
    
    return jsonify({'success': True, 'message': 'Added to cart!'})

@cart_bp.route('/cart')
def view_cart():
    if 'user_id' not in session:
        flash("Please log in to view your cart.", 'error')
        return redirect(url_for('user.login'))
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT p.id, p.title, p.price_usd, c.quantity, p.featured_image
                FROM cart c
                JOIN products p ON c.product_id = p.id
                WHERE c.user_id = ?
            """, (session['user_id'],))
            cart_items = [dict(row) for row in c.fetchall()]
        return render_template('cart.html', cart_items=cart_items)
    except Exception as e:
        print(f"Error in view_cart: {str(e)}")
        flash("An error occurred while loading your cart.", 'error')
        return redirect(url_for('public.index'))
# Register in app.py
# app.register_blueprint(cart_bp)