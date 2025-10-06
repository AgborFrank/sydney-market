"""
Advertising System for Sydney Marketplace
Handles sponsored ads, bidding, impressions, and payments
"""

import os
import secrets
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.utils import secure_filename
from utils.database import get_db_connection
from utils.auth import require_vendor_role, login_required
from utils.crypto import get_btc_price, get_xmr_price
from flask_wtf.csrf import generate_csrf
#from utils.security import validate_csrf_token

ads_bp = Blueprint('ads', __name__)

@ads_bp.context_processor
def inject_csrf_token():
    return {'csrf_token': generate_csrf}

# Ad placement types and their base costs
AD_PLACEMENTS = {
    'homepage_featured': {
        'name': 'Homepage Featured',
        'base_cost_btc': 0.001,
        'base_cost_xmr': 0.05,
        'description': 'Featured placement on homepage carousel',
        'max_duration_days': 7,
        'priority': 1
    },
    'category_top': {
        'name': 'Category Top',
        'base_cost_btc': 0.0005,
        'base_cost_xmr': 0.025,
        'description': 'Top placement in category pages',
        'max_duration_days': 14,
        'priority': 2
    },
    'search_results': {
        'name': 'Search Results',
        'base_cost_btc': 0.0002,
        'base_cost_xmr': 0.01,
        'description': 'Sponsored placement in search results',
        'max_duration_days': 30,
        'priority': 3
    },
    'sidebar_promoted': {
        'name': 'Sidebar Promoted',
        'base_cost_btc': 0.0003,
        'base_cost_xmr': 0.015,
        'description': 'Promoted products in sidebar',
        'max_duration_days': 21,
        'priority': 4
    }
}

@ads_bp.route('/dashboard')
@require_vendor_role
def ads_dashboard():
    """Vendor ads dashboard showing active campaigns and performance"""
    if 'user_id' not in session:
        flash("Please log in to access ads dashboard.", 'error')
        return redirect(url_for('user.login'))
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Get vendor's active ads
            c.execute("""
                SELECT sa.*, p.title as product_title, p.featured_image,
                       (SELECT SUM(impression_count) FROM ad_impressions WHERE ad_id = sa.id) as total_impressions,
                       (SELECT SUM(click_count) FROM ad_impressions WHERE ad_id = sa.id) as total_clicks,
                       (SELECT SUM(cost) FROM ad_impressions WHERE ad_id = sa.id) as total_cost
                FROM sponsored_ads sa
                JOIN products p ON sa.product_id = p.id
                WHERE sa.vendor_id = ? AND sa.status = 'active'
                ORDER BY sa.created_at DESC
            """, (session['user_id'],))
            active_ads = [dict(row) for row in c.fetchall()]
            
            # Get recent ad performance
            c.execute("""
                SELECT ai.*, sa.bid_amount, p.title as product_title
                FROM ad_impressions ai
                JOIN sponsored_ads sa ON ai.ad_id = sa.id
                JOIN products p ON sa.product_id = p.id
                WHERE sa.vendor_id = ? AND ai.date >= date('now', '-7 days')
                ORDER BY ai.date DESC
            """, (session['user_id'],))
            recent_performance = [dict(row) for row in c.fetchall()]
            
            # Get vendor's products for creating new ads
            c.execute("""
                SELECT id, title, price_usd, stock, featured_image
                FROM products
                WHERE vendor_id = ? AND status = 'active' AND stock > 0
                ORDER BY title
            """, (session['user_id'],))
            available_products = [dict(row) for row in c.fetchall()]
            
            # Calculate total spend
            c.execute("""
                SELECT COALESCE(SUM(cost), 0) as total_spend
                FROM ad_impressions ai
                JOIN sponsored_ads sa ON ai.ad_id = sa.id
                WHERE sa.vendor_id = ?
            """, (session['user_id'],))
            total_spend = c.fetchone()['total_spend']
            
            # Get current crypto prices
            btc_price = get_btc_price()
            xmr_price = get_xmr_price()
            
        return render_template('ads/dashboard.html',
                             active_ads=active_ads,
                             recent_performance=recent_performance,
                             available_products=available_products,
                             total_spend=total_spend,
                             btc_price=btc_price,
                             xmr_price=xmr_price,
                             ad_placements=AD_PLACEMENTS)
                             
    except Exception as e:
        flash(f"Error loading ads dashboard: {str(e)}", 'error')
        return redirect(url_for('user.dashboard'))

@ads_bp.route('/create', methods=['GET', 'POST'])
@require_vendor_role
def create_ad():
    """Create a new sponsored ad campaign"""
    if 'user_id' not in session:
        flash("Please log in to create ads.", 'error')
        return redirect(url_for('user.login'))
    
    if request.method == 'POST':
        #validate_csrf_token()
        
        # Get form data
        product_id = request.form.get('product_id', type=int)
        placement_type = request.form.get('placement_type')
        bid_amount = request.form.get('bid_amount', type=float)
        daily_budget = request.form.get('daily_budget', type=float)
        duration_days = request.form.get('duration_days', type=int)
        crypto_currency = request.form.get('crypto_currency', 'BTC')
        
        # Validation
        if not all([product_id, placement_type, bid_amount, daily_budget, duration_days]):
            flash("All fields are required.", 'error')
            return redirect(url_for('ads.create_ad'))
        
        if placement_type not in AD_PLACEMENTS:
            flash("Invalid placement type.", 'error')
            return redirect(url_for('ads.create_ad'))
        
        if duration_days > AD_PLACEMENTS[placement_type]['max_duration_days']:
            flash(f"Maximum duration for {placement_type} is {AD_PLACEMENTS[placement_type]['max_duration_days']} days.", 'error')
            return redirect(url_for('ads.create_ad'))
        
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                
                # Verify product belongs to vendor and is active
                c.execute("""
                    SELECT id, title FROM products 
                    WHERE id = ? AND vendor_id = ? AND status = 'active' AND stock > 0
                """, (product_id, session['user_id']))
                product = c.fetchone()
                
                if not product:
                    flash("Product not found or not eligible for advertising.", 'error')
                    return redirect(url_for('ads.create_ad'))
                
                # Check if vendor has sufficient balance
                c.execute("SELECT balance_btc, balance_xmr FROM balances WHERE user_id = ?", (session['user_id'],))
                user_balance = c.fetchone()
                
                # Create balance record if it doesn't exist
                if not user_balance:
                    c.execute("INSERT INTO balances (user_id, balance_btc, balance_xmr) VALUES (?, 0.0, 0.0)", (session['user_id'],))
                    user_balance = {'balance_btc': 0.0, 'balance_xmr': 0.0}
                
                required_balance = daily_budget * duration_days
                if crypto_currency == 'BTC' and user_balance['balance_btc'] < required_balance:
                    flash(f"Insufficient BTC balance. Required: {required_balance:.6f} BTC", 'error')
                    return redirect(url_for('ads.create_ad'))
                elif crypto_currency == 'XMR' and user_balance['balance_xmr'] < required_balance:
                    flash(f"Insufficient XMR balance. Required: {required_balance:.6f} XMR", 'error')
                    return redirect(url_for('ads.create_ad'))
                
                # Create the ad
                c.execute("""
                    INSERT INTO sponsored_ads (
                        vendor_id, product_id, placement_type, bid_amount, daily_budget,
                        crypto_currency, duration_days, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', CURRENT_TIMESTAMP)
                """, (session['user_id'], product_id, placement_type, bid_amount, 
                      daily_budget, crypto_currency, duration_days))
                
                # Deduct initial budget from user balance
                if crypto_currency == 'BTC':
                    c.execute("""
                        UPDATE balances SET balance_btc = balance_btc - ? WHERE user_id = ?
                    """, (required_balance, session['user_id']))
                else:
                    c.execute("""
                        UPDATE balances SET balance_xmr = balance_xmr - ? WHERE user_id = ?
                    """, (required_balance, session['user_id']))
                
                conn.commit()
                flash("Ad campaign created successfully!", 'success')
                return redirect(url_for('ads.ads_dashboard'))
                
        except Exception as e:
            flash(f"Error creating ad: {str(e)}", 'error')
            return redirect(url_for('ads.create_ad'))
    
    # GET request - show form
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT id, title, price_usd, stock, featured_image
                FROM products
                WHERE vendor_id = ? AND status = 'active' AND stock > 0
                ORDER BY title
            """, (session['user_id'],))
            products = [dict(row) for row in c.fetchall()]
            
            # Get user balance
            c.execute("SELECT balance_btc, balance_xmr FROM balances WHERE user_id = ?", (session['user_id'],))
            user_balance = c.fetchone()
            
            # Create balance record if it doesn't exist
            if not user_balance:
                c.execute("INSERT INTO balances (user_id, balance_btc, balance_xmr) VALUES (?, 0.0, 0.0)", (session['user_id'],))
                user_balance = {'balance_btc': 0.0, 'balance_xmr': 0.0}
            
        return render_template('ads/create.html',
                             products=products,
                             user_balance=user_balance,
                             ad_placements=AD_PLACEMENTS)
                             
    except Exception as e:
        flash(f"Error loading create ad form: {str(e)}", 'error')
        return redirect(url_for('ads.ads_dashboard'))

@ads_bp.route('/edit/<int:ad_id>', methods=['GET', 'POST'])
@require_vendor_role
def edit_ad(ad_id):
    """Edit an existing ad campaign"""
    if 'user_id' not in session:
        flash("Please log in to edit ads.", 'error')
        return redirect(url_for('user.login'))
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Get ad details and verify ownership
            c.execute("""
                SELECT sa.*, p.title as product_title
                FROM sponsored_ads sa
                JOIN products p ON sa.product_id = p.id
                WHERE sa.id = ? AND sa.vendor_id = ?
            """, (ad_id, session['user_id']))
            ad = c.fetchone()
            
            if not ad:
                flash("Ad not found or you don't have permission to edit it.", 'error')
                return redirect(url_for('ads.ads_dashboard'))
            
            if request.method == 'POST':
                #validate_csrf_token()
                
                # Get form data
                bid_amount = request.form.get('bid_amount', type=float)
                daily_budget = request.form.get('daily_budget', type=float)
                status = request.form.get('status')
                
                # Validation
                if not all([bid_amount, daily_budget, status]):
                    flash("All fields are required.", 'error')
                    return redirect(url_for('ads.edit_ad', ad_id=ad_id))
                
                if status not in ['active', 'paused', 'ended']:
                    flash("Invalid status.", 'error')
                    return redirect(url_for('ads.edit_ad', ad_id=ad_id))
                
                # Update ad
                c.execute("""
                    UPDATE sponsored_ads 
                    SET bid_amount = ?, daily_budget = ?, status = ?
                    WHERE id = ?
                """, (bid_amount, daily_budget, status, ad_id))
                
                conn.commit()
                flash("Ad updated successfully!", 'success')
                return redirect(url_for('ads.ads_dashboard'))
            
            # GET request - show edit form
            c.execute("""
                SELECT id, title, price_usd, stock, featured_image
                FROM products
                WHERE vendor_id = ? AND status = 'active' AND stock > 0
                ORDER BY title
            """, (session['user_id'],))
            products = [dict(row) for row in c.fetchall()]
            
            return render_template('ads/edit.html',
                                 ad=ad,
                                 products=products,
                                 ad_placements=AD_PLACEMENTS)
                                 
    except Exception as e:
        flash(f"Error editing ad: {str(e)}", 'error')
        return redirect(url_for('ads.ads_dashboard'))

@ads_bp.route('/delete/<int:ad_id>', methods=['POST'])
@require_vendor_role
def delete_ad(ad_id):
    """Delete an ad campaign"""
    if 'user_id' not in session:
        flash("Please log in to delete ads.", 'error')
        return redirect(url_for('user.login'))
    
    #validate_csrf_token()
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Verify ownership and get ad details
            c.execute("""
                SELECT * FROM sponsored_ads 
                WHERE id = ? AND vendor_id = ?
            """, (ad_id, session['user_id']))
            ad = c.fetchone()
            
            if not ad:
                flash("Ad not found or you don't have permission to delete it.", 'error')
                return redirect(url_for('ads.ads_dashboard'))
            
            # Calculate refund amount
            c.execute("""
                SELECT COALESCE(SUM(cost), 0) as total_spent
                FROM ad_impressions 
                WHERE ad_id = ?
            """, (ad_id,))
            total_spent = c.fetchone()['total_spent']
            
            refund_amount = (ad['daily_budget'] * ad['duration_days']) - total_spent
            
            # Refund unused budget
            if refund_amount > 0:
                if ad['crypto_currency'] == 'BTC':
                    c.execute("""
                        UPDATE balances SET balance_btc = balance_btc + ? WHERE user_id = ?
                    """, (refund_amount, session['user_id']))
                else:
                    c.execute("""
                        UPDATE balances SET balance_xmr = balance_xmr + ? WHERE user_id = ?
                    """, (refund_amount, session['user_id']))
            
            # Delete ad and related data
            c.execute("DELETE FROM ad_impressions WHERE ad_id = ?", (ad_id,))
            c.execute("DELETE FROM sponsored_ads WHERE id = ?", (ad_id,))
            
            conn.commit()
            flash("Ad campaign deleted successfully!", 'success')
            
    except Exception as e:
        flash(f"Error deleting ad: {str(e)}", 'error')
    
    return redirect(url_for('ads.ads_dashboard'))

@ads_bp.route('/analytics/<int:ad_id>')
@require_vendor_role
def ad_analytics(ad_id):
    """Detailed analytics for a specific ad campaign"""
    if 'user_id' not in session:
        flash("Please log in to view analytics.", 'error')
        return redirect(url_for('user.login'))
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Get ad details and verify ownership
            c.execute("""
                SELECT sa.*, p.title as product_title, p.featured_image
                FROM sponsored_ads sa
                JOIN products p ON sa.product_id = p.id
                WHERE sa.id = ? AND sa.vendor_id = ?
            """, (ad_id, session['user_id']))
            ad = c.fetchone()
            
            if not ad:
                flash("Ad not found or you don't have permission to view it.", 'error')
                return redirect(url_for('ads.ads_dashboard'))
            
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
            
            return render_template('ads/analytics.html',
                                 ad=ad,
                                 daily_data=daily_data,
                                 total_impressions=total_impressions,
                                 total_clicks=total_clicks,
                                 total_cost=total_cost,
                                 ctr=ctr)
                                 
    except Exception as e:
        flash(f"Error loading analytics: {str(e)}", 'error')
        return redirect(url_for('ads.ads_dashboard'))

@ads_bp.route('/api/get_ads/<placement_type>')
def get_ads_for_placement(placement_type):
    """API endpoint to get ads for specific placement (used by frontend)"""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Get active ads for placement, ordered by bid amount (highest first)
            c.execute("""
                SELECT sa.*, p.title, p.description, p.price_usd, p.featured_image,
                       u.pusername as vendor_name
                FROM sponsored_ads sa
                JOIN products p ON sa.product_id = p.id
                JOIN users u ON sa.vendor_id = u.id
                WHERE sa.placement_type = ? AND sa.status = 'active'
                AND p.status = 'active' AND p.stock > 0
                ORDER BY sa.bid_amount DESC
                LIMIT 5
            """, (placement_type,))
            
            ads = [dict(row) for row in c.fetchall()]
            
            # Record impressions for each ad
            for ad in ads:
                c.execute("""
                    INSERT OR REPLACE INTO ad_impressions (ad_id, product_id, impression_count, date)
                    VALUES (?, ?, 
                        COALESCE((SELECT impression_count FROM ad_impressions 
                                 WHERE ad_id = ? AND date = CURRENT_DATE), 0) + 1,
                        CURRENT_DATE)
                """, (ad['id'], ad['product_id'], ad['id']))
            
            conn.commit()
            return jsonify({'ads': ads})
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@ads_bp.route('/api/record_click/<int:ad_id>', methods=['POST'])
def record_ad_click(ad_id):
    """API endpoint to record ad clicks"""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Verify ad exists and is active
            c.execute("""
                SELECT sa.*, p.status as product_status, p.stock
                FROM sponsored_ads sa
                JOIN products p ON sa.product_id = p.id
                WHERE sa.id = ? AND sa.status = 'active'
            """, (ad_id,))
            ad = c.fetchone()
            
            if not ad or ad['product_status'] != 'active' or ad['stock'] <= 0:
                return jsonify({'error': 'Ad not available'}), 404
            
            # Record click
            c.execute("""
                UPDATE ad_impressions 
                SET click_count = click_count + 1
                WHERE ad_id = ? AND date = CURRENT_DATE
            """, (ad_id,))
            
            # If no impression record exists for today, create one
            if c.rowcount == 0:
                c.execute("""
                    INSERT INTO ad_impressions (ad_id, product_id, click_count, date)
                    VALUES (?, ?, 1, CURRENT_DATE)
                """, (ad_id, ad['product_id']))
            
            conn.commit()
            return jsonify({'success': True})
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@ads_bp.route('/pricing')
def pricing():
    """Show advertising pricing information"""
    try:
        btc_price = get_btc_price()
        xmr_price = get_xmr_price()
        
        # Calculate USD equivalents
        for placement in AD_PLACEMENTS.values():
            placement['cost_usd_btc'] = placement['base_cost_btc'] * btc_price
            placement['cost_usd_xmr'] = placement['base_cost_xmr'] * xmr_price
        
        return render_template('ads/pricing.html',
                             ad_placements=AD_PLACEMENTS,
                             btc_price=btc_price,
                             xmr_price=xmr_price)
                             
    except Exception as e:
        flash(f"Error loading pricing: {str(e)}", 'error')
        return redirect(url_for('public.index')) 