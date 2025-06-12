#import psycopg2
#from psycopg2.extras import RealDictCursor
import sqlite3
import requests
from flask import g
from datetime import datetime
import os
import logging

logger = logging.getLogger(__name__)
#def get_db_connection():
#    conn = psycopg2.connect(
#        dbname=os.getenv('DB_NAME'),
#        user=os.getenv('DB_USER'),
#        password=os.getenv('DB_PASSWORD'),
#        host=os.getenv('DB_HOST'),
#        cursor_factory=RealDictCursor
#    )
#    return conn
def get_db_connection():
    conn = sqlite3.connect(os.getenv('DB_PATH', 'marketplace.db'))
    conn.row_factory = sqlite3.Row
    return conn

def get_user_profile_data(user_id):
    """Fetch user profile data for the user profile component."""
    profile_data = {
        'pusername': 'Unknown',
        'feedback_percentage': 0.0,
        'trust_level': 1,
        'notification_count': 0,
        'btc_balance': 0.0,
        'xmr_balance': 0.0,
        'role': 'user'
    }

    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            # Fetch user info
            c.execute("SELECT pusername, role FROM users WHERE id = ?", (user_id,))
            user_row = c.fetchone()
            if not user_row:
                logger.error(f"No user found for user_id: {user_id}")
                return None, "User not found. Please log in again."

            profile_data['pusername'] = user_row['pusername'] or 'Unknown'
            profile_data['role'] = user_row['role']

            # Fetch balances
            c.execute("SELECT balance_btc, balance_xmr FROM balances WHERE user_id = ?", (user_id,))
            balance = c.fetchone()
            if balance:
                profile_data['btc_balance'] = balance['balance_btc'] or 0.0
                profile_data['xmr_balance'] = balance['balance_xmr'] or 0.0

            # Fetch trust level and feedback for vendors
            if profile_data['role'] == 'vendor':
                c.execute("SELECT level, positive_feedback_percentage FROM vendor_levels WHERE vendor_id = ?", (user_id,))
                vendor_data = c.fetchone()
                if vendor_data:
                    profile_data['trust_level'] = vendor_data['level'] or 1
                    profile_data['feedback_percentage'] = vendor_data['positive_feedback_percentage'] or 0.0

        return profile_data, None
    except Exception as e:
        logger.error(f"Error fetching user profile data: {str(e)}")
        return None, f"Error fetching profile data: {str(e)}"

def get_profile_data(user_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    profile = c.fetchone()
    return dict(profile) if profile else {}

def init_db(reset=False):
    with get_db_connection() as conn:
        c = conn.cursor()
        if reset:
            c.executescript('''
                DROP TABLE IF EXISTS categories;
                DROP TABLE IF EXISTS products;
                DROP TABLE IF EXISTS product_images;
                DROP TABLE IF EXISTS users;
                DROP TABLE IF EXISTS packages;
                DROP TABLE IF EXISTS vendor_subscriptions;
                DROP TABLE IF EXISTS vendor_settings;  -- Replaced vendors
                DROP TABLE IF EXISTS vendor_payments;
                DROP TABLE IF EXISTS messages;
                DROP TABLE IF EXISTS escrow;
                DROP TABLE IF EXISTS reports;
                DROP TABLE IF EXISTS reviews;
                DROP TABLE IF EXISTS settings;
                DROP TABLE IF EXISTS user_settings;
                DROP TABLE IF EXISTS sponsored_ads;
                DROP TABLE IF EXISTS ad_impressions;
                DROP TABLE IF EXISTS ad_payments;
                DROP TABLE IF EXISTS disputes;
                DROP TABLE IF EXISTS favorites;
                DROP TABLE IF EXISTS tickets;
                ALTER TABLE products ADD COLUMN visibility TEXT DEFAULT 'public';
                DROP TABLE IF EXISTS ticket_responses;
                ALTER TABLE vendor_subscriptions;
                ALTER TABLE orders ADD COLUMN crypto_currency TEXT DEFAULT 'BTC';
                ALTER TABLE products  ADD COLUMN origin_country TEXT;
                ALTER TABLE orders ADD COLUMN item_count INTEGER DEFAULT 0;
                ALTER TABLE orders ADD COLUMN amount_usd REAL DEFAULT 0.0;
                ALTER TABLE orders ADD COLUMN status TEXT DEFAULT 'pending';
                ALTER TABLE balances ADD COLUMN deposit_address TEXT;
                ALTER TABLE escrow ADD COLUMN crypto_currency TEXT DEFAULT 'BTC';
                ALTER TABLE vendor_subscriptions ADD COLUMN bond_amount_usd REAL DEFAULT 0.0;
                ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active'";
                UPDATE users SET status = CASE WHEN active = 1 THEN 'active' ELSE 'suspended' END
                ALTER TABLE users ADD COLUMN last_login TIMESTAMP;
                INSERT OR IGNORE INTO fees (fee_type, percentage, description)
                VALUES ('order', 5.0, 'Fee applied to vendor earnings per completed order');
                INSERT OR IGNORE INTO fees (fee_type, percentage, description)
                VALUES ('withdrawal', 2.0, 'Fee applied to vendor withdrawals');
                INSERT OR IGNORE INTO fees (fee_type, percentage, description)
                VALUES ('general', 0.0, 'Placeholder for other transaction fees');
                ALTER TABLE products ADD COLUMN rejection_reason TEXT;
                INSERT OR IGNORE INTO security_settings (setting_name, value, description)
                VALUES ('2fa_admin', 'disabled', 'Enable 2FA for admin accounts');
                INSERT OR IGNORE INTO security_settings (setting_name, value, description)
                VALUES ('2fa_vendor', 'disabled', 'Enable 2FA for vendor accounts');
                INSERT OR IGNORE INTO security_settings (setting_name, value, description)
                VALUES ('password_min_length', '12', 'Minimum password length');
                INSERT OR IGNORE INTO security_settings (setting_name, value, description)
                VALUES ('password_require_special', 'yes', 'Require special characters in passwords');
                INSERT OR IGNORE INTO security_settings (setting_name, value, description)
                VALUES ('session_timeout_minutes', '30', 'Session timeout duration in minutes')
            ''')

        # Users table (no vendor-specific fields)
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                pusername TEXT UNIQUE NOT NULL,
                level TEXT,
                pin TEXT NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                active INTEGER DEFAULT 1,
                registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                btc_address TEXT,
                avatar TEXT,
                login_phrase TEXT,
                status TEXT DEFAULT 'active',
                session_timeout TEXT DEFAULT '30',
                profile_visibility TEXT DEFAULT 'public',
                is_vendor INTEGER DEFAULT 0,
                notify_messages INTEGER DEFAULT 1,
                notify_orders INTEGER DEFAULT 1,
                pgp_public_key TEXT,
                pgp_private_key BLOB,
                vendor_status TEXT DEFAULT NULL,
                two_factor_secret TEXT,
                mnemonic_hash TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                jabber TEXT,
                description TEXT,
                currencyid TEXT DEFAULT 'USD',
                stealth INTEGER DEFAULT 0,
                multisig TEXT,
                refund TEXT,
                canbuy INTEGER DEFAULT 1,
                pinbuy INTEGER DEFAULT 1,
                phis INTEGER DEFAULT 1,
                factor INTEGER DEFAULT 0,
                menu_follow INTEGER DEFAULT 0,
                feedback INTEGER DEFAULT 0,
                tocountryid INTEGER DEFAULT -1,
                countryid INTEGER DEFAULT -1,
                discardww INTEGER DEFAULT 0
            )''')
        c.execute('''CREATE TABLE IF NOT EXISTS favorite_vendors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            vendor_id INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (vendor_id) REFERENCES users(id),
            UNIQUE (user_id, vendor_id)
        )''')
        # Vendor settings table
        c.execute('''CREATE TABLE IF NOT EXISTS vendor_settings 
             (id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id INTEGER UNIQUE NOT NULL,
              rules TEXT,
              slug TEXT,
              business_name TEXT,
              description TEXT,
              logo TEXT,
              currency TEXT DEFAULT 'USD',
              shipping_location TEXT,
              shipping_destinations TEXT,
              backup_wallet TEXT,
              warehouse_address TEXT,
              shipping_details TEXT,
              processing_time TEXT,
              shipping_zones TEXT,
              shipping_policy TEXT,
              return_policy TEXT,
              min_order_amount REAL,
              support_contact TEXT,
              created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
              FOREIGN KEY (user_id) REFERENCES users(id)
              )''')
        c.execute('''CREATE TABLE IF NOT EXISTS cart (
              user_id INTEGER NOT NULL,
              product_id INTEGER NOT NULL,
              quantity INTEGER NOT NULL,
              created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
              PRIMARY KEY (user_id, product_id),
              FOREIGN KEY (user_id) REFERENCES users(id),
              FOREIGN KEY (product_id) REFERENCES products(id)
            )''')
        # Disputes table
        c.execute(''' CREATE TABLE IF NOT EXISTS disputes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_id INTEGER NOT NULL,
                submitted_by INTEGER NOT NULL,
                reason TEXT NOT NULL,
                comments TEXT,
                status TEXT DEFAULT 'open',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved_at TIMESTAMP,
                FOREIGN KEY (order_id) REFERENCES orders(id),
                FOREIGN KEY (submitted_by) REFERENCES users(id)
            )''')

        # Favorites table
        c.execute('''CREATE TABLE IF NOT EXISTS favorites(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        product_id INTEGER NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users(id),
                        FOREIGN KEY (product_id) REFERENCES products(id),
                        UNIQUE(user_id, product_id)
                )''')
        c.execute('''CREATE TABLE IF NOT EXISTS security_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                setting_name TEXT NOT NULL UNIQUE,
                value TEXT NOT NULL,
                description TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
        c.execute('''CREATE TABLE IF NOT EXISTS vendor_ratings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vendor_id INTEGER NOT NULL,
                order_id INTEGER NOT NULL,
                rating INTEGER NOT NULL CHECK(rating >= 1 AND rating <= 5),
                comment TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (vendor_id) REFERENCES users(id),
                FOREIGN KEY (order_id) REFERENCES orders(id)
            )''')
        c.execute('''CREATE TABLE IF NOT EXISTS vendor_levels (
                vendor_id INTEGER PRIMARY KEY,
                level INTEGER NOT NULL DEFAULT 1 CHECK(level >= 1 AND level <= 5),
                sales_count INTEGER NOT NULL DEFAULT 0,
                positive_feedback_percentage REAL NOT NULL DEFAULT 0.0,
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (vendor_id) REFERENCES users(id)
            )''')
        c.execute('''CREATE TABLE IF NOT EXISTS vendor_level_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vendor_id INTEGER NOT NULL,
                old_level INTEGER NOT NULL,
                new_level INTEGER NOT NULL,
                reason TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (vendor_id) REFERENCES users(id)
            )''')
        # Products table
        c.execute('''CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price_usd REAL NOT NULL,
                price_btc REAL NOT NULL,
                price_xmr REAL NOT NULL,
                original_price_usd REAL,
                origin_country TEXT,
                discount_active BOOLEAN DEFAULT 0,
                stock INTEGER NOT NULL,
                category_id INTEGER NOT NULL,
                vendor_id INTEGER NOT NULL,
                sku TEXT,
                weight_grams REAL,
                shipping_dimensions TEXT,
                is_featured INTEGER DEFAULT 0,
                shipping_methods TEXT,
                shipping_origin TEXT,
                shipping_destinations TEXT NOT NULL,
                visibility TEXT DEFAULT 'public',
                moq INTEGER DEFAULT 1,
                lead_time TEXT,
                packaging_details TEXT,
                tags TEXT,
                product_type TEXT NOT NULL CHECK(product_type IN ('physical', 'digital')),
                return_policy TEXT,
                status TEXT NOT NULL CHECK(status IN ('pending', 'active', 'rejected', 'disabled')) DEFAULT 'pending',
                featured_image TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (category_id) REFERENCES categories(id),
                FOREIGN KEY (vendor_id) REFERENCES users(id)
            )''')
        c.execute('''CREATE TABLE IF NOT EXISTS faq_categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
        c.execute('''CREATE TABLE IF NOT EXISTS faqs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                question TEXT NOT NULL,
                answer TEXT NOT NULL,
                category_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (category_id) REFERENCES faq_categories(id)
            )''')
        c.execute('''INSERT OR IGNORE INTO faq_categories (name) VALUES
                ('Orders'),
                ('Sales'),
                ('Account'),
                ('Vendor'),
                ('Jobs'),
                ('Bugs'),
                ('Deposit'),
                ('Withdrawal'),
                ('Others')''')
        c.execute('''CREATE TABLE IF NOT EXISTS rates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    currency_pair TEXT NOT NULL UNIQUE, -- e.g., 'BTC/USD', 'XMR/USD'
                    rate REAL NOT NULL,                -- e.g., 70000.00
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')
        c.execute('''CREATE TABLE IF NOT EXISTS news (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    admin_id INTEGER NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME,
                    FOREIGN KEY (admin_id) REFERENCES users(id)
                )''')
            
        c.execute('''CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                currency TEXT NOT NULL CHECK(currency IN ('BTC', 'XMR')),
                type TEXT NOT NULL CHECK(type IN ('deposit', 'withdrawal', 'purchase', 'refund')),
                amount DECIMAL(16,8) NOT NULL,
                address TEXT,
                tx_id TEXT,
                status TEXT NOT NULL CHECK(status IN ('pending', 'completed', 'failed')),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )''')

        # Packages table
        c.execute('''CREATE TABLE IF NOT EXISTS packages 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      title TEXT NOT NULL,
                      features TEXT,
                      expires_at TIMESTAMP, 
                      product_limit INTEGER NOT NULL,
                      price_usd REAL NOT NULL,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

        # Vendor payments table
        c.execute('''CREATE TABLE IF NOT EXISTS vendor_payments 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      user_id INTEGER,
                      crypto_type TEXT CHECK(crypto_type IN ('btc', 'xmr')),
                      amount REAL,
                      address TEXT NOT NULL,
                      txid TEXT,
                      status TEXT CHECK(status IN ('pending', 'confirmed', 'failed')) DEFAULT 'pending',
                      encrypted_details TEXT,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      FOREIGN KEY (user_id) REFERENCES users(id))''')

        c.execute('''CREATE TABLE IF NOT EXISTS vendor_subscriptions 
                  (id INTEGER PRIMARY KEY AUTOINCREMENT,
                    vendor_id INTEGER NOT NULL,
                    package_id INTEGER NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('pending', 'active', 'expired')),
                    subscribed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    payment_txid TEXT,  -- Transaction ID for crypto payment
                    FOREIGN KEY (vendor_id) REFERENCES users(id),
                    FOREIGN KEY (package_id) REFERENCES packages(id))''')
        # Orders table
        c.execute('''CREATE TABLE IF NOT EXISTS orders 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      user_id INTEGER NOT NULL,
                      product_id INTEGER NOT NULL,
                      vendor_id INTEGER NOT NULL,
                      amount_usd REAL NOT NULL,
                      amount_btc REAL NOT NULL,
                      status TEXT NOT NULL DEFAULT 'pending',
                      escrow_status TEXT NOT NULL DEFAULT 'held',
                      dispute_status TEXT DEFAULT NULL,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      FOREIGN KEY (user_id) REFERENCES users(id),
                      FOREIGN KEY (product_id) REFERENCES products(id),
                      FOREIGN KEY (vendor_id) REFERENCES users(id)
                      )''')

        # Escrow table
        c.execute('''CREATE TABLE IF NOT EXISTS escrow (
                order_id INTEGER PRIMARY KEY,
                multisig_address TEXT NOT NULL,
                buyer_address TEXT NOT NULL,
                vendor_address TEXT NOT NULL,
                escrow_address TEXT NOT NULL,
                amount_usd REAL NOT NULL,
                amount_btc REAL NOT NULL,
                crypto_currency TEXT DEFAULT 'BTC',
                status TEXT DEFAULT 'pending',
                txid TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (order_id) REFERENCES orders(id))''')

        # User settings table
        c.execute('''CREATE TABLE IF NOT EXISTS user_settings 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      user_id INTEGER UNIQUE,
                      theme TEXT DEFAULT 'dark',
                      currency TEXT DEFAULT 'USD',
                      notifications INTEGER DEFAULT 1,
                      two_factor_enabled INTEGER DEFAULT 0,
                      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      FOREIGN KEY (user_id) REFERENCES users(id))''')

        # Reviews table
        c.execute('''CREATE TABLE IF NOT EXISTS reviews 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      user_id INTEGER,
                      product_id INTEGER,
                      rating INTEGER CHECK (rating >= 1 AND rating <= 5),
                      comment TEXT,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      FOREIGN KEY (user_id) REFERENCES users(id),
                      FOREIGN KEY (product_id) REFERENCES products(id))''')
        # Forum Categories
        c.execute('''CREATE TABLE IF NOT EXISTS forum_categories 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      title TEXT NOT NULL,
                      description TEXT,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      created_by INTEGER,
                      FOREIGN KEY (created_by) REFERENCES users(id))''')
        
        # Forum Threads
        c.execute('''CREATE TABLE IF NOT EXISTS forum_threads 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      category_id INTEGER NOT NULL,
                      title TEXT NOT NULL,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      created_by INTEGER NOT NULL,
                      views INTEGER DEFAULT 0,
                      locked INTEGER DEFAULT 0,
                      sticky INTEGER DEFAULT 0,
                      FOREIGN KEY (category_id) REFERENCES forum_categories(id),
                      FOREIGN KEY (created_by) REFERENCES users(id))''')
        
        # Forum Posts
        c.execute('''CREATE TABLE IF NOT EXISTS forum_posts 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      thread_id INTEGER NOT NULL,
                      content TEXT NOT NULL,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      created_by INTEGER NOT NULL,
                      edited_at TIMESTAMP,
                      FOREIGN KEY (thread_id) REFERENCES forum_threads(id),
                      FOREIGN KEY (created_by) REFERENCES users(id))''')
        
        # Vendor subscriptions table
        c.execute('''CREATE TABLE IF NOT EXISTS vendor_subscriptions 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      vendor_id INTEGER,
                      package_id INTEGER,
                      subscribed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      status TEXT DEFAULT 'pending',
                      payment_address TEXT,
                      btc_txid TEXT,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      FOREIGN KEY (vendor_id) REFERENCES users(id),
                      FOREIGN KEY (package_id) REFERENCES packages(id))''')

        # Product images table
        c.execute('''CREATE TABLE IF NOT EXISTS product_images 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      product_id INTEGER,
                      image_path TEXT,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      FOREIGN KEY (product_id) REFERENCES products(id))''')

        # Categories table
        c.execute('''CREATE TABLE IF NOT EXISTS categories 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      name TEXT NOT NULL,
                      description TEXT,
                      featured INTEGER DEFAULT 0,
                      image_path TEXT,
                      parent_id INTEGER,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      FOREIGN KEY (parent_id) REFERENCES categories(id))''')

        # Messages table
        c.execute('''CREATE TABLE IF NOT EXISTS messages 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      sender_id INTEGER NOT NULL,
                      recipient_type TEXT NOT NULL,
                      recipient_id INTEGER,
                      subject TEXT NOT NULL,
                      body TEXT,
                      encrypted_body TEXT,
                      sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      FOREIGN KEY (sender_id) REFERENCES users(id),
                      FOREIGN KEY (recipient_id) REFERENCES users(id))''')

        # Reports table
        c.execute('''CREATE TABLE IF NOT EXISTS reports 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      user_id INTEGER,
                      vendor_id INTEGER,
                      vendor_username TEXT,
                      reason TEXT,
                      evidence TEXT,
                      status TEXT DEFAULT 'pending',
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      FOREIGN KEY (user_id) REFERENCES users(id),
                      FOREIGN KEY (vendor_id) REFERENCES users(id))''')

        # Settings table
        c.execute('''CREATE TABLE IF NOT EXISTS settings 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      key TEXT UNIQUE,
                      value TEXT,
                      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

        # Sponsored ads table
        c.execute('''CREATE TABLE IF NOT EXISTS sponsored_ads 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      vendor_id INTEGER NOT NULL,
                      product_id INTEGER NOT NULL,
                      bid_amount REAL NOT NULL,
                      daily_budget REAL NOT NULL,
                      status TEXT CHECK(status IN ('active', 'paused', 'ended')) DEFAULT 'active',
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      FOREIGN KEY (vendor_id) REFERENCES users(id),
                      FOREIGN KEY (product_id) REFERENCES products(id))''')

        # Ad impressions table
        c.execute('''CREATE TABLE IF NOT EXISTS ad_impressions 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      ad_id INTEGER NOT NULL,
                      product_id INTEGER NOT NULL,
                      impression_count INTEGER DEFAULT 0,
                      click_count INTEGER DEFAULT 0,
                      cost REAL DEFAULT 0.0,
                      date DATE DEFAULT CURRENT_DATE,
                      FOREIGN KEY (ad_id) REFERENCES sponsored_ads(id),
                      FOREIGN KEY (product_id) REFERENCES products(id))''')

        # Ad payments table
        c.execute('''CREATE TABLE IF NOT EXISTS ad_payments 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      vendor_id INTEGER NOT NULL,
                      amount REAL NOT NULL, 
                      status TEXT CHECK(status IN ('pending', 'completed', 'failed')) DEFAULT 'pending',
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      FOREIGN KEY (vendor_id) REFERENCES users(id))''')

        # Tickets table
        c.execute('''CREATE TABLE IF NOT EXISTS tickets 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      user_id INTEGER NOT NULL,
                      subject TEXT NOT NULL,
                      description TEXT NOT NULL,
                      category TEXT NOT NULL DEFAULT 'General',
                      priority TEXT NOT NULL DEFAULT 'Medium',
                      status TEXT NOT NULL DEFAULT 'open',
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      FOREIGN KEY (user_id) REFERENCES users(id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS vendor_wallets 
                  (vendor_id INTEGER PRIMARY KEY,
                    balance_usd REAL DEFAULT 0.0,
                    FOREIGN KEY (vendor_id) REFERENCES users(id))''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS withdrawals 
                  (id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    amount_usd REAL NOT NULL,
                    crypto_currency TEXT NOT NULL CHECK(crypto_currency IN ('XMR', 'BTC')),
                    crypto_amount REAL NOT NULL,
                    wallet_address TEXT NOT NULL,
                    status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'processed', 'failed')),
                    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    processed_at TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id))''')
        # Ticket responses table
        c.execute('''CREATE TABLE IF NOT EXISTS ticket_responses 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      ticket_id INTEGER NOT NULL,
                      sender_id INTEGER NOT NULL,
                      body TEXT,
                      encrypted_body TEXT,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      FOREIGN KEY (ticket_id) REFERENCES tickets(id),
                      FOREIGN KEY (sender_id) REFERENCES users(id))''')
        #c.execute("ALTER TABLE orders ADD COLUMN vendor_earnings_usd REAL DEFAULT 0.0")
        # Add indexes for performance
        c.execute("CREATE INDEX IF NOT EXISTS idx_orders_user_id ON orders(user_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_messages_sender_recipient ON messages(sender_id, recipient_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_products_vendor_id ON products(vendor_id)")
        #c.execute("ALTER TABLE packages ADD COLUMN  expires_at TIMESTAMP")
        
        # Fix image paths (consistent separators)
        c.execute("UPDATE products SET featured_image = REPLACE(featured_image, '\\', '/') WHERE featured_image LIKE '%\\%'")
        c.execute("UPDATE product_images SET image_path = REPLACE(image_path, '\\', '/') WHERE image_path LIKE '%\\%'")
        c.execute('''CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id))''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS balances (
                user_id INTEGER PRIMARY KEY,
                balance_usd REAL NOT NULL DEFAULT 0.0,
                balance_btc REAL NOT NULL DEFAULT 0.0,
                balance_xmr REAL NOT NULL DEFAULT 0.0,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )''')
        c.execute('''CREATE TABLE IF NOT EXISTS fees (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fee_type TEXT NOT NULL UNIQUE,
                percentage REAL NOT NULL CHECK(percentage >= 0 AND percentage <= 100),
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
        # Insert initial order fee (5%)
       
        # Insert default settings
        c.execute("SELECT COUNT(*) FROM settings")
        if c.fetchone()[0] == 0:
            defaults = [
                ('site_name', 'Sydney'),
                ('primary_color', '#FA1515FF'),  # Yellow-400
                ('secondary_color', '#1f2937'),  # Gray-800
                ('logo_path', 'images/logo.png'),
                ('meta_title', 'Sydney - Secure Marketplace'),
                ('meta_description', 'A secure and anonymous marketplace for exclusive products.'),
                ('maintenance_mode', '0'),
                ('two_factor_required', '0'),
                ('session_timeout', '30'),  # Minutes
                ('max_login_attempts', '5'),
                ('btc_conversion_enabled', '1'),
                ('min_order_amount_usd', '10.00'),
                ('support_email', 'support@Sydney.onion'),
                ('pgp_key', '')
            ]
            c.executemany("INSERT INTO settings (key, value) VALUES (?, ?)", defaults)

        conn.commit()

def get_product_rating(product_id):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT AVG(rating) as avg_rating, COUNT(*) as review_count FROM reviews WHERE product_id = ?", (product_id,))
        result = c.fetchone()
        return {
            'avg_rating': round(result['avg_rating'], 1) if result['avg_rating'] else 0.0,
            'review_count': result['review_count']
        }
def get_settings():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT key, value FROM settings")
        return dict(c.fetchall())
    
def get_product_count(category_id, category_tree, cursor):
    """Recursively count products in a category and its subcategories."""
    cursor.execute("SELECT COUNT(*) FROM products WHERE category_id = ? AND stock > 0", (category_id,))
    direct_count = cursor.fetchone()[0]
    total_count = direct_count
    for subcategory in category_tree.get(category_id, {}).get('subcategories', []):
        total_count += get_product_count(subcategory['id'], category_tree, cursor)
    return total_count

def get_vendor_btc_address(vendor_id):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT btc_address FROM users WHERE id = ? AND role = 'vendor'", (vendor_id,))
        result = c.fetchone()
        return result['btc_address'] if result else None
    
def get_vendor_settings(vendor_id):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM vendor_settings WHERE user_id = ?", (vendor_id,))
        return c.fetchone()  # Returns None if no settings exist

def get_random_products(limit=6):
    """Fetch random products with enriched data."""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            # Check if qualifying products exist
            c.execute("""
                SELECT COUNT(*) as count
                FROM products p
                LEFT JOIN users u ON p.vendor_id = u.id
                WHERE u.role = 'vendor' AND p.stock > 0 AND p.status = 'active'
            """)
            count = c.fetchone()['count']
            logger.info(f"Found {count} qualifying random products")

            c.execute("""
                SELECT p.*, u.pusername as vendor_username
                FROM products p
                LEFT JOIN users u ON p.vendor_id = u.id
                WHERE u.role = 'vendor' AND p.stock > 0 AND p.status = 'active'
                ORDER BY RANDOM()
                LIMIT ?
            """, (limit,))
            products = c.fetchall()
            logger.info(f"Fetched {len(products)} random products: {[dict(p)['id'] for p in products]}")

            enriched_products = []
            for product in products:
                product_dict = dict(product)

                c.execute("SELECT name FROM categories WHERE id = ?", (product['category_id'],))
                category = c.fetchone()
                if category:
                    product_dict['category_name'] = category['name']
                else:
                    product_dict['category_name'] = 'Unknown Category'
                    logger.warning(f"No category found for category_id {product['category_id']}")

                c.execute("""
                    SELECT COUNT(*) as total, SUM(CASE WHEN rating >= 4 THEN 1 ELSE 0 END) as positive
                    FROM reviews r
                    JOIN products p ON r.product_id = p.id
                    WHERE p.vendor_id = ?
                """, (product['vendor_id'],))
                feedback = c.fetchone()
                product_dict['feedback_percentage'] = (feedback['positive'] / feedback['total'] * 100) if feedback['total'] > 0 else 0.0

                c.execute("""
                    SELECT COUNT(*) as count
                    FROM orders
                    WHERE vendor_id = ? AND status = 'completed'
                """, (product['vendor_id'],))
                sales_count = c.fetchone()
                product_dict['sales_count'] = sales_count['count'] if sales_count else 0

                c.execute("SELECT level FROM vendor_levels WHERE vendor_id = ?", (product['vendor_id'],))
                vendor_level = c.fetchone()
                product_dict['vendor_level'] = vendor_level['level'] if vendor_level else 1

                enriched_products.append(product_dict)

            logger.info(f"Enriched {len(enriched_products)} random products")
            return enriched_products
    except Exception as e:
        logger.error(f"Error fetching random products: {str(e)}")
        return []

def get_featured_products(limit=6):
    """Fetch admin-selected featured products with enriched data."""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            # Check if qualifying products exist
            c.execute("""
                SELECT COUNT(*) as count
                FROM products p
                LEFT JOIN users u ON p.vendor_id = u.id
                WHERE u.role = 'vendor' AND p.stock > 0 AND p.status = 'active' AND p.is_featured = 1
            """)
            count = c.fetchone()['count']
            logger.info(f"Found {count} qualifying featured products")

            c.execute("""
                SELECT p.*, u.pusername as vendor_username
                FROM products p
                LEFT JOIN users u ON p.vendor_id = u.id
                WHERE u.role = 'vendor' AND p.stock > 0 AND p.status = 'active' AND p.is_featured = 1
                ORDER BY p.created_at DESC
                LIMIT ?
            """, (limit,))
            products = c.fetchall()
            logger.info(f"Fetched {len(products)} featured products: {[dict(p)['id'] for p in products]}")

            enriched_products = []
            for product in products:
                product_dict = dict(product)

                c.execute("SELECT name FROM categories WHERE id = ?", (product['category_id'],))
                category = c.fetchone()
                if category:
                    product_dict['category_name'] = category['name']
                else:
                    product_dict['category_name'] = 'Unknown Category'
                    logger.warning(f"No category found for category_id {product['category_id']}")

                c.execute("""
                    SELECT COUNT(*) as total, SUM(CASE WHEN rating >= 4 THEN 1 ELSE 0 END) as positive
                    FROM reviews r
                    JOIN products p ON r.product_id = p.id
                    WHERE p.vendor_id = ?
                """, (product['vendor_id'],))
                feedback = c.fetchone()
                product_dict['feedback_percentage'] = (feedback['positive'] / feedback['total'] * 100) if feedback['total'] > 0 else 0.0

                c.execute("""
                    SELECT COUNT(*) as count
                    FROM orders
                    WHERE vendor_id = ? AND status = 'completed'
                """, (product['vendor_id'],))
                sales_count = c.fetchone()
                product_dict['sales_count'] = sales_count['count'] if sales_count else 0

                c.execute("SELECT level FROM vendor_levels WHERE vendor_id = ?", (product['vendor_id'],))
                vendor_level = c.fetchone()
                product_dict['vendor_level'] = vendor_level['level'] if vendor_level else 1

                enriched_products.append(product_dict)

            logger.info(f"Enriched {len(enriched_products)} featured products")
            return enriched_products
    except Exception as e:
        logger.error(f"Error fetching featured products: {str(e)}")
        return []  
def get_settings():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT key, value FROM settings")
        return dict(c.fetchall())
    
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()
        
def get_rates():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT currency_pair, rate, updated_at FROM rates ORDER BY currency_pair")
    rates = {row['currency_pair']: {'rate': row['rate'], 'updated_at': row['updated_at']} 
             for row in c.fetchall()}
    return rates

def update_rates():
    # Fetch rates from CoinGecko API
    url = "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,monero&vs_currencies=usd"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()
        
        rates = {
            'BTC/USD': data.get('bitcoin', {}).get('usd', 0.0),
            'XMR/USD': data.get('monero', {}).get('usd', 0.0)
        }
        
        # Update database
        conn = get_db_connection()
        c = conn.cursor()
        for currency_pair, rate in rates.items():
            c.execute("""
                INSERT OR REPLACE INTO rates (currency_pair, rate, updated_at)
                VALUES (?, ?, ?)
            """, (currency_pair, rate, datetime.utcnow().isoformat()))
        conn.commit()
        return rates
    except (requests.RequestException, ValueError) as e:
        print(f"Error updating rates: {e}")
        return get_rates()  # Return cached rates on failure