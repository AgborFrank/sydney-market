import sqlite3

def get_db_connection():
    conn = sqlite3.connect('marketplace.db')
    conn.row_factory = sqlite3.Row
    return conn

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
                DROP TABLE IF EXISTS ticket_responses;
                ALTER TABLE vendor_subscriptions;
              
            ''')

        # Users table (no vendor-specific fields)
        c.execute('''CREATE TABLE IF NOT EXISTS users 
             (id INTEGER PRIMARY KEY AUTOINCREMENT,
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
              session_timeout TEXT DEFAULT '30',
              profile_visibility TEXT DEFAULT 'public',
              notify_messages INTEGER DEFAULT 1,
              notify_orders INTEGER DEFAULT 1,
              pgp_public_key TEXT,
              pgp_private_key BLOB,
              created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
        c.execute('''CREATE TABLE IF NOT EXISTS cart 
            (user_id INTEGER,
            product_id INTEGER,
            quantity INTEGER,
            PRIMARY KEY (user_id, product_id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
            )''')
        # Disputes table
        c.execute('''CREATE TABLE IF NOT EXISTS disputes 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      order_id INTEGER,
                      reason TEXT,
                      status TEXT DEFAULT 'open',
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      FOREIGN KEY (order_id) REFERENCES orders(id))''')

        # Favorites table
        c.execute('''CREATE TABLE IF NOT EXISTS favorites 
                     (user_id INTEGER,
                      product_id INTEGER,
                      PRIMARY KEY (user_id, product_id),
                      FOREIGN KEY (user_id) REFERENCES users(id),
                      FOREIGN KEY (product_id) REFERENCES products(id))''')

        # Products table
        c.execute('''CREATE TABLE IF NOT EXISTS products 
                  (id INTEGER PRIMARY KEY AUTOINCREMENT,
              title TEXT NOT NULL,
              description TEXT,
              price_usd REAL NOT NULL,
              stock INTEGER NOT NULL,
              category_id INTEGER NOT NULL,
              vendor_id INTEGER NOT NULL,
              featured_image TEXT,
              sku TEXT UNIQUE,
              shipping_weight REAL,
              shipping_dimensions TEXT,
              shipping_method TEXT,
              moq INTEGER DEFAULT 1,
              lead_time TEXT,
              packaging_details TEXT,
              tags TEXT,
              original_price_usd REAL,
              discount_active BOOLEAN DEFAULT 0,
              status TEXT DEFAULT 'active',
              created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
              FOREIGN KEY (category_id) REFERENCES categories(id),
              FOREIGN KEY (vendor_id) REFERENCES users(id))''')

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
                      vendor_id INTEGER,
                      amount_usd REAL,
                      btc_txid TEXT,
                      status TEXT DEFAULT 'pending',
                      encrypted_details TEXT,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      FOREIGN KEY (vendor_id) REFERENCES users(id))''')

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
        c.execute('''CREATE TABLE IF NOT EXISTS escrow 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      order_id INTEGER,
                      multisig_address TEXT,
                      buyer_address TEXT,
                      vendor_address TEXT,
                      escrow_address TEXT,
                      amount_usd REAL,
                      txid TEXT,
                      status TEXT DEFAULT 'pending',
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
                    vendor_id INTEGER,
                    amount_usd REAL NOT NULL,
                    crypto_currency TEXT NOT NULL CHECK(crypto_currency IN ('XMR', 'BTC')),
                    crypto_amount REAL NOT NULL,
                    wallet_address TEXT NOT NULL,
                    status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'processed', 'failed')),
                    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    processed_at TIMESTAMP,
                    FOREIGN KEY (vendor_id) REFERENCES users(id))''')
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

        # Insert default settings
        c.execute("SELECT COUNT(*) FROM settings")
        if c.fetchone()[0] == 0:
            defaults = [
                ('site_name', 'DarkVault'),
                ('primary_color', '#facc15'),  # Yellow-400
                ('secondary_color', '#1f2937'),  # Gray-800
                ('logo_path', '/static/uploads/logos/default_logo.png'),
                ('meta_title', 'DarkVault - Secure Marketplace'),
                ('meta_description', 'A secure and anonymous marketplace for exclusive products.'),
                ('maintenance_mode', '0'),
                ('two_factor_required', '0'),
                ('session_timeout', '30'),  # Minutes
                ('max_login_attempts', '5'),
                ('btc_conversion_enabled', '1'),
                ('min_order_amount_usd', '10.00'),
                ('support_email', 'support@darkvault.onion'),
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
    
def get_settings():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT key, value FROM settings")
        return dict(c.fetchall())