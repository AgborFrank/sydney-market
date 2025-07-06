#!/usr/bin/env python3
"""
Test script to verify search functionality with category names and images
"""

import sqlite3
import os
from datetime import datetime

def test_search_functionality():
    """Test the search functionality to ensure category names and images are working"""
    
    # Connect to the database
    db_path = 'marketplace.db'
    if not os.path.exists(db_path):
        print(f"Database file {db_path} not found!")
        return False
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        print("🔍 Testing Search Functionality...")
        print("=" * 50)
        
        # Test 1: Check if categories table has data
        print("\n1. Checking categories table...")
        cursor.execute("SELECT COUNT(*) as count FROM categories")
        category_count = cursor.fetchone()['count']
        print(f"   Found {category_count} categories")
        
        if category_count > 0:
            cursor.execute("SELECT id, name FROM categories LIMIT 5")
            categories = cursor.fetchall()
            print("   Sample categories:")
            for cat in categories:
                print(f"     - {cat['id']}: {cat['name']}")
        
        # Test 2: Check if products table has data with category_id
        print("\n2. Checking products table...")
        cursor.execute("SELECT COUNT(*) as count FROM products")
        product_count = cursor.fetchone()['count']
        print(f"   Found {product_count} products")
        
        if product_count > 0:
            cursor.execute("""
                SELECT p.id, p.title, p.category_id, c.name as category_name
                FROM products p
                LEFT JOIN categories c ON p.category_id = c.id
                LIMIT 5
            """)
            products = cursor.fetchall()
            print("   Sample products with categories:")
            for prod in products:
                category_name = prod['category_name'] if prod['category_name'] else 'No Category'
                print(f"     - {prod['id']}: {prod['title']} (Category: {category_name})")
        
        # Test 3: Check if product_images table has data
        print("\n3. Checking product_images table...")
        cursor.execute("SELECT COUNT(*) as count FROM product_images")
        image_count = cursor.fetchone()['count']
        print(f"   Found {image_count} product images")
        
        if image_count > 0:
            cursor.execute("""
                SELECT pi.product_id, pi.image_path, p.title
                FROM product_images pi
                LEFT JOIN products p ON pi.product_id = p.id
                LIMIT 5
            """)
            images = cursor.fetchall()
            print("   Sample product images:")
            for img in images:
                print(f"     - Product {img['product_id']} ({img['title']}): {img['image_path']}")
        
        # Test 4: Test the actual search query
        print("\n4. Testing search query...")
        search_sql = """
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
            GROUP BY p.id
            ORDER BY p.created_at DESC
            LIMIT 3
        """
        
        cursor.execute(search_sql)
        search_results = cursor.fetchall()
        print(f"   Search query returned {len(search_results)} results")
        
        for i, product in enumerate(search_results, 1):
            print(f"\n   Product {i}:")
            print(f"     - ID: {product['id']}")
            print(f"     - Title: {product['title']}")
            print(f"     - Category: {product['category_name'] or 'No Category'}")
            print(f"     - Vendor: {product['vendor_username'] or 'No Vendor'}")
            print(f"     - Price: ${product['price_usd'] or 0}")
            print(f"     - Stock: {product['stock'] or 0}")
            
            # Check for images
            cursor.execute("SELECT image_path FROM product_images WHERE product_id = ? ORDER BY created_at ASC LIMIT 1", (product['id'],))
            img = cursor.fetchone()
            if img and img['image_path']:
                print(f"     - Image: {img['image_path']}")
            elif product.get('featured_image'):
                print(f"     - Featured Image: {product['featured_image']}")
            else:
                print(f"     - Image: No image found")
        
        # Test 5: Check for any products without category names
        print("\n5. Checking for products without category names...")
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            WHERE c.name IS NULL AND p.category_id IS NOT NULL
        """)
        orphaned_count = cursor.fetchone()['count']
        print(f"   Found {orphaned_count} products with missing category names")
        
        if orphaned_count > 0:
            cursor.execute("""
                SELECT p.id, p.title, p.category_id
                FROM products p
                LEFT JOIN categories c ON p.category_id = c.id
                WHERE c.name IS NULL AND p.category_id IS NOT NULL
                LIMIT 5
            """)
            orphaned = cursor.fetchall()
            print("   Sample orphaned products:")
            for prod in orphaned:
                print(f"     - {prod['id']}: {prod['title']} (category_id: {prod['category_id']})")
        
        print("\n" + "=" * 50)
        print("✅ Search functionality test completed!")
        
        return True
        
    except Exception as e:
        print(f"❌ Error during testing: {str(e)}")
        return False
    
    finally:
        conn.close()

if __name__ == "__main__":
    test_search_functionality() 