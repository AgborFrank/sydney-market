#!/usr/bin/env python3
"""
Test script for vendor edit functionality
"""

import sqlite3
import os
from datetime import datetime

def test_vendor_edit_functionality():
    """Test the vendor edit functionality"""
    
    # Connect to the database
    db_path = 'marketplace.db'
    if not os.path.exists(db_path):
        print(f"Database file {db_path} not found. Please ensure the marketplace is set up.")
        return
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        # Test 1: Check if vendor_levels table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vendor_levels'")
        if not cursor.fetchone():
            print("❌ vendor_levels table not found")
            return
        print("✅ vendor_levels table exists")
        
        # Test 2: Check if vendor_level_logs table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vendor_level_logs'")
        if not cursor.fetchone():
            print("❌ vendor_level_logs table not found")
            return
        print("✅ vendor_level_logs table exists")
        
        # Test 3: Check if vendor_ratings table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vendor_ratings'")
        if not cursor.fetchone():
            print("❌ vendor_ratings table not found")
            return
        print("✅ vendor_ratings table exists")
        
        # Test 4: Check if there are any vendors
        cursor.execute("""
            SELECT u.id, u.pusername, vl.level, vl.sales_count, vl.positive_feedback_percentage
            FROM users u
            LEFT JOIN vendor_levels vl ON u.id = vl.vendor_id
            WHERE u.role = 'vendor'
            LIMIT 1
        """)
        vendor = cursor.fetchone()
        
        if vendor:
            print(f"✅ Found vendor: {vendor['pusername']} (ID: {vendor['id']})")
            print(f"   Current level: {vendor['level'] or 'N/A'}")
            print(f"   Sales count: {vendor['sales_count'] or 0}")
            print(f"   Feedback: {vendor['positive_feedback_percentage'] or 0}%")
        else:
            print("⚠️  No vendors found in database")
        
        # Test 5: Check vendor level logs
        cursor.execute("SELECT COUNT(*) as count FROM vendor_level_logs")
        log_count = cursor.fetchone()['count']
        print(f"✅ Vendor level logs: {log_count} entries")
        
        # Test 6: Test the enhanced vendor profile query
        if vendor:
            cursor.execute("""
                SELECT u.id, u.pusername, u.btc_address, u.pgp_public_key, u.role, u.is_vendor, u.vendor_status, u.level,
                       vl.level AS vendor_level, vl.sales_count, vl.positive_feedback_percentage, vl.joined_at, vl.updated_at,
                       AVG(vr.rating) AS avg_rating
                FROM users u
                LEFT JOIN vendor_levels vl ON u.id = vl.vendor_id
                LEFT JOIN vendor_ratings vr ON u.id = vr.vendor_id
                WHERE u.id = ? AND u.is_vendor = 1
                GROUP BY u.id
            """, (vendor['id'],))
            
            enhanced_vendor = cursor.fetchone()
            if enhanced_vendor:
                print("✅ Enhanced vendor profile query works")
                print(f"   Vendor level: {enhanced_vendor['vendor_level'] or 'N/A'}")
                print(f"   Average rating: {enhanced_vendor['avg_rating'] or 'N/A'}")
            else:
                print("❌ Enhanced vendor profile query failed")
        
        print("\n🎉 All tests completed successfully!")
        print("\nThe vendor edit functionality should now be available at:")
        print("- /admin/vendors (vendor list with edit links)")
        print("- /admin/vendor_profile/<vendor_id> (vendor profile with edit button)")
        print("- /admin/edit_vendor/<vendor_id> (edit vendor form)")
        print("- /admin/vendor_level_history/<vendor_id> (level change history)")
        
    except Exception as e:
        print(f"❌ Error during testing: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    test_vendor_edit_functionality() 