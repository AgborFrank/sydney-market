#!/usr/bin/env python3
"""
Test script to debug vendor level update issues above level 5
"""

import sqlite3
import os
from datetime import datetime

def test_vendor_level_update():
    """Test vendor level updates above level 5"""
    
    # Connect to the database
    db_path = 'marketplace.db'
    if not os.path.exists(db_path):
        print(f"Database file {db_path} not found.")
        return
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        print("🔍 Testing vendor level updates above level 5...")
        
        # Test 1: Check if we can find a vendor
        cursor.execute("""
            SELECT u.id, u.pusername, vl.level, vl.sales_count, vl.positive_feedback_percentage
            FROM users u
            LEFT JOIN vendor_levels vl ON u.id = vl.vendor_id
            WHERE u.role = 'vendor'
            LIMIT 1
        """)
        vendor = cursor.fetchone()
        
        if not vendor:
            print("❌ No vendors found in database")
            return
        
        vendor_id = vendor['id']
        print(f"✅ Found vendor: {vendor['pusername']} (ID: {vendor_id})")
        print(f"   Current level: {vendor['level'] or 'N/A'}")
        
        # Test 2: Try to update to level 6
        print(f"\n🔄 Testing update to level 6...")
        try:
            cursor.execute("""
                UPDATE vendor_levels
                SET level = ?, updated_at = ?
                WHERE vendor_id = ?
            """, (6, datetime.utcnow(), vendor_id))
            
            # Also update users.level for consistency
            cursor.execute("UPDATE users SET level = ? WHERE id = ?", (6, vendor_id))
            
            # Log the change
            cursor.execute("""
                INSERT INTO vendor_level_logs (vendor_id, old_level, new_level, reason)
                VALUES (?, ?, ?, ?)
            """, (vendor_id, vendor['level'] or 1, 6, 'Test update to level 6'))
            
            conn.commit()
            print("✅ Successfully updated to level 6")
            
        except Exception as e:
            print(f"❌ Error updating to level 6: {e}")
            conn.rollback()
            return
        
        # Test 3: Try to update to level 7
        print(f"\n🔄 Testing update to level 7...")
        try:
            cursor.execute("""
                UPDATE vendor_levels
                SET level = ?, updated_at = ?
                WHERE vendor_id = ?
            """, (7, datetime.utcnow(), vendor_id))
            
            cursor.execute("UPDATE users SET level = ? WHERE id = ?", (7, vendor_id))
            
            cursor.execute("""
                INSERT INTO vendor_level_logs (vendor_id, old_level, new_level, reason)
                VALUES (?, ?, ?, ?)
            """, (vendor_id, 6, 7, 'Test update to level 7'))
            
            conn.commit()
            print("✅ Successfully updated to level 7")
            
        except Exception as e:
            print(f"❌ Error updating to level 7: {e}")
            conn.rollback()
            return
        
        # Test 4: Try to update to level 8
        print(f"\n🔄 Testing update to level 8...")
        try:
            cursor.execute("""
                UPDATE vendor_levels
                SET level = ?, updated_at = ?
                WHERE vendor_id = ?
            """, (8, datetime.utcnow(), vendor_id))
            
            cursor.execute("UPDATE users SET level = ? WHERE id = ?", (8, vendor_id))
            
            cursor.execute("""
                INSERT INTO vendor_level_logs (vendor_id, old_level, new_level, reason)
                VALUES (?, ?, ?, ?)
            """, (vendor_id, 7, 8, 'Test update to level 8'))
            
            conn.commit()
            print("✅ Successfully updated to level 8")
            
        except Exception as e:
            print(f"❌ Error updating to level 8: {e}")
            conn.rollback()
            return
        
        # Test 5: Try to update to level 9
        print(f"\n🔄 Testing update to level 9...")
        try:
            cursor.execute("""
                UPDATE vendor_levels
                SET level = ?, updated_at = ?
                WHERE vendor_id = ?
            """, (9, datetime.utcnow(), vendor_id))
            
            cursor.execute("UPDATE users SET level = ? WHERE id = ?", (9, vendor_id))
            
            cursor.execute("""
                INSERT INTO vendor_level_logs (vendor_id, old_level, new_level, reason)
                VALUES (?, ?, ?, ?)
            """, (vendor_id, 8, 9, 'Test update to level 9'))
            
            conn.commit()
            print("✅ Successfully updated to level 9")
            
        except Exception as e:
            print(f"❌ Error updating to level 9: {e}")
            conn.rollback()
            return
        
        # Test 6: Try to update to level 10
        print(f"\n🔄 Testing update to level 10...")
        try:
            cursor.execute("""
                UPDATE vendor_levels
                SET level = ?, updated_at = ?
                WHERE vendor_id = ?
            """, (10, datetime.utcnow(), vendor_id))
            
            cursor.execute("UPDATE users SET level = ? WHERE id = ?", (10, vendor_id))
            
            cursor.execute("""
                INSERT INTO vendor_level_logs (vendor_id, old_level, new_level, reason)
                VALUES (?, ?, ?, ?)
            """, (vendor_id, 9, 10, 'Test update to level 10'))
            
            conn.commit()
            print("✅ Successfully updated to level 10")
            
        except Exception as e:
            print(f"❌ Error updating to level 10: {e}")
            conn.rollback()
            return
        
        # Test 7: Verify the final state
        cursor.execute("""
            SELECT u.id, u.pusername, vl.level, vl.sales_count, vl.positive_feedback_percentage
            FROM users u
            LEFT JOIN vendor_levels vl ON u.id = vl.vendor_id
            WHERE u.id = ?
        """, (vendor_id,))
        
        final_vendor = cursor.fetchone()
        print(f"\n📊 Final vendor state:")
        print(f"   Level: {final_vendor['level']}")
        print(f"   Sales: {final_vendor['sales_count']}")
        print(f"   Feedback: {final_vendor['positive_feedback_percentage']}%")
        
        # Test 8: Check level logs
        cursor.execute("""
            SELECT old_level, new_level, reason, created_at
            FROM vendor_level_logs
            WHERE vendor_id = ?
            ORDER BY created_at DESC
            LIMIT 5
        """, (vendor_id,))
        
        logs = cursor.fetchall()
        print(f"\n📝 Recent level changes:")
        for log in logs:
            print(f"   {log['old_level']} → {log['new_level']}: {log['reason']} ({log['created_at']})")
        
        print("\n🎉 All tests completed successfully!")
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    test_vendor_level_update() 