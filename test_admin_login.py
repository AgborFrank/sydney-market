#!/usr/bin/env python3
"""
Test admin login functionality
"""

import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.database import get_db_connection, get_settings

def test_admin_login_settings():
    """Test admin login settings"""
    print("🔧 Testing Admin Login Settings")
    print("=" * 50)
    
    try:
        # Check current settings
        settings = get_settings()
        admin_login_captcha = settings.get('admin_login_captcha', 'enabled')
        print(f"   Admin login CAPTCHA setting: {admin_login_captcha}")
        
        # Check if setting exists in database
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT value FROM security_settings WHERE setting_name = 'admin_login_captcha'")
            result = c.fetchone()
            
            if result:
                print(f"   Database value: {result['value']}")
                return True
            else:
                print("   ❌ Setting not found in database")
                return False
                
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

def test_admin_users():
    """Test if admin users exist"""
    print("\n👥 Testing Admin Users")
    print("=" * 50)
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT id, username, role FROM users WHERE role = 'admin'")
            admins = c.fetchall()
            
            if admins:
                print(f"   Found {len(admins)} admin user(s):")
                for admin in admins:
                    print(f"      - {admin['username']} (ID: {admin['id']})")
                return True
            else:
                print("   ❌ No admin users found")
                return False
                
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Admin Login Test Suite")
    print("=" * 60)
    
    # Run tests
    test1_passed = test_admin_login_settings()
    test2_passed = test_admin_users()
    
    print("\n" + "=" * 60)
    print("📊 Test Results:")
    print(f"   Admin Login Settings: {'✅ PASSED' if test1_passed else '❌ FAILED'}")
    print(f"   Admin Users: {'✅ PASSED' if test2_passed else '❌ FAILED'}")
    
    if test1_passed and test2_passed:
        print("\n🎉 Basic admin setup looks good!")
        print("\n💡 To test admin login:")
        print("   1. Start the Flask app")
        print("   2. Go to /admin/login")
        print("   3. Try logging in with admin credentials")
        sys.exit(0)
    else:
        print("\n💥 Some tests failed. Please check the setup.")
        sys.exit(1) 