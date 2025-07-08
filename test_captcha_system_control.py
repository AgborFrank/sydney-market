#!/usr/bin/env python3
"""
Test script to verify CAPTCHA system control functionality
"""

import sqlite3
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.database import get_db_connection, get_settings
from utils.captcha import get_captcha_system_status, is_captcha_required

def test_captcha_system_control():
    """Test the CAPTCHA system control functionality"""
    print("🧪 Testing CAPTCHA System Control")
    print("=" * 50)
    
    try:
        # Test 1: Check current CAPTCHA system status
        print("\n1. Checking current CAPTCHA system status...")
        status = get_captcha_system_status()
        print(f"   Current status: {status}")
        
        # Test 2: Check settings in database
        print("\n2. Checking database settings...")
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT setting_name, value FROM security_settings WHERE setting_name = 'captcha_system_enabled'")
            result = c.fetchone()
            if result:
                print(f"   Database setting: {result['setting_name']} = {result['value']}")
            else:
                print("   ❌ CAPTCHA system setting not found in database")
                return False
        
        # Test 3: Test enabling CAPTCHA system
        print("\n3. Testing CAPTCHA system enable...")
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("UPDATE security_settings SET value = 'enabled' WHERE setting_name = 'captcha_system_enabled'")
            conn.commit()
        
        status_after_enable = get_captcha_system_status()
        print(f"   Status after enabling: {status_after_enable}")
        
        # Test 4: Test disabling CAPTCHA system
        print("\n4. Testing CAPTCHA system disable...")
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("UPDATE security_settings SET value = 'disabled' WHERE setting_name = 'captcha_system_enabled'")
            conn.commit()
        
        status_after_disable = get_captcha_system_status()
        print(f"   Status after disabling: {status_after_disable}")
        
        # Test 5: Restore original setting
        print("\n5. Restoring original setting...")
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("UPDATE security_settings SET value = ? WHERE setting_name = 'captcha_system_enabled'", (status,))
            conn.commit()
        
        final_status = get_captcha_system_status()
        print(f"   Final status: {final_status}")
        
        # Test 6: Verify the setting is working correctly
        print("\n6. Verifying functionality...")
        if status_after_enable == 'enabled' and status_after_disable == 'disabled':
            print("   ✅ CAPTCHA system control is working correctly")
            return True
        else:
            print("   ❌ CAPTCHA system control is not working correctly")
            return False
            
    except Exception as e:
        print(f"   ❌ Error during testing: {e}")
        return False

def test_admin_settings_access():
    """Test that admin can access the CAPTCHA setting"""
    print("\n🔧 Testing Admin Settings Access")
    print("=" * 50)
    
    try:
        # Check if the setting appears in admin settings
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT setting_name, value, description FROM security_settings WHERE setting_name = 'captcha_system_enabled'")
            result = c.fetchone()
            
            if result:
                print(f"   ✅ Setting found in admin panel:")
                print(f"      Name: {result['setting_name']}")
                print(f"      Value: {result['value']}")
                print(f"      Description: {result['description']}")
                return True
            else:
                print("   ❌ Setting not found in admin panel")
                return False
                
    except Exception as e:
        print(f"   ❌ Error checking admin settings: {e}")
        return False

if __name__ == "__main__":
    print("🚀 CAPTCHA System Control Test Suite")
    print("=" * 60)
    
    # Run tests
    test1_passed = test_captcha_system_control()
    test2_passed = test_admin_settings_access()
    
    print("\n" + "=" * 60)
    print("📊 Test Results:")
    print(f"   CAPTCHA System Control: {'✅ PASSED' if test1_passed else '❌ FAILED'}")
    print(f"   Admin Settings Access: {'✅ PASSED' if test2_passed else '❌ FAILED'}")
    
    if test1_passed and test2_passed:
        print("\n🎉 All tests passed! CAPTCHA system control is working correctly.")
        sys.exit(0)
    else:
        print("\n💥 Some tests failed. Please check the implementation.")
        sys.exit(1) 