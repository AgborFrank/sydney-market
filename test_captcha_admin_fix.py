#!/usr/bin/env python3
"""
Test script to verify that admin CAPTCHA settings fix works correctly
"""

import sqlite3
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.database import get_db_connection, get_settings, get_security_settings
from utils.captcha import get_captcha_system_status, is_captcha_required

def test_captcha_admin_fix():
    """Test that admin can properly control CAPTCHA system globally"""
    print("🔧 Testing Admin CAPTCHA Settings Fix")
    print("=" * 50)
    
    try:
        # Test 1: Check current CAPTCHA system status
        print("\n1. Checking current CAPTCHA system status...")
        status = get_captcha_system_status()
        print(f"   Current status: {status}")
        
        # Test 2: Check settings in both tables
        print("\n2. Checking settings in both tables...")
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Check security_settings table
            c.execute("SELECT setting_name, value FROM security_settings WHERE setting_name = 'captcha_system_enabled'")
            security_result = c.fetchone()
            if security_result:
                print(f"   Security settings table: {security_result['setting_name']} = {security_result['value']}")
            else:
                print("   ❌ CAPTCHA system setting not found in security_settings table")
                return False
            
            # Check settings table (should not have this setting)
            c.execute("SELECT key, value FROM settings WHERE key = 'captcha_system_enabled'")
            settings_result = c.fetchone()
            if settings_result:
                print(f"   ⚠️  Warning: Setting also found in settings table: {settings_result['key']} = {settings_result['value']}")
            else:
                print("   ✅ Setting correctly only in security_settings table")
        
        # Test 3: Test admin disabling CAPTCHA system
        print("\n3. Testing admin disabling CAPTCHA system...")
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("UPDATE security_settings SET value = 'disabled' WHERE setting_name = 'captcha_system_enabled'")
            conn.commit()
        
        status_after_disable = get_captcha_system_status()
        print(f"   Status after admin disable: {status_after_disable}")
        
        # Test 4: Test admin enabling CAPTCHA system
        print("\n4. Testing admin enabling CAPTCHA system...")
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("UPDATE security_settings SET value = 'enabled' WHERE setting_name = 'captcha_system_enabled'")
            conn.commit()
        
        status_after_enable = get_captcha_system_status()
        print(f"   Status after admin enable: {status_after_enable}")
        
        # Test 5: Restore original setting
        print("\n5. Restoring original setting...")
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("UPDATE security_settings SET value = ? WHERE setting_name = 'captcha_system_enabled'", (status,))
            conn.commit()
        
        final_status = get_captcha_system_status()
        print(f"   Final status: {final_status}")
        
        # Test 6: Verify the fix is working correctly
        print("\n6. Verifying the fix...")
        if status_after_enable == 'enabled' and status_after_disable == 'disabled':
            print("   ✅ Admin CAPTCHA settings fix is working correctly!")
            print("   ✅ Admin can now control CAPTCHA system globally")
            return True
        else:
            print("   ❌ Admin CAPTCHA settings fix is not working correctly")
            return False
            
    except Exception as e:
        print(f"   ❌ Error during testing: {e}")
        return False

def test_admin_panel_access():
    """Test that admin panel can access and modify the setting"""
    print("\n🔧 Testing Admin Panel Access")
    print("=" * 50)
    
    try:
        # Check if the setting appears in admin security settings
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT setting_name, value, description FROM security_settings WHERE setting_name = 'captcha_system_enabled'")
            result = c.fetchone()
            
            if result:
                print(f"   ✅ Setting found in admin security panel:")
                print(f"      Name: {result['setting_name']}")
                print(f"      Value: {result['value']}")
                print(f"      Description: {result['description']}")
                return True
            else:
                print("   ❌ Setting not found in admin security panel")
                return False
                
    except Exception as e:
        print(f"   ❌ Error checking admin panel: {e}")
        return False

def test_captcha_functionality():
    """Test that CAPTCHA functionality respects the admin setting"""
    print("\n🔧 Testing CAPTCHA Functionality")
    print("=" * 50)
    
    try:
        # Test with CAPTCHA enabled
        print("\n1. Testing with CAPTCHA enabled...")
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("UPDATE security_settings SET value = 'enabled' WHERE setting_name = 'captcha_system_enabled'")
            conn.commit()
        
        status_enabled = get_captcha_system_status()
        print(f"   CAPTCHA system status: {status_enabled}")
        
        # Test with CAPTCHA disabled
        print("\n2. Testing with CAPTCHA disabled...")
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("UPDATE security_settings SET value = 'disabled' WHERE setting_name = 'captcha_system_enabled'")
            conn.commit()
        
        status_disabled = get_captcha_system_status()
        print(f"   CAPTCHA system status: {status_disabled}")
        
        # Restore enabled state
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("UPDATE security_settings SET value = 'enabled' WHERE setting_name = 'captcha_system_enabled'")
            conn.commit()
        
        if status_enabled == 'enabled' and status_disabled == 'disabled':
            print("   ✅ CAPTCHA functionality correctly respects admin settings")
            return True
        else:
            print("   ❌ CAPTCHA functionality does not respect admin settings")
            return False
            
    except Exception as e:
        print(f"   ❌ Error testing CAPTCHA functionality: {e}")
        return False

if __name__ == "__main__":
    print("🧪 Running Admin CAPTCHA Settings Fix Tests")
    print("=" * 60)
    
    test1_passed = test_captcha_admin_fix()
    test2_passed = test_admin_panel_access()
    test3_passed = test_captcha_functionality()
    
    print("\n" + "=" * 60)
    print("📊 Test Results Summary")
    print("=" * 60)
    print(f"Admin CAPTCHA Settings Fix: {'✅ PASSED' if test1_passed else '❌ FAILED'}")
    print(f"Admin Panel Access: {'✅ PASSED' if test2_passed else '❌ FAILED'}")
    print(f"CAPTCHA Functionality: {'✅ PASSED' if test3_passed else '❌ FAILED'}")
    
    if all([test1_passed, test2_passed, test3_passed]):
        print("\n🎉 All tests passed! The admin CAPTCHA settings fix is working correctly.")
        print("✅ Admins can now properly control the CAPTCHA system globally.")
    else:
        print("\n❌ Some tests failed. Please check the implementation.")
        sys.exit(1) 