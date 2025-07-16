#!/usr/bin/env python3
"""
Script to fix the missing CAPTCHA setting in the security_settings table
"""

import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.database import get_db_connection, get_security_settings

def fix_captcha_setting():
    """Add the missing CAPTCHA setting to the security_settings table"""
    print("🔧 Fixing CAPTCHA Setting in Security Settings Table")
    print("=" * 60)
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            
            # Check if the setting already exists
            c.execute("SELECT setting_name, value FROM security_settings WHERE setting_name = 'captcha_system_enabled'")
            existing = c.fetchone()
            
            if existing:
                print(f"✅ Setting already exists: {existing['setting_name']} = {existing['value']}")
                return True
            
            # Add the missing setting
            print("📝 Adding missing CAPTCHA setting...")
            c.execute("""
                INSERT INTO security_settings (setting_name, value, description)
                VALUES ('captcha_system_enabled', 'enabled', 'Enable or disable CAPTCHA challenge system')
            """)
            conn.commit()
            
            # Verify the setting was added
            c.execute("SELECT setting_name, value FROM security_settings WHERE setting_name = 'captcha_system_enabled'")
            result = c.fetchone()
            
            if result:
                print(f"✅ Successfully added: {result['setting_name']} = {result['value']}")
                return True
            else:
                print("❌ Failed to add the setting")
                return False
                
    except Exception as e:
        print(f"❌ Error fixing CAPTCHA setting: {e}")
        return False

def verify_fix():
    """Verify that the fix worked"""
    print("\n🔍 Verifying the fix...")
    
    try:
        # Test the get_security_settings function
        security_settings = get_security_settings()
        captcha_setting = security_settings.get('captcha_system_enabled')
        
        if captcha_setting:
            print(f"✅ CAPTCHA setting found: {captcha_setting}")
            
            # Test the CAPTCHA functions
            from utils.captcha import get_captcha_system_status
            status = get_captcha_system_status()
            print(f"✅ CAPTCHA system status: {status}")
            
            return True
        else:
            print("❌ CAPTCHA setting not found in security settings")
            return False
            
    except Exception as e:
        print(f"❌ Error verifying fix: {e}")
        return False

if __name__ == "__main__":
    print("🧪 Running CAPTCHA Setting Fix")
    print("=" * 60)
    
    fix_success = fix_captcha_setting()
    verify_success = verify_fix()
    
    print("\n" + "=" * 60)
    print("📊 Fix Results")
    print("=" * 60)
    print(f"Setting Fix: {'✅ SUCCESS' if fix_success else '❌ FAILED'}")
    print(f"Verification: {'✅ SUCCESS' if verify_success else '❌ FAILED'}")
    
    if fix_success and verify_success:
        print("\n🎉 CAPTCHA setting fix completed successfully!")
        print("✅ Admins can now properly control the CAPTCHA system globally.")
    else:
        print("\n❌ Fix failed. Please check the implementation.")
        sys.exit(1) 