#!/usr/bin/env python3
"""
Test script to verify CAPTCHA system functionality
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from utils.captcha import (
    generate_captcha_code, 
    validate_captcha, 
    set_captcha_code, 
    get_captcha_code,
    clear_captcha_code
)

def test_captcha_generation():
    """Test CAPTCHA code generation"""
    print("Testing CAPTCHA code generation...")
    
    # Generate multiple codes to ensure randomness
    codes = []
    for i in range(5):
        code = generate_captcha_code()
        codes.append(code)
        print(f"Generated code {i+1}: {code}")
    
    # Check that codes are different
    if len(set(codes)) == len(codes):
        print("✓ CAPTCHA codes are unique")
    else:
        print("✗ CAPTCHA codes are not unique")
        return False
    
    # Check code length
    for code in codes:
        if len(code) == 5:
            print(f"✓ Code length is correct: {len(code)}")
        else:
            print(f"✗ Code length is incorrect: {len(code)}")
            return False
    
    return True

def test_captcha_validation():
    """Test CAPTCHA validation logic"""
    print("\nTesting CAPTCHA validation...")
    
    # Test with correct code
    test_code = "ABC12"
    set_captcha_code(test_code)
    stored_code = get_captcha_code()
    
    if stored_code == test_code:
        print("✓ CAPTCHA code stored correctly")
    else:
        print(f"✗ CAPTCHA code not stored correctly. Expected: {test_code}, Got: {stored_code}")
        return False
    
    # Test validation with correct input
    if validate_captcha("ABC12"):
        print("✓ CAPTCHA validation with correct input works")
    else:
        print("✗ CAPTCHA validation with correct input failed")
        return False
    
    # Test validation with incorrect input
    if not validate_captcha("XYZ99"):
        print("✓ CAPTCHA validation with incorrect input works")
    else:
        print("✗ CAPTCHA validation with incorrect input failed")
        return False
    
    # Test validation with case-insensitive input
    if validate_captcha("abc12"):
        print("✓ CAPTCHA validation with lowercase input works")
    else:
        print("✗ CAPTCHA validation with lowercase input failed")
        return False
    
    # Test validation with whitespace
    if validate_captcha("  ABC12  "):
        print("✓ CAPTCHA validation with whitespace works")
    else:
        print("✗ CAPTCHA validation with whitespace failed")
        return False
    
    # Test validation with empty input
    if not validate_captcha(""):
        print("✓ CAPTCHA validation with empty input works")
    else:
        print("✗ CAPTCHA validation with empty input failed")
        return False
    
    return True

def test_captcha_clear():
    """Test CAPTCHA code clearing"""
    print("\nTesting CAPTCHA code clearing...")
    
    # Set a code
    test_code = "TEST1"
    set_captcha_code(test_code)
    
    # Verify it's stored
    if get_captcha_code() == test_code:
        print("✓ CAPTCHA code stored for clearing test")
    else:
        print("✗ CAPTCHA code not stored for clearing test")
        return False
    
    # Clear the code
    clear_captcha_code()
    
    # Verify it's cleared
    if get_captcha_code() == "":
        print("✓ CAPTCHA code cleared successfully")
    else:
        print("✗ CAPTCHA code not cleared")
        return False
    
    return True

def main():
    """Run all CAPTCHA tests"""
    print("CAPTCHA System Test Suite")
    print("=" * 40)
    
    tests = [
        test_captcha_generation,
        test_captcha_validation,
        test_captcha_clear
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                print(f"Test {test.__name__} failed")
        except Exception as e:
            print(f"Test {test.__name__} raised an exception: {e}")
    
    print("\n" + "=" * 40)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("✓ All CAPTCHA tests passed!")
        return 0
    else:
        print("✗ Some CAPTCHA tests failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 