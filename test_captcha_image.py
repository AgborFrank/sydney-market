#!/usr/bin/env python3
"""
Test script to verify CAPTCHA image generation
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_captcha_generation():
    """Test basic CAPTCHA image generation"""
    print("Testing CAPTCHA image generation...")
    
    try:
        from captcha.image import ImageCaptcha
        
        # Test basic generation
        image = ImageCaptcha(width=200, height=70)
        test_code = "ABC12"
        
        print(f"Generating image for code: {test_code}")
        image_data = image.generate(test_code)
        
        # Handle BytesIO object
        if hasattr(image_data, 'read'):
            image_data.seek(0)
            image_bytes = image_data.read()
        else:
            image_bytes = image_data
        
        print(f"✓ Image generated successfully")
        print(f"✓ Image size: {len(image_bytes)} bytes")
        
        # Test if it's valid PNG data
        if image_bytes.startswith(b'\x89PNG'):
            print("✓ Image is valid PNG format")
        else:
            print("✗ Image is not valid PNG format")
            return False
            
        return True
        
    except Exception as e:
        print(f"✗ CAPTCHA image generation failed: {e}")
        return False

def test_captcha_utils():
    """Test our CAPTCHA utility functions"""
    print("\nTesting CAPTCHA utility functions...")
    
    try:
        from utils.captcha import generate_captcha_code, generate_captcha_image
        
        # Test code generation
        code = generate_captcha_code()
        print(f"✓ Generated code: {code}")
        
        # Test image generation
        image_data = generate_captcha_image(code)
        print(f"✓ Generated image, size: {len(image_data)} bytes")
        
        return True
        
    except Exception as e:
        print(f"✗ CAPTCHA utility test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("CAPTCHA Image Generation Test")
    print("=" * 40)
    
    tests = [
        test_captcha_generation,
        test_captcha_utils
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
        print("✓ All CAPTCHA image tests passed!")
        print("✓ CAPTCHA image generation is working correctly!")
        return 0
    else:
        print("✗ Some CAPTCHA image tests failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 