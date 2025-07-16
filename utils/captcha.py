try:
    from captcha.image import ImageCaptcha
except ImportError:
    # Fallback if there's a naming conflict
    import sys
    import os
    # Remove current directory from path to avoid local captcha.py
    if os.getcwd() in sys.path:
        sys.path.remove(os.getcwd())
    from captcha.image import ImageCaptcha
import random
import string
from flask import session, send_file, make_response, current_app
import io
import logging
import time

def generate_captcha_code(length=5):
    """Generate a random CAPTCHA code using uppercase letters and digits."""
    chars = string.ascii_uppercase + string.digits
    # Exclude similar characters (0, O, 1, I, L) for better readability
    chars = chars.replace('0', '').replace('O', '').replace('1', '').replace('I', '').replace('L', '')
    return ''.join(random.choices(chars, k=length))

def generate_captcha_image(code):
    """Generate CAPTCHA image with improved readability."""
    try:
        # Use default font configuration to avoid font loading issues
        image = ImageCaptcha(width=200, height=70)
        data = image.generate(code)
        # Read the data from BytesIO object
        if hasattr(data, 'read'):
            data.seek(0)
            return data.read()
        return data
    except Exception as e:
        logging.error(f"Failed to generate CAPTCHA image: {e}")
        # Fallback to basic image generation
        image = ImageCaptcha(width=180, height=60)
        data = image.generate(code)
        if hasattr(data, 'read'):
            data.seek(0)
            return data.read()
        return data

def set_captcha_code(code):
    """Store CAPTCHA code in session with timestamp."""
    try:
        session['captcha_code'] = code
        session['captcha_timestamp'] = time.time()
        session.modified = True
    except Exception as e:
        logging.error(f"Failed to set CAPTCHA code in session: {e}")
        # Fallback to simple session storage
        session['captcha_code'] = code

def get_captcha_code():
    """Retrieve CAPTCHA code from session with validation."""
    try:
        code = session.get('captcha_code', '')
        timestamp = session.get('captcha_timestamp', 0)
        
        # Check if CAPTCHA has expired (5 minutes)
        if time.time() - timestamp > 300:
            logging.warning("CAPTCHA code expired")
            clear_captcha_code()
            return ''
            
        return code
    except Exception as e:
        logging.error(f"Failed to get CAPTCHA code from session: {e}")
        return ''

def clear_captcha_code():
    """Clear CAPTCHA code from session."""
    try:
        session.pop('captcha_code', None)
        session.pop('captcha_timestamp', None)
        session.modified = True
    except Exception as e:
        logging.error(f"Failed to clear CAPTCHA code from session: {e}")

def serve_captcha_image():
    """Serve CAPTCHA image with proper headers."""
    try:
        code = generate_captcha_code()
        set_captcha_code(code)
        image_data = generate_captcha_image(code)
        
        # Ensure image_data is bytes
        if isinstance(image_data, io.BytesIO):
            image_data = image_data.getvalue()
        
        response = make_response(send_file(
            io.BytesIO(image_data),
            mimetype='image/png'
        ))
        
        # Prevent caching
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response
    except Exception as e:
        logging.error(f"Failed to serve CAPTCHA image: {e}")
        # Return a simple error response
        return make_response("CAPTCHA generation failed", 500)

def validate_captcha(user_input):
    """Validate user input against stored CAPTCHA code."""
    try:
        if not user_input:
            logging.warning("Empty CAPTCHA input")
            return False
        code = get_captcha_code()
        logging.warning(f"CAPTCHA validation: user_input='{user_input}', stored_code='{code}'")
        normalized_input = user_input.strip().upper()
        logging.warning(f"CAPTCHA validation: normalized_input='{normalized_input}', stored_code='{code}'")
        if normalized_input == code:
            clear_captcha_code()
            return True
        else:
            logging.warning(f"CAPTCHA validation failed: expected='{code}', got='{normalized_input}'")
            return False
    except Exception as e:
        logging.error(f"CAPTCHA validation error: {e}")
        return False

def is_captcha_required():
    """Check if CAPTCHA verification is required."""
    try:
        # First check if CAPTCHA system is enabled globally
        from utils.database import get_security_settings
        security_settings = get_security_settings()
        if security_settings.get('captcha_system_enabled') != 'enabled':
            logging.info("CAPTCHA system is disabled globally")
            return False
        
        # Then check if user has already verified
        return not session.get('captcha_verified', False)
    except Exception as e:
        logging.error(f"Error checking CAPTCHA requirement: {e}")
        return True

def mark_captcha_verified():
    """Mark CAPTCHA as verified in session."""
    try:
        session['captcha_verified'] = True
        session.modified = True
    except Exception as e:
        logging.error(f"Failed to mark CAPTCHA as verified: {e}")

def reset_captcha_verification():
    """Reset CAPTCHA verification status."""
    try:
        session['captcha_verified'] = False
        session.modified = True
    except Exception as e:
        logging.error(f"Failed to reset CAPTCHA verification: {e}")

def get_captcha_system_status():
    """Get the current status of the CAPTCHA system."""
    try:
        from utils.database import get_security_settings
        security_settings = get_security_settings()
        return security_settings.get('captcha_system_enabled', 'enabled')
    except Exception as e:
        logging.error(f"Error getting CAPTCHA system status: {e}")
        return 'enabled'  # Default to enabled for security 