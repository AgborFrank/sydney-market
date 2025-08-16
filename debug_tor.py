#!/usr/bin/env python3
"""
Debug script to test Tor-specific functionality
"""

import os
import sys
import logging
import sqlite3
from config import Config

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def test_database_connection():
    """Test database connection with Tor-specific settings"""
    try:
        db_path = os.getenv('DB_PATH', 'marketplace.db')
        logger.info(f"Testing database connection to: {db_path}")
        
        conn = sqlite3.connect(db_path, timeout=Config.TOR_DB_TIMEOUT)
        conn.row_factory = sqlite3.Row
        
        # Test basic operations
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        logger.info(f"Database connection successful. User count: {user_count}")
        
        # Test messages table
        cursor.execute("SELECT COUNT(*) FROM messages")
        message_count = cursor.fetchone()[0]
        logger.info(f"Messages table accessible. Message count: {message_count}")
        
        conn.close()
        return True
        
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        return False

def test_gpg_functionality():
    """Test GPG functionality with Tor-specific settings"""
    try:
        from utils.security import init_gpg_for_tor
        
        logger.info("Testing GPG functionality...")
        gpg, error = init_gpg_for_tor()
        
        if error:
            logger.error(f"GPG initialization failed: {error}")
            return False
        
        if gpg:
            # Test GPG operations
            keys = gpg.list_keys()
            logger.info(f"GPG working. Found {len(keys)} keys")
            return True
        else:
            logger.error("GPG object is None")
            return False
            
    except Exception as e:
        logger.error(f"GPG test failed: {e}")
        return False

def test_file_permissions():
    """Test file permissions for Tor access"""
    try:
        # Test database file
        db_path = os.getenv('DB_PATH', 'marketplace.db')
        if os.path.exists(db_path):
            logger.info(f"Database file exists: {db_path}")
            logger.info(f"Database file readable: {os.access(db_path, os.R_OK)}")
            logger.info(f"Database file writable: {os.access(db_path, os.W_OK)}")
        else:
            logger.error(f"Database file does not exist: {db_path}")
            return False
        
        # Test GPG home directory
        gpg_home = Config.GPG_HOME
        if os.path.exists(gpg_home):
            logger.info(f"GPG home exists: {gpg_home}")
            logger.info(f"GPG home readable: {os.access(gpg_home, os.R_OK)}")
            logger.info(f"GPG home writable: {os.access(gpg_home, os.W_OK)}")
        else:
            logger.info(f"GPG home does not exist: {gpg_home}")
        
        return True
        
    except Exception as e:
        logger.error(f"File permission test failed: {e}")
        return False

def main():
    """Run all tests"""
    logger.info("Starting Tor compatibility tests...")
    
    tests = [
        ("Database Connection", test_database_connection),
        ("GPG Functionality", test_gpg_functionality),
        ("File Permissions", test_file_permissions),
    ]
    
    results = {}
    for test_name, test_func in tests:
        logger.info(f"\n{'='*50}")
        logger.info(f"Running test: {test_name}")
        logger.info(f"{'='*50}")
        
        try:
            result = test_func()
            results[test_name] = result
            status = "PASSED" if result else "FAILED"
            logger.info(f"Test {test_name}: {status}")
        except Exception as e:
            logger.error(f"Test {test_name} failed with exception: {e}")
            results[test_name] = False
    
    # Summary
    logger.info(f"\n{'='*50}")
    logger.info("TEST SUMMARY")
    logger.info(f"{'='*50}")
    
    for test_name, result in results.items():
        status = "PASSED" if result else "FAILED"
        logger.info(f"{test_name}: {status}")
    
    all_passed = all(results.values())
    logger.info(f"\nOverall result: {'ALL TESTS PASSED' if all_passed else 'SOME TESTS FAILED'}")
    
    return all_passed

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 