#!/usr/bin/env python3
"""
Tor Setup Script for Sydney Marketplace
This script helps configure the marketplace for Tor network deployment.
"""

import os
import sys
import subprocess
import shutil

def check_tor_installation():
    """Check if Tor is installed and running"""
    print("🔍 Checking Tor installation...")
    
    # Check if tor binary exists
    tor_path = shutil.which('tor')
    if not tor_path:
        print("❌ Tor is not installed. Please install Tor first:")
        print("   - Ubuntu/Debian: sudo apt-get install tor")
        print("   - CentOS/RHEL: sudo yum install tor")
        print("   - macOS: brew install tor")
        print("   - Windows: Download from https://www.torproject.org/")
        return False
    
    print(f"✅ Tor found at: {tor_path}")
    
    # Check if Tor service is running
    try:
        result = subprocess.run(['systemctl', 'is-active', 'tor'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip() == 'active':
            print("✅ Tor service is running")
            return True
        else:
            print("⚠️  Tor service is not running. Starting Tor...")
            subprocess.run(['sudo', 'systemctl', 'start', 'tor'], check=True)
            print("✅ Tor service started")
            return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("⚠️  Could not check Tor service status. Please ensure Tor is running manually.")
        return True

def check_socks_proxy():
    """Check if SOCKS proxy is accessible"""
    print("🔍 Checking SOCKS proxy...")
    
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex(('127.0.0.1', 9050))
        sock.close()
        
        if result == 0:
            print("✅ SOCKS proxy is accessible on 127.0.0.1:9050")
            return True
        else:
            print("❌ SOCKS proxy is not accessible on 127.0.0.1:9050")
            print("   Please ensure Tor is configured to listen on port 9050")
            return False
    except Exception as e:
        print(f"❌ Error checking SOCKS proxy: {e}")
        return False

def create_env_file():
    """Create or update .env file with Tor settings"""
    print("🔧 Configuring environment variables...")
    
    env_file = '.env'
    env_content = []
    
    # Read existing .env file if it exists
    if os.path.exists(env_file):
        with open(env_file, 'r') as f:
            env_content = f.readlines()
    
    # Update or add Tor-related settings
    tor_settings = {
        'TOR_ENABLED': 'true',
        'OFFLINE_MODE': 'false',
        'FALLBACK_BTC_PRICE': '45000',
        'FALLBACK_XMR_PRICE': '150'
    }
    
    updated = False
    for key, value in tor_settings.items():
        found = False
        for i, line in enumerate(env_content):
            if line.startswith(f'{key}='):
                env_content[i] = f'{key}={value}\n'
                found = True
                updated = True
                break
        
        if not found:
            env_content.append(f'{key}={value}\n')
            updated = True
    
    if updated:
        with open(env_file, 'w') as f:
            f.writelines(env_content)
        print("✅ Environment variables updated")
    else:
        print("✅ Environment variables already configured")

def test_external_apis():
    """Test external API connectivity through Tor"""
    print("🌐 Testing external API connectivity...")
    
    import requests
    
    # Test URLs
    test_urls = [
        'https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd',
        'https://api.blockcypher.com/v1/btc/main'
    ]
    
    proxies = {
        "http": "socks5h://127.0.0.1:9050",
        "https": "socks5h://127.0.0.1:9050"
    }
    
    for url in test_urls:
        try:
            print(f"   Testing {url}...")
            response = requests.get(url, proxies=proxies, timeout=10)
            if response.status_code == 200:
                print(f"   ✅ Success: {url}")
            else:
                print(f"   ⚠️  HTTP {response.status_code}: {url}")
        except Exception as e:
            print(f"   ❌ Failed: {url} - {e}")

def main():
    print("🚀 Sydney Marketplace Tor Setup")
    print("=" * 40)
    
    # Check Tor installation
    if not check_tor_installation():
        print("\n❌ Tor setup failed. Please install and configure Tor first.")
        sys.exit(1)
    
    # Check SOCKS proxy
    if not check_socks_proxy():
        print("\n❌ SOCKS proxy setup failed. Please configure Tor properly.")
        sys.exit(1)
    
    # Configure environment
    create_env_file()
    
    # Test connectivity
    print("\n🌐 Testing external API connectivity through Tor...")
    test_external_apis()
    
    print("\n✅ Tor setup completed!")
    print("\n📋 Next steps:")
    print("1. Restart your Flask application")
    print("2. Test the marketplace over Tor")
    print("3. If external APIs are blocked, set OFFLINE_MODE=true in .env")
    print("4. Monitor logs for any connectivity issues")
    
    print("\n🔧 Manual configuration options:")
    print("- Set TOR_ENABLED=true in .env to enable Tor proxy")
    print("- Set OFFLINE_MODE=true in .env to use fallback addresses/prices")
    print("- Adjust FALLBACK_BTC_PRICE and FALLBACK_XMR_PRICE as needed")

if __name__ == '__main__':
    main() 