from bitcoinlib.keys import Key
from bitcoinlib.scripts import Script
from bitcoinlib.transactions import Transaction
from bitcoinlib.services.services import Service
import requests
import logging
import os
import hashlib
from config import Config
from utils.database import get_settings

logger = logging.getLogger(__name__)

# Tor proxy configuration
TOR_ENABLED = os.getenv('TOR_ENABLED', 'false').lower() == 'true'
TOR_PROXY = {
    "http": f"socks5h://127.0.0.1:{Config.TOR_PROXY_PORT}",
    "https": f"socks5h://127.0.0.1:{Config.TOR_PROXY_PORT}"
}

# Global Bitcoin service and escrow key
SERVICE = Service(network='bitcoin')  # Use mainnet to match BlockCypher API
ESCROW_KEY = Key(Config.ESCROW_PRIVATE_KEY, network='bitcoin') if Config.ESCROW_PRIVATE_KEY else None
ESCROW_ADDRESS = ESCROW_KEY.address() if ESCROW_KEY else None

def estimate_fee():
    url = f"{Config.BLOCKCYPHER_API}/fees?token={Config.BLOCKCYPHER_TOKEN}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        fee_per_byte = data.get('medium_fee_per_kb', 10) // 1000
        tx_size = 250  # Estimate for a simple transaction
        return fee_per_byte * tx_size
    except requests.RequestException:
        return 10000  # Fallback fee in satoshis

def send_btc(from_key, to_address, amount_btc):
    utxos = SERVICE.getutxos(from_key.address())
    if not utxos:
        return None
    
    total_input = sum(utxo['value'] for utxo in utxos)
    amount_satoshi = int(amount_btc * 100000000)
    fee = estimate_fee()
    
    if total_input < amount_satoshi + fee:
        return None
    
    tx = Transaction(network='bitcoin')
    for utxo in utxos:
        tx.add_input(utxo['txid'], utxo['output_n'])
    
    tx.add_output(amount_satoshi, to_address)
    change = total_input - amount_satoshi - fee
    if change > 0:
        tx.add_output(change, from_key.address())
    
    for i, inp in enumerate(tx.inputs):
        tx.sign(from_key.private_hex, i)
    
    txid = SERVICE.sendrawtransaction(tx.raw_hex())
    return txid

def generate_fallback_btc_address(user_id):
    """Generate a fallback BTC address when external APIs are unavailable"""
    try:
        # Use the admin escrow address as fallback
        from utils.database import get_settings
        settings = get_settings()
        escrow_address = settings.get('btc_escrow_wallet')
        
        if escrow_address:
            logger.info(f"Using admin escrow address as fallback for user {user_id}: {escrow_address}")
            return escrow_address
        else:
            # If no escrow address in settings, use the hardcoded one from config
            logger.warning("No admin escrow address in settings, using config fallback")
            return Config.ESCROW_BTC_ADDRESS
    except Exception as e:
        logger.error(f"Failed to get admin escrow address: {str(e)}")
        # Final fallback to hardcoded address
        return Config.ESCROW_BTC_ADDRESS

def generate_btc_address(vendor_id):
    # Check if offline mode is enabled
    if Config.OFFLINE_MODE:
        logger.info("Offline mode enabled, using fallback BTC address generation")
        return generate_fallback_btc_address(vendor_id)
    
    url = f"{Config.BLOCKCYPHER_API}/addrs?token={Config.BLOCKCYPHER_TOKEN}"
    print(f"[DEBUG] BlockCypher API URL: {url}")
    
    # Use Tor proxy if enabled
    proxies = TOR_PROXY if TOR_ENABLED else None
    
    try:
        # First try with Tor proxy if enabled
        if TOR_ENABLED:
            print("[DEBUG] Attempting BlockCypher API call through Tor proxy...")
            response = requests.post(url, proxies=proxies, timeout=30)  # Increased timeout for Tor
            print(f"[DEBUG] Tor proxy response status: {response.status_code}")
            
            if response.status_code in [200, 201]:
                address_data = response.json()
                btc_address = address_data['address']
                print(f"[DEBUG] Successfully generated address through Tor: {btc_address}")
                
                # Create webhook
                webhook_data = {
                    "event": "confirmed-tx",
                    "address": btc_address,
                    "url": Config.WEBHOOK_URL,
                    "token": Config.BLOCKCYPHER_TOKEN
                }
                webhook_url = f"{Config.BLOCKCYPHER_API}/hooks"
                webhook_response = requests.post(webhook_url, json=webhook_data, proxies=proxies, timeout=30)
                if webhook_response.status_code not in (200, 201):
                    print(f"Webhook creation failed: {webhook_response.text}")
                return btc_address
            else:
                print(f"[DEBUG] Tor proxy failed with status {response.status_code}, trying direct connection...")
        
        # If Tor failed or not enabled, try direct connection
        print("[DEBUG] Attempting BlockCypher API call with direct connection...")
        response = requests.post(url, timeout=15)
        print(f"[DEBUG] Direct connection response status: {response.status_code}")
        
        if response.status_code in [200, 201]:
            address_data = response.json()
            btc_address = address_data['address']
            print(f"[DEBUG] Successfully generated address with direct connection: {btc_address}")
            
            # Create webhook
            webhook_data = {
                "event": "confirmed-tx",
                "address": btc_address,
                "url": Config.WEBHOOK_URL,
                "token": Config.BLOCKCYPHER_TOKEN
            }
            webhook_url = f"{Config.BLOCKCYPHER_API}/hooks"
            webhook_response = requests.post(webhook_url, json=webhook_data, timeout=15)
            if webhook_response.status_code not in (200, 201):
                print(f"Webhook creation failed: {webhook_response.text}")
            return btc_address
        elif response.status_code == 429:
            # Rate limited - use fallback
            print("[DEBUG] Rate limited by BlockCypher API, using fallback")
            logger.warning("BlockCypher API rate limited, using fallback address generation")
            return generate_fallback_btc_address(vendor_id)
        else:
            print(f"[DEBUG] Direct connection also failed with status {response.status_code}")
            raise requests.RequestException(f"API returned status {response.status_code}")
            
    except requests.RequestException as e:
        print(f"[DEBUG] Exception: {str(e)}")
        logger.warning(f"BlockCypher API failed, using fallback address generation: {str(e)}")
        return generate_fallback_btc_address(vendor_id)
    except Exception as e:
        print(f"[DEBUG] Exception: {str(e)}")
        logger.error(f"Unexpected error in BTC address generation: {str(e)}")
        return generate_fallback_btc_address(vendor_id)

def check_payment(multisig_address, expected_amount_btc):
    # Check if BlockCypher token is configured
    if not Config.BLOCKCYPHER_TOKEN:
        print("BlockCypher token not configured, using bitcoinlib service")
        try:
            utxos = SERVICE.getutxos(multisig_address)
            total_btc = sum(utxo['value'] for utxo in utxos) / 100000000
            if total_btc >= expected_amount_btc:
                return utxos[0]['txid'] if utxos else None
        except Exception as e:
            print(f"Bitcoinlib service failed: {str(e)}")
        return None
    
    # Use Tor proxy if enabled
    proxies = TOR_PROXY if TOR_ENABLED else None
    
    try:
        # Use BlockCypher API to check address balance instead of bitcoinlib service
        url = f"{Config.BLOCKCYPHER_API}/addrs/{multisig_address}/balance?token={Config.BLOCKCYPHER_TOKEN}"
        response = requests.get(url, timeout=15, proxies=proxies)
        response.raise_for_status()
        data = response.json()
        
        # Get balance in BTC (BlockCypher returns balance in satoshis)
        balance_btc = data.get('final_balance', 0) / 100000000
        
        if balance_btc >= expected_amount_btc:
            # Get the latest transaction ID
            url = f"{Config.BLOCKCYPHER_API}/addrs/{multisig_address}?token={Config.BLOCKCYPHER_TOKEN}"
            response = requests.get(url, timeout=15, proxies=proxies)
            response.raise_for_status()
            addr_data = response.json()
            
            # Get the most recent transaction
            if addr_data.get('txrefs'):
                return addr_data['txrefs'][0]['tx_hash']
            return "payment_confirmed"  # Fallback if no tx_hash available
        
        return None
    except requests.RequestException as e:
        print(f"Error checking payment with BlockCypher: {str(e)}")
        # Fallback to bitcoinlib service
        try:
            utxos = SERVICE.getutxos(multisig_address)
            total_btc = sum(utxo['value'] for utxo in utxos) / 100000000
            if total_btc >= expected_amount_btc:
                return utxos[0]['txid'] if utxos else None
        except Exception as e2:
            print(f"Bitcoinlib service also failed: {str(e2)}")
        return None

def get_usd_to_btc_rate():
    url = "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd"
    
    # Use Tor proxy if enabled
    proxies = TOR_PROXY if TOR_ENABLED else None
    
    try:
        response = requests.get(url, timeout=10, proxies=proxies)
        return response.json()["bitcoin"]["usd"]
    except:
        return 50000  # Fallback USD/BTC rate

def send_multisig_tx(multisig_address, to_address, amount_btc, *keys):
    # Placeholder for multisig transaction
    utxos = SERVICE.getutxos(multisig_address)
    if not utxos:
        return None
    tx = Transaction(network='bitcoin')
    for utxo in utxos:
        tx.add_input(utxo['txid'], utxo['output_n'])
    amount_satoshi = int(amount_btc * 100000000)
    fee = estimate_fee()
    tx.add_output(amount_satoshi, to_address)
    change = sum(utxo['value'] for utxo in utxos) - amount_satoshi - fee
    if change > 0:
        tx.add_output(change, multisig_address)
    for i, inp in enumerate(tx.inputs):
        tx.sign(keys[i % len(keys)].private_hex, i)  # Simplified signing
    return SERVICE.sendrawtransaction(tx.raw_hex())

def create_multisig(buyer_address, vendor_address):
    settings = get_settings()
    # Use the platform's escrow public key from settings if available, else fallback
    escrow_pubkey = settings.get('btc_escrow_wallet', None)
    if escrow_pubkey:
        public_keys = [
            Key(buyer_address, network='bitcoin').public_hex,
            Key(vendor_address, network='bitcoin').public_hex,
            escrow_pubkey
        ]
    else:
        public_keys = [
            Key(buyer_address, network='bitcoin').public_hex,
            Key(vendor_address, network='bitcoin').public_hex,
            ESCROW_KEY.public_hex if ESCROW_KEY else None
        ]
    script = Script.multisig(2, public_keys)
    return script.address()

def generate_btc_escrow_address(order_id):
    """Generate a unique, spendable BTC escrow address for the given order_id.
    Deterministically derives a child private key from ESCROW_PRIVATE_KEY and order_id.
    """
    try:
        if not Config.ESCROW_PRIVATE_KEY:
            logger.error("ESCROW_PRIVATE_KEY not set; cannot derive BTC escrow address")
            return None
        seed_material = f"{str(Config.ESCROW_PRIVATE_KEY)}:{str(order_id)}".encode()
        derived_priv_hex = hashlib.sha256(seed_material).hexdigest()
        derived_key = Key(derived_priv_hex, network='bitcoin')
        return derived_key.address()
    except Exception as e:
        logger.error(f"Failed to derive BTC escrow address: {str(e)}")
        return None