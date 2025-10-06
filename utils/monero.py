from monero.wallet import Wallet
from monero.backends.jsonrpc import JSONRPCWallet
from config import Config
import os
import hashlib
import logging

logger = logging.getLogger(__name__)

# Initialize Monero wallet using JSONRPC
try:
    wallet = Wallet(JSONRPCWallet(
        host=os.getenv('MONERO_RPC_HOST', 'localhost'),
        port=int(os.getenv('MONERO_RPC_PORT', 18081)),
        user=os.getenv('MONERO_RPC_USER', ''),
        password=os.getenv('MONERO_RPC_PASSWORD', '')
    ))
except Exception as e:
    print(f"[Monero] Could not connect to Monero RPC: {e}")
    wallet = None

def generate_fallback_monero_address(user_id):
    """Generate a fallback XMR address when RPC is unavailable"""
    try:
        # Use the admin escrow address as fallback
        from utils.database import get_settings
        settings = get_settings()
        escrow_address = settings.get('xmr_escrow_wallet')
        
        if escrow_address:
            logger.info(f"Using admin escrow address as fallback for user {user_id}: {escrow_address}")
            return escrow_address
        else:
            logger.warning("No admin escrow address configured, cannot generate fallback address")
            return None
    except Exception as e:
        logger.error(f"Failed to get admin escrow address: {str(e)}")
        return None

def generate_monero_address(user_id):
    # Check if offline mode is enabled
    if Config.OFFLINE_MODE:
        logger.info("Offline mode enabled, using fallback XMR address generation")
        return generate_fallback_monero_address(user_id)
    
    if wallet is None:
        logger.warning("Monero wallet not available, using fallback address generation")
        return generate_fallback_monero_address(user_id)
    
    try:
        # Create a new subaddress for the user
        address = wallet.new_address()
        return str(address[0])  # Return the address as a string
    except Exception as e:
        print(f"[Monero] Failed to generate address: {e}")
        logger.warning(f"Monero RPC failed, using fallback address generation: {str(e)}")
        return generate_fallback_monero_address(user_id)

def check_monero_payment(address, expected_amount_xmr, min_confirmations=10):
    if wallet is None:
        return None
    try:
        # Check incoming transactions for the address
        wallet.refresh()  # Ensure wallet is synced
        account = wallet.accounts[0]  # Use default account
        transactions = account.incoming()
        for tx in transactions:
            if str(tx.address) == address and tx.confirmations >= min_confirmations and tx.amount >= expected_amount_xmr:
                return tx.hash
        return None
    except Exception as e:
        print(f"[Monero] Failed to check payment: {e}")
        return None

def send_monero(address, amount_xmr):
    if wallet is None:
        return None
    try:
        # Send XMR to the specified address
        wallet.refresh()
        account = wallet.accounts[0]
        tx = account.transfer(address, amount_xmr)
        return tx.hash  # Return transaction hash
    except Exception as e:
        print(f"[Monero] Failed to send Monero: {e}")
        return None