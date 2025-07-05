from monero.wallet import Wallet
from monero.backends.jsonrpc import JSONRPCWallet
from config import Config
import os

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

def generate_monero_address(user_id):
    if wallet is None:
        return None
    try:
        # Create a new subaddress for the user
        address = wallet.new_address()
        return str(address[0])  # Return the address as a string
    except Exception as e:
        print(f"[Monero] Failed to generate address: {e}")
        return None

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