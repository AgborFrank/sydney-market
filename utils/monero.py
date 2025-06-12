from monero.wallet import Wallet
from monero.backends.jsonrpc import JSONRPCWallet
from config import Config
import os

# Initialize Monero wallet using JSONRPC
wallet = Wallet(JSONRPCWallet(
    host=os.getenv('MONERO_RPC_HOST', 'localhost'),
    port=int(os.getenv('MONERO_RPC_PORT', 18081)),
    user=os.getenv('MONERO_RPC_USER', ''),
    password=os.getenv('MONERO_RPC_PASSWORD', '')
))

def generate_monero_address(user_id):
    try:
        # Create a new subaddress for the user
        address = wallet.new_address()
        return str(address[0])  # Return the address as a string
    except Exception as e:
        raise Exception(f"Failed to generate Monero address: {str(e)}")

def check_monero_payment(address, expected_amount_xmr):
    try:
        # Check incoming transactions for the address
        wallet.refresh()  # Ensure wallet is synced
        account = wallet.accounts[0]  # Use default account
        transactions = account.incoming()
        total_xmr = sum(tx.amount for tx in transactions if str(tx.address) == address)
        return total_xmr >= expected_amount_xmr
    except Exception as e:
        raise Exception(f"Failed to check Monero payment: {str(e)}")

def send_monero(address, amount_xmr):
    try:
        # Send XMR to the specified address
        wallet.refresh()
        account = wallet.accounts[0]
        tx = account.transfer(address, amount_xmr)
        return tx.hash  # Return transaction hash
    except Exception as e:
        raise Exception(f"Failed to send Monero: {str(e)}")