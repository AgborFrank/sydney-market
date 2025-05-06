from bitcoinlib.keys import Key
from bitcoinlib.scripts import Script
from bitcoinlib.transactions import Transaction
from bitcoinlib.services.services import Service
import requests
from config import Config

# Global Bitcoin service and escrow key
SERVICE = Service(network='testnet')
ESCROW_KEY = Key(Config.ESCROW_PRIVATE_KEY, network='testnet')
ESCROW_ADDRESS = ESCROW_KEY.address()

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
    
    tx = Transaction(network='testnet')
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

def generate_btc_address(vendor_id):
    url = f"{Config.BLOCKCYPHER_API}/addrs?token={Config.BLOCKCYPHER_TOKEN}"
    try:
        response = requests.post(url)
        response.raise_for_status()
        address_data = response.json()
        btc_address = address_data['address']
        
        webhook_data = {
            "event": "confirmed-tx",
            "address": btc_address,
            "url": Config.WEBHOOK_URL,
            "token": Config.BLOCKCYPHER_TOKEN
        }
        webhook_url = f"{Config.BLOCKCYPHER_API}/hooks"
        webhook_response = requests.post(webhook_url, json=webhook_data)
        if webhook_response.status_code not in (200, 201):
            print(f"Webhook creation failed: {webhook_response.text}")
        return btc_address
    except requests.RequestException as e:
        raise Exception(f"Failed to generate BTC address: {str(e)}")

def check_payment(multisig_address, expected_amount_btc):
    utxos = SERVICE.getutxos(multisig_address)
    total_btc = sum(utxo['value'] for utxo in utxos) / 100000000
    if total_btc >= expected_amount_btc:
        return utxos[0]['txid'] if utxos else None
    return None

def get_usd_to_btc_rate():
    url = "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd"
    try:
        response = requests.get(url)
        return response.json()["bitcoin"]["usd"]
    except:
        return 50000  # Fallback USD/BTC rate
# utils/bitcoin.py
def send_multisig_tx(multisig_address, to_address, amount_btc, *keys):
    # Placeholder for multisig transaction
    utxos = SERVICE.getutxos(multisig_address)
    if not utxos:
        return None
    tx = Transaction(network='testnet')
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
    public_keys = [
        Key(buyer_address, network='testnet').public_hex,
        Key(vendor_address, network='testnet').public_hex,
        ESCROW_KEY.public_hex
    ]
    script = Script.multisig(2, public_keys)
    return script.address()