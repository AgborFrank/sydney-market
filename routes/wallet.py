from flask import Blueprint, render_template, session, request, flash, redirect, url_for, jsonify
from utils.database import get_db_connection
import requests
import datetime
import re
import os
from bitcoinlib.wallets import Wallet, wallet_create_or_open
from bitcoinlib.services.bitcoind import BitcoindClient
from monero.wallet import Wallet as MoneroWallet
from monero.backends.jsonrpc import JSONRPCWallet

wallet_bp = Blueprint('wallet', __name__)

# Fallback prices
FALLBACK_PRICES = {
    "BTC": 60000.00,
    "XMR": 150.00
}


BTC_WALLET_NAME = "MarketplaceBTCWallet"
BTC_TESTNET = os.getenv("BTC_TESTNET", "True") == "True"  # Default to True if not set
MONERO_RPC_HOST = os.getenv("MONERO_RPC_HOST", "localhost")
MONERO_RPC_PORT = int(os.getenv("MONERO_RPC_PORT", 18082))
MONERO_RPC_USER = os.getenv("MONERO_RPC_USER", "your_rpc_username")
MONERO_RPC_PASSWORD = os.getenv("MONERO_RPC_PASSWORD", "your_rpc_password")

def get_crypto_price(currency):
    url = "https://api.coingecko.com/api/v3/simple/price"
    params = {"ids": "bitcoin,monero", "vs_currencies": "usd"}
    try:
        response = requests.get(url, params=params, timeout=5)
        response.raise_for_status()
        data = response.json()
        if currency == "BTC":
            return data["bitcoin"]["usd"]
        elif currency == "XMR":
            return data["monero"]["usd"]
        return None
    except (requests.RequestException, ValueError) as e:
        print(f"Error fetching crypto price: {str(e)}, using fallback")
        return FALLBACK_PRICES.get(currency)

def validate_wallet_address(currency, address):
    if currency == "BTC":
        return bool(re.match(r"^(1[0-9A-Za-z]{25,34}|3[0-9A-Za-z]{25,34}|bc1[0-9A-Za-z]{39,59})$", address))
    elif currency == "XMR":
        return bool(re.match(r"^4[0-9A-Za-z]{94}$", address))
    return False

# Initialize Bitcoin wallet (run once to create, then reuse)
def init_btc_wallet():
    try:
        wallet = wallet_create_or_open(BTC_WALLET_NAME, network='testnet' if BTC_TESTNET else 'bitcoin')
        print(f"BTC Wallet Address: {wallet.get_key().address}")
        return wallet
    except Exception as e:
        print(f"Error initializing BTC wallet: {str(e)}")
        return None

# Initialize Monero wallet
def init_xmr_wallet():
    try:
        wallet = MoneroWallet(JSONRPCWallet(host=MONERO_RPC_HOST, port=MONERO_RPC_PORT, 
                                           user=MONERO_RPC_USER, password=MONERO_RPC_PASSWORD))
        print(f"XMR Wallet Address: {wallet.address()}")
        return wallet
    except Exception as e:
        print(f"Error initializing XMR wallet: {str(e)}")
        return None

@wallet_bp.route('/wallet')
def wallet():
    # Unchanged except for get_crypto_price usage
    if 'user_id' not in session:
        flash("Please log in to access your wallet.", 'error')
        return redirect(url_for('auth.login'))
    
    # if 'user_id' not in session or not has_active_subscription(session['user_id']):
    #    flash("You must have an active subscription to withdraw sales.", 'error')
    #    return redirect(url_for('vendor.subscribe'))

    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT role FROM users WHERE id = ?", (session['user_id'],))
            user = c.fetchone()
            if not user or user['role'] != 'vendor':
                flash("Only vendors can access the wallet page.", 'error')
                return redirect(url_for('public.index'))

            c.execute("SELECT SUM(vendor_earnings_usd) FROM orders WHERE vendor_id = ? AND status = 'completed'", (session['user_id'],))
            total_sales = c.fetchone()[0] or 0.0
            c.execute("SELECT balance_usd FROM vendor_wallets WHERE vendor_id = ?", (session['user_id'],))
            wallet = c.fetchone()
            balance_usd = wallet['balance_usd'] if wallet else 0.0
            c.execute("""
                SELECT id, amount_usd, crypto_currency, crypto_amount, wallet_address, status, requested_at
                FROM withdrawals 
                WHERE vendor_id = ? 
                ORDER BY requested_at DESC 
                LIMIT 5
            """, (session['user_id'],))
            withdrawals = [dict(row) for row in c.fetchall()]

        btc_price = get_crypto_price("BTC")
        xmr_price = get_crypto_price("XMR")
        return render_template('user/wallet.html', total_sales=total_sales, balance_usd=balance_usd, 
                              withdrawals=withdrawals, btc_price=btc_price, xmr_price=xmr_price)
    except Exception as e:
        print(f"Error in wallet: {str(e)}")
        flash("An error occurred while loading your wallet.", 'error')
        return redirect(url_for('public.index'))

@wallet_bp.route('/withdraw', methods=['POST'])
def withdraw():
    # Unchanged except for validation
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please log in.'}), 401

    amount_usd = request.form.get('amount_usd', type=float)
    crypto_currency = request.form.get('crypto_currency')
    wallet_address = request.form.get('wallet_address', '').strip()

    if not amount_usd or amount_usd <= 0:
        flash("Invalid withdrawal amount.", 'error')
        return redirect(url_for('wallet.wallet'))
    if crypto_currency not in ['BTC', 'XMR']:
        flash("Invalid cryptocurrency selected.", 'error')
        return redirect(url_for('wallet.wallet'))
    if not wallet_address or not validate_wallet_address(crypto_currency, wallet_address):
        flash(f"Invalid {crypto_currency} wallet address format.", 'error')
        return redirect(url_for('wallet.wallet'))

    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT balance_usd FROM vendor_wallets WHERE vendor_id = ?", (session['user_id'],))
            wallet = c.fetchone()
            balance_usd = wallet['balance_usd'] if wallet else 0.0

            if amount_usd > balance_usd:
                flash("Insufficient balance for withdrawal.", 'error')
                return redirect(url_for('wallet.wallet'))

            crypto_price = get_crypto_price(crypto_currency)
            if not crypto_price:
                flash("Unable to calculate crypto amount. Try again later.", 'error')
                return redirect(url_for('wallet.wallet'))
            crypto_amount = amount_usd / crypto_price

            c.execute("""
                INSERT INTO withdrawals (vendor_id, amount_usd, crypto_currency, crypto_amount, wallet_address)
                VALUES (?, ?, ?, ?, ?)
            """, (session['user_id'], amount_usd, crypto_currency, crypto_amount, wallet_address))
            c.execute("""
                INSERT INTO vendor_wallets (vendor_id, balance_usd) 
                VALUES (?, ?) 
                ON CONFLICT (vendor_id) DO UPDATE SET balance_usd = balance_usd - ?
            """, (session['user_id'], balance_usd - amount_usd, amount_usd))
            conn.commit()

        flash(f"Withdrawal request for {crypto_amount:.6f} {crypto_currency} submitted successfully!", 'success')
        return redirect(url_for('wallet.wallet'))
    except Exception as e:
        print(f"Error in withdraw: {str(e)}")
        flash("An error occurred during withdrawal.", 'error')
        return redirect(url_for('wallet.wallet'))

@wallet_bp.route('/admin/withdrawals', methods=['GET', 'POST'])
def admin_withdrawals():
    if 'user_id' not in session:
        flash("Please log in as an admin.", 'error')
        return redirect(url_for('auth.login'))

    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT role FROM users WHERE id = ?", (session['user_id'],))
            user = c.fetchone()
            if not user or user['role'] != 'admin':
                flash("Only admins can access this page.", 'error')
                return redirect(url_for('public.index'))

            if request.method == 'POST':
                withdrawal_id = request.form.get('withdrawal_id', type=int)
                action = request.form.get('action')

                if not withdrawal_id or action not in ['process', 'fail']:
                    flash("Invalid withdrawal ID or action.", 'error')
                    return redirect(url_for('wallet.admin_withdrawals'))

                c.execute("SELECT crypto_currency, crypto_amount, wallet_address FROM withdrawals WHERE id = ? AND status = 'pending'", (withdrawal_id,))
                withdrawal = c.fetchone()
                if not withdrawal:
                    flash("Withdrawal already processed or not found.", 'error')
                    return redirect(url_for('wallet.admin_withdrawals'))

                status = 'processed' if action == 'process' else 'failed'
                if action == 'process':
                    if withdrawal['crypto_currency'] == 'BTC':
                        btc_wallet = init_btc_wallet()
                        if btc_wallet:
                            tx = btc_wallet.send_to(withdrawal['wallet_address'], int(withdrawal['crypto_amount'] * 100000000),  # Convert to satoshis
                                                  fee=10000)  # Adjust fee as needed
                            if tx:
                                print(f"BTC TXID: {tx.txid}")
                            else:
                                flash("Failed to send BTC.", 'error')
                                status = 'failed'
                        else:
                            flash("BTC wallet unavailable.", 'error')
                            status = 'failed'
                    elif withdrawal['crypto_currency'] == 'XMR':
                        xmr_wallet = init_xmr_wallet()
                        if xmr_wallet:
                            tx = xmr_wallet.transfer(withdrawal['wallet_address'], withdrawal['crypto_amount'])
                            if tx:
                                print(f"XMR TXID: {tx.hash}")
                            else:
                                flash("Failed to send XMR.", 'error')
                                status = 'failed'
                        else:
                            flash("XMR wallet unavailable.", 'error')
                            status = 'failed'

                c.execute("""
                    UPDATE withdrawals 
                    SET status = ?, processed_at = ?
                    WHERE id = ?
                """, (status, datetime.datetime.now(), withdrawal_id))
                conn.commit()
                flash(f"Withdrawal {status} successfully!", 'success')

            c.execute("""
                SELECT w.id, w.amount_usd, w.crypto_currency, w.crypto_amount, w.wallet_address, w.requested_at, u.username
                FROM withdrawals w
                JOIN users u ON w.vendor_id = u.id
                WHERE w.status = 'pending'
                ORDER BY w.requested_at ASC
            """)
            withdrawals = [dict(row) for row in c.fetchall()]

        return render_template('admin/withdrawals.html', withdrawals=withdrawals)
    except Exception as e:
        print(f"Error in admin_withdrawals: {str(e)}")
        flash("An error occurred while processing withdrawals.", 'error')
        return redirect(url_for('public.index'))