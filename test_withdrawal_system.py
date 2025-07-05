#!/usr/bin/env python3
"""
Test script to verify the withdrawal system functionality
"""

import sqlite3
import os
from datetime import datetime

def test_withdrawal_system():
    """Test the withdrawal system components"""
    
    # Check if database exists
    db_path = 'marketplace.db'
    if not os.path.exists(db_path):
        print("❌ Database not found. Please run the application first.")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        print("🔍 Testing Withdrawal System...")
        
        # 1. Check withdrawals table schema
        print("\n1. Checking withdrawals table schema...")
        c.execute("PRAGMA table_info(withdrawals)")
        columns = c.fetchall()
        required_columns = {
            'id': 'INTEGER',
            'user_id': 'INTEGER', 
            'amount_usd': 'REAL',
            'amount_btc': 'REAL',
            'crypto_currency': 'TEXT',
            'crypto_amount': 'REAL',
            'wallet_address': 'TEXT',
            'btc_address': 'TEXT',
            'status': 'TEXT',
            'txid': 'TEXT',
            'rejection_reason': 'TEXT',
            'requested_at': 'TIMESTAMP',
            'processed_at': 'TIMESTAMP'
        }
        
        found_columns = {col['name']: col['type'] for col in columns}
        missing_columns = []
        
        for col_name, col_type in required_columns.items():
            if col_name not in found_columns:
                missing_columns.append(col_name)
            elif found_columns[col_name] != col_type:
                print(f"⚠️  Column {col_name} has type {found_columns[col_name]} instead of {col_type}")
        
        if missing_columns:
            print(f"❌ Missing columns: {missing_columns}")
            return False
        else:
            print("✅ All required columns present")
        
        # 2. Check fees table
        print("\n2. Checking fees table...")
        c.execute("SELECT fee_type, percentage FROM fees WHERE fee_type = 'withdrawal'")
        fee = c.fetchone()
        if fee:
            print(f"✅ Withdrawal fee: {fee['percentage']}%")
        else:
            print("❌ No withdrawal fee found")
            return False
        
        # 3. Check for vendor users
        print("\n3. Checking for vendor users...")
        c.execute("SELECT id, pusername FROM users WHERE role = 'vendor' LIMIT 5")
        vendors = c.fetchall()
        if vendors:
            print(f"✅ Found {len(vendors)} vendor(s): {[v['pusername'] for v in vendors]}")
        else:
            print("⚠️  No vendor users found")
        
        # 4. Check balances table
        print("\n4. Checking balances table...")
        c.execute("SELECT COUNT(*) as count FROM balances")
        balance_count = c.fetchone()['count']
        print(f"✅ Found {balance_count} balance records")
        
        # 5. Check existing withdrawals
        print("\n5. Checking existing withdrawals...")
        c.execute("""
            SELECT w.id, w.status, w.amount_usd, w.crypto_currency, u.pusername
            FROM withdrawals w
            JOIN users u ON w.user_id = u.id
            WHERE u.role = 'vendor'
            ORDER BY w.requested_at DESC
            LIMIT 5
        """)
        withdrawals = c.fetchall()
        if withdrawals:
            print(f"✅ Found {len(withdrawals)} withdrawal(s):")
            for w in withdrawals:
                print(f"   - ID: {w['id']}, Status: {w['status']}, Amount: ${w['amount_usd']:.2f} {w['crypto_currency']}, Vendor: {w['pusername']}")
        else:
            print("ℹ️  No withdrawals found")
        
        # 6. Test withdrawal creation (simulation)
        print("\n6. Testing withdrawal creation...")
        if vendors:
            vendor_id = vendors[0]['id']
            test_amount = 10.0
            test_crypto = 'BTC'
            test_wallet = 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh'
            
            # Check if vendor has balance
            c.execute("SELECT balance_usd FROM balances WHERE user_id = ?", (vendor_id,))
            balance = c.fetchone()
            if balance and balance['balance_usd'] >= test_amount:
                print(f"✅ Vendor {vendors[0]['pusername']} has sufficient balance: ${balance['balance_usd']:.2f}")
                
                # Simulate withdrawal creation
                c.execute("""
                    INSERT INTO withdrawals (user_id, amount_usd, amount_btc, crypto_currency, crypto_amount, wallet_address, btc_address, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (vendor_id, test_amount, test_amount/50000, test_crypto, test_amount/50000, test_wallet, test_wallet, 'pending'))
                
                withdrawal_id = c.lastrowid
                print(f"✅ Created test withdrawal ID: {withdrawal_id}")
                
                # Clean up test withdrawal
                c.execute("DELETE FROM withdrawals WHERE id = ?", (withdrawal_id,))
                print("✅ Cleaned up test withdrawal")
            else:
                print(f"⚠️  Vendor {vendors[0]['pusername']} has insufficient balance")
        
        # 7. Test admin withdrawal queries
        print("\n7. Testing admin withdrawal queries...")
        c.execute("""
            SELECT w.id, u.pusername AS vendor_username, w.amount_usd, w.amount_btc, w.wallet_address,
                   w.status, w.requested_at, w.crypto_currency, w.crypto_amount
            FROM withdrawals w
            JOIN users u ON w.user_id = u.id
            WHERE u.role = 'vendor'
            ORDER BY w.requested_at DESC
            LIMIT 5
        """)
        admin_withdrawals = c.fetchall()
        print(f"✅ Admin query returned {len(admin_withdrawals)} withdrawal(s)")
        
        conn.close()
        print("\n🎉 Withdrawal system test completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Error testing withdrawal system: {str(e)}")
        return False

if __name__ == "__main__":
    test_withdrawal_system() 