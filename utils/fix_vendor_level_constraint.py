#!/usr/bin/env python3
"""
Migration script to fix vendor_levels table constraint (level 1-10)
"""
import sqlite3
import sys
import os

def migrate_vendor_levels(db_path='marketplace.db'):
    if not os.path.exists(db_path):
        print(f"Database file {db_path} not found.")
        sys.exit(1)
    
    conn = sqlite3.connect(db_path)
    try:
        c = conn.cursor()
        print("Backing up vendor_levels table...")
        c.execute("ALTER TABLE vendor_levels RENAME TO vendor_levels_old;")
        print("Creating new vendor_levels table with correct constraint...")
        c.execute("""
            CREATE TABLE vendor_levels (
                vendor_id INTEGER PRIMARY KEY,
                level INTEGER NOT NULL DEFAULT 1 CHECK(level >= 1 AND level <= 10),
                sales_count INTEGER NOT NULL DEFAULT 0,
                positive_feedback_percentage REAL NOT NULL DEFAULT 0.0,
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (vendor_id) REFERENCES users(id)
            );
        """)
        print("Restoring data...")
        c.execute("""
            INSERT INTO vendor_levels (vendor_id, level, sales_count, positive_feedback_percentage, joined_at, updated_at)
            SELECT vendor_id, level, sales_count, positive_feedback_percentage, joined_at, updated_at
            FROM vendor_levels_old;
        """)
        print("Dropping old table...")
        c.execute("DROP TABLE vendor_levels_old;")
        conn.commit()
        print("✅ Migration complete! Vendor levels can now be set from 1 to 10.")
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        conn.rollback()
        sys.exit(1)
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_vendor_levels() 