-- Migration: Add new fields to vendor_settings for full vendor profile management
ALTER TABLE vendor_settings ADD COLUMN pgp_public_key TEXT;

ALTER TABLE vendor_settings
ADD COLUMN bond_status TEXT DEFAULT 'Not posted';

ALTER TABLE vendor_settings
ADD COLUMN verification_status TEXT DEFAULT 'Unverified';

ALTER TABLE vendor_settings ADD COLUMN shipping_methods TEXT;

ALTER TABLE vendor_settings
ADD COLUMN vacation_mode TEXT DEFAULT 'off';

ALTER TABLE vendor_settings
ADD COLUMN notify_orders INTEGER DEFAULT 1;

ALTER TABLE vendor_settings
ADD COLUMN notify_messages INTEGER DEFAULT 1;

ALTER TABLE vendor_settings
ADD COLUMN notify_disputes INTEGER DEFAULT 1;

ALTER TABLE vendor_settings ADD COLUMN btc_address TEXT;

ALTER TABLE vendor_settings ADD COLUMN xmr_address TEXT;

ALTER TABLE vendor_settings ADD COLUMN banner TEXT;