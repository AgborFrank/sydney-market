-- Migration: Add pgp_key column to vendor_settings
ALTER TABLE vendor_settings ADD COLUMN pgp_key TEXT;