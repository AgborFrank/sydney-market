# 🔐 Dark Web Marketplace Verification Guide

This document explains how to verify the authenticity of this dark web marketplace using the market's PGP key.

## 📋 Overview

The marketplace provides a public verification system that allows users to cryptographically verify that they are accessing the legitimate marketplace and not a phishing site. This is crucial for security on the dark web.

## 🔑 How It Works

1. **Market PGP Key**: The marketplace has a PGP keypair (public/private)
2. **Public Key Display**: The market's public key is displayed on the verification page
3. **Signed Messages**: The market signs verification messages with their private key
4. **User Verification**: Users can verify these signatures using the public key

## 🌐 Accessing Verification

Visit the verification page at: `https://your-marketplace.onion/verify`

This page displays:
- Admin's PGP public key
- Current verification message
- Signed message (if available)
- Step-by-step verification instructions

## 🛠️ Verification Process

### Step 1: Get the Market's PGP Key

1. Visit `/verify` on the marketplace
2. Copy the market's PGP public key from the page
3. Save it to a file (e.g., `market_key.asc`)

### Step 2: Import the Key

```bash
# Import the market's public key
gpg --import market_key.asc

# Verify the key was imported
gpg --list-keys
```

### Step 3: Get the Verification Message

1. Copy the verification message from the `/verify` page
2. Save it to a file (e.g., `verification.txt`)

### Step 4: Verify the Signature

```bash
# If you have a signed message file
gpg --verify message.sig verification.txt

# Check the key fingerprint
gpg --fingerprint [key-id]
```

## 🔒 Security Considerations

### What to Verify

1. **Key Fingerprint**: Ensure the key fingerprint matches the one published by the market
2. **Signature Validity**: The signature should be valid and not expired
3. **Message Content**: Verify the message contains expected information (site name, URL, timestamp)
4. **Key Trust**: Consider the trust level of the market's key

### Red Flags

- ❌ Invalid or expired signatures
- ❌ Wrong key fingerprint
- ❌ Suspicious message content
- ❌ Missing or corrupted signatures
- ❌ Keys that can't be verified through other channels

## 🛡️ Market Setup

### Setting Up Market PGP Key

1. **Generate Keypair**:
   ```bash
   gpg --full-generate-key
   # Choose RSA, 4096 bits, 2 years expiration
   ```

2. **Export Public Key**:
   ```bash
   gpg --armor --export [key-id] > market_public.asc
   ```

3. **Configure in Admin Panel**:
   - Go to Admin → Settings
   - Paste the public key in the "Market PGP Key" field
   - Save settings

### Signing Verification Messages

The market should regularly sign verification messages:

```bash
# Create a verification message
echo "MARKETPLACE VERIFICATION
Site: Your Marketplace Name
URL: https://your-marketplace.onion
Timestamp: $(date -u)
Market PGP Key Fingerprint: $(gpg --fingerprint [key-id] | grep fingerprint | cut -d' ' -f4)

This message confirms the authenticity of this marketplace." > verification.txt

# Sign the message
gpg --armor --detach-sign verification.txt
```

## 🔧 Technical Implementation

### Verification Endpoint

The marketplace includes a public verification endpoint at `/verify` that:

1. Retrieves market PGP key from settings
2. Generates current verification message
3. Displays key and message for user verification
4. Provides copy-paste functionality

### PGP Utilities

The system includes PGP utilities for:
- Key generation and management
- Message signing and verification
- Signature validation
- Key fingerprint extraction

### Security Features

- **No Private Key Storage**: Private keys should never be stored on the server
- **Public Key Only**: Only the public key is displayed
- **Timestamped Messages**: Verification messages include timestamps
- **Secure Signing**: Signing should be done offline with proper key management

## 📱 User Interface

The verification page includes:

- **Market PGP Key**: Full public key for import
- **Verification Message**: Current message to be signed
- **Signed Message**: PGP signature (when available)
- **Copy Buttons**: Easy copying of keys and messages
- **Instructions**: Step-by-step verification guide
- **Security Notes**: Important security considerations

## 🚨 Important Security Notes

1. **Never Trust Without Verification**: Always verify PGP signatures before trusting
2. **Check Key Fingerprints**: Ensure you have the correct market key
3. **Beware of Phishing**: Phishing sites may copy this verification page
4. **Key Management**: Keep your PGP keys secure and backed up
5. **Regular Updates**: Market should regularly update verification messages

## 🔍 Troubleshooting

### Common Issues

1. **Key Import Fails**: Check the key format and ensure it's complete
2. **Signature Invalid**: Verify you have the correct public key
3. **Key Not Found**: Ensure the key is properly imported
4. **Expired Signature**: Check if the signature has expired

### Verification Commands

```bash
# List imported keys
gpg --list-keys

# Check key details
gpg --fingerprint [key-id]

# Verify signature
gpg --verify signature.asc message.txt

# Check signature details
gpg --list-sigs [key-id]
```

## 📞 Support

If you encounter issues with verification:

1. Check the `/how-to-pgp` page for PGP setup instructions
2. Verify you have the correct market public key
3. Ensure your PGP client is properly configured
4. Contact support if the market key appears compromised

## 🔄 Regular Updates

The market should:

1. **Update Verification Messages**: Regularly sign new verification messages
2. **Key Rotation**: Consider rotating keys periodically
3. **Monitor Key Usage**: Watch for unauthorized use of the market key
4. **Backup Keys**: Maintain secure backups of keypairs

---

**Remember**: PGP verification is your primary defense against phishing and impersonation on the dark web. Always verify before trusting any marketplace.
