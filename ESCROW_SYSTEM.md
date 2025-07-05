# Escrow System Documentation

## Overview

The marketplace implements a secure escrow system similar to Abacus Market, where all orders are held in escrow until the buyer confirms receipt or the admin finalizes the order. The system includes automatic finalization for trusted vendors with positive feedback.

## Escrow Flow

### 1. Order Placement
- Buyer places an order and sends BTC to the multisig escrow address
- Order status: `pending`, Escrow status: `pending`

### 2. Payment Confirmation
- Buyer confirms payment was sent
- Order status: `paid`, Escrow status: `held`
- Vendor is notified and can ship the order

### 3. Vendor Ships
- Vendor marks order as `shipped`
- Order status: `shipped`, Escrow status: `held`

### 4. Buyer Receives Product
- Buyer has two options:
  - **Release Funds**: Confirm receipt and release escrow
  - **Dispute**: Create a dispute if there are issues

### 5. Escrow Finalization

#### For Trusted Vendors (Auto-Finalization)
**Criteria:**
- Vendor Level 8+ 
- 97%+ positive feedback
- 500+ total sales

**Process:**
- Buyer clicks "Release" → Funds automatically released to vendor
- Order status: `completed`, Escrow status: `released`
- Vendor receives funds minus 5% platform fee

#### For Standard Vendors (Manual Review)
**Process:**
- Buyer clicks "Release" → Escrow status: `pending_release`
- Admin reviews and manually finalizes within 24 hours
- Admin can release funds to vendor or refund to buyer

### 6. Auto-Finalization for Trusted Vendors
- Background job runs every hour
- Finds orders with `pending_release` status for trusted vendors
- Automatically finalizes after 24 hours if buyer doesn't release

## Escrow Statuses

| Status | Description |
|--------|-------------|
| `pending` | Payment not yet confirmed |
| `held` | Payment confirmed, funds locked in escrow |
| `pending_release` | Buyer requested release, awaiting admin review |
| `released` | Funds released to vendor |
| `refunded` | Funds refunded to buyer |
| `disputed` | Order in dispute resolution |

## Admin Escrow Management

### Features
- **View All Escrow Transactions**: Admin can see all escrow transactions across the marketplace
- **Vendor Information**: Shows vendor level, feedback percentage, and sales count
- **Trusted Vendor Status**: Clearly indicates which vendors qualify for auto-finalization
- **Manual Actions**: Admin can manually release or refund funds
- **Auto-Finalization**: Button to manually trigger auto-finalization for testing

### Admin Actions
1. **View Escrow Details**: Click "View Details" to see full transaction information
2. **Release Funds**: Select "Release Funds" to finalize and pay vendor
3. **Refund Funds**: Select "Refund Funds" to return money to buyer
4. **Auto-Finalize**: Click "Auto-Finalize Trusted Vendors" to process pending releases

## Trusted Vendor System

### Criteria for Auto-Finalization
- **Vendor Level**: 8 or higher
- **Positive Feedback**: 97% or higher
- **Total Sales**: 500 or more completed orders

### Benefits
- **Faster Payments**: Funds released immediately when buyer confirms
- **Reduced Admin Workload**: Automatic processing for reliable vendors
- **Better User Experience**: Faster transaction completion

## Dispute Resolution

### Buyer Dispute Process
1. Buyer clicks "Dispute" button
2. System creates dispute record
3. Order status: `disputed`, Escrow status: `disputed`
4. Admin reviews evidence and resolves

### Admin Dispute Actions
- **Release to Vendor**: If vendor is in the right
- **Refund to Buyer**: If buyer is in the right
- **Escalate**: For complex cases requiring further review

## Security Features

### Multisig Escrow
- 2-of-3 multisig addresses (buyer, vendor, platform)
- Requires 2 signatures to release funds
- Platform acts as neutral third party

### Automatic Expiry
- Orders automatically refunded after 14 days if not finalized
- Prevents funds from being locked indefinitely

### Fee Structure
- 5% platform fee on all completed transactions
- Fee deducted from vendor payout
- Transparent fee structure

## Database Schema

### Key Tables
- `orders`: Order information and status
- `escrow`: Escrow transaction details
- `vendor_levels`: Vendor trust metrics
- `disputes`: Dispute resolution records
- `balances`: User balance tracking

### Important Fields
- `orders.escrow_status`: Current escrow state
- `escrow.status`: Escrow transaction state
- `vendor_levels.level`: Vendor trust level (1-10)
- `vendor_levels.positive_feedback_percentage`: Feedback score
- `vendor_levels.sales_count`: Total completed sales

## API Endpoints

### Public Routes
- `POST /order/confirm/<order_id>`: Confirm payment
- `POST /release_escrow/<order_id>`: Release escrow funds
- `POST /dispute_order/<order_id>`: Create dispute

### Admin Routes
- `GET /admin/escrow`: View all escrow transactions
- `GET /admin/escrow_details/<order_id>`: View escrow details
- `POST /admin/update_escrow/<order_id>`: Update escrow status
- `POST /admin/auto_finalize_trusted_orders`: Trigger auto-finalization

## Testing

### Manual Testing
1. Create test orders with different vendor levels
2. Test buyer release functionality
3. Test admin manual finalization
4. Test auto-finalization for trusted vendors
5. Test dispute creation and resolution

### Background Jobs
- Auto-finalization runs every hour
- Expired order cleanup runs daily
- Vendor level updates triggered by sales

## Monitoring

### Key Metrics
- Escrow transaction volume
- Average time to finalization
- Dispute rate by vendor level
- Auto-finalization success rate

### Alerts
- Failed escrow transactions
- High dispute rates
- System errors in auto-finalization

## Future Enhancements

### Planned Features
- **Escrow Insurance**: Optional insurance for high-value orders
- **Partial Releases**: Support for partial escrow releases
- **Multi-Currency**: Support for XMR escrow
- **Advanced Analytics**: Detailed escrow performance metrics
- **Mobile Notifications**: Real-time escrow status updates

### Security Improvements
- **Hardware Security Modules**: Enhanced key management
- **Audit Logging**: Comprehensive transaction logging
- **Rate Limiting**: Protection against abuse
- **Fraud Detection**: AI-powered fraud detection system 