# 🎯 Sydney Marketplace Advertising System

## Overview

The Sydney Marketplace Advertising System is a comprehensive, privacy-focused advertising platform that allows vendors to promote their products using cryptocurrency payments. The system is designed with anonymity, security, and user privacy as top priorities.

## 🚀 Features

### Core Advertising Features
- **Multiple Placement Types**: Homepage featured, category top, search results, sidebar promoted
- **Cryptocurrency Payments**: Bitcoin (BTC) and Monero (XMR) support
- **Real-time Bidding**: Competitive bidding system for ad placement
- **Performance Tracking**: Detailed analytics and click-through rate monitoring
- **Budget Management**: Daily budget limits and automatic refunds
- **Privacy-First**: No IP tracking, no user profiling, minimal data collection

### Vendor Dashboard Features
- **Campaign Management**: Create, edit, pause, and delete ad campaigns
- **Performance Analytics**: Real-time metrics and insights
- **Budget Control**: Set daily budgets and monitor spending
- **Product Selection**: Choose from eligible active products
- **Pricing Transparency**: Clear pricing structure and cost estimates

### Technical Features
- **Responsive Design**: Works on all devices and screen sizes
- **Tor Network Compatible**: Designed for anonymous access
- **PGP Encryption**: Secure communication for support
- **Auto-Expiration**: Campaigns automatically end after duration
- **Refund System**: Unused budget automatically refunded

## 📊 Database Schema

### Sponsored Ads Table
```sql
CREATE TABLE sponsored_ads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    placement_type TEXT NOT NULL,
    bid_amount REAL NOT NULL,
    daily_budget REAL NOT NULL,
    crypto_currency TEXT NOT NULL,
    duration_days INTEGER NOT NULL,
    status TEXT CHECK(status IN ('active', 'paused', 'ended')) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vendor_id) REFERENCES users(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);
```

### Ad Impressions Table
```sql
CREATE TABLE ad_impressions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ad_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    impression_count INTEGER DEFAULT 0,
    click_count INTEGER DEFAULT 0,
    cost REAL DEFAULT 0.0,
    date DATE DEFAULT CURRENT_DATE,
    FOREIGN KEY (ad_id) REFERENCES sponsored_ads(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);
```

### Ad Payments Table
```sql
CREATE TABLE ad_payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor_id INTEGER NOT NULL,
    amount REAL NOT NULL,
    status TEXT CHECK(status IN ('pending', 'completed', 'failed')) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vendor_id) REFERENCES users(id)
);
```

## 💰 Pricing Structure

### Placement Types and Base Costs

| Placement Type | Base Cost (BTC) | Base Cost (XMR) | Max Duration | Priority | Description |
|----------------|-----------------|-----------------|--------------|----------|-------------|
| Homepage Featured | 0.001 | 0.05 | 7 days | 1 | Featured placement on homepage carousel |
| Category Top | 0.0005 | 0.025 | 14 days | 2 | Top placement in category pages |
| Search Results | 0.0002 | 0.01 | 30 days | 3 | Sponsored placement in search results |
| Sidebar Promoted | 0.0003 | 0.015 | 21 days | 4 | Promoted products in sidebar |

### Bidding System
- **Competitive Bidding**: Higher bids get better placement
- **Pay-per-Impression**: Only pay for actual impressions
- **Daily Budget Limits**: Control spending with daily caps
- **Automatic Refunds**: Unused budget returned to vendor wallet

## 🛠️ Implementation Details

### Routes Structure
```
/ads/
├── dashboard/          # Vendor ads dashboard
├── create/            # Create new ad campaign
├── edit/<id>/         # Edit existing campaign
├── delete/<id>/       # Delete campaign
├── analytics/<id>/    # Campaign analytics
├── pricing/           # Pricing information
└── api/
    ├── get_ads/<type>/     # Get ads for placement
    └── record_click/<id>/  # Record ad clicks
```

### Key Functions

#### `get_sponsored_ads(placement_type, limit)`
- Fetches active ads for specific placement
- Orders by bid amount (highest first)
- Records impressions automatically
- Filters for active products with stock

#### `record_ad_click(ad_id)`
- Records click events for analytics
- Updates click count in database
- Validates ad is still active

#### Campaign Management
- **Create**: Select product, placement, set budget and duration
- **Edit**: Modify bid amount, daily budget, status
- **Delete**: Remove campaign and refund unused budget
- **Pause**: Temporarily stop campaign without losing budget

### Frontend Components

#### Sponsored Ads Component (`templates/components/sponsored_ads.html`)
- **Grid Layout**: Responsive grid for multiple ads
- **Carousel**: Auto-advancing carousel for featured ads
- **Sidebar**: Compact sidebar ads
- **Click Tracking**: Automatic click recording
- **Visual Indicators**: Clear "Sponsored" badges

#### Templates
- **Dashboard**: Campaign overview and management
- **Create**: Step-by-step campaign creation
- **Analytics**: Detailed performance metrics
- **Pricing**: Transparent pricing information

## 🔒 Privacy & Security Features

### Privacy Protection
- **No IP Logging**: No IP addresses stored
- **No User Profiling**: No tracking across sessions
- **Minimal Data**: Only necessary campaign data stored
- **Auto-Deletion**: Data automatically deleted after campaign ends

### Security Measures
- **PGP Encryption**: Secure vendor communications
- **Cryptocurrency Only**: No traditional payment methods
- **Session Security**: Secure session management
- **CSRF Protection**: Cross-site request forgery protection

### Data Retention
- **Active Campaigns**: Data retained while active
- **Completed Campaigns**: Data deleted after 30 days
- **Analytics**: Performance data deleted after 90 days
- **Payment Records**: Minimal transaction records kept

## 📈 Analytics & Performance

### Metrics Tracked
- **Impressions**: Number of times ad was displayed
- **Clicks**: Number of clicks on ad
- **Click-Through Rate**: Clicks divided by impressions
- **Cost per Click**: Total cost divided by clicks
- **Daily Performance**: Performance by day
- **Budget Utilization**: How much of daily budget was used

### Performance Insights
- **Best Performing Days**: Days with highest engagement
- **Average Metrics**: Daily averages for comparison
- **Recommendations**: AI-powered optimization suggestions
- **Trend Analysis**: Performance trends over time

## 🎨 User Interface

### Design Principles
- **Dark Theme**: Consistent with marketplace design
- **Responsive**: Works on all device sizes
- **Accessible**: WCAG compliant design
- **Intuitive**: Easy-to-use interface

### Key UI Elements
- **Campaign Cards**: Visual campaign overview
- **Performance Charts**: Interactive analytics
- **Budget Controls**: Easy budget management
- **Status Indicators**: Clear campaign status

## 🚀 Getting Started

### For Vendors

1. **Access Ads Dashboard**
   - Navigate to vendor dashboard
   - Click "Advertising" link
   - Or visit `/ads/dashboard`

2. **Create First Campaign**
   - Click "Create New Ad"
   - Select eligible product
   - Choose placement type
   - Set bid amount and budget
   - Confirm and pay

3. **Monitor Performance**
   - View real-time analytics
   - Track impressions and clicks
   - Monitor budget usage
   - Optimize based on insights

### For Developers

1. **Database Setup**
   ```bash
   # Tables are created automatically by init_db()
   python app.py
   ```

2. **Register Blueprint**
   ```python
   # Already done in routes/__init__.py
   app.register_blueprint(ads_bp, url_prefix='/ads')
   ```

3. **Add to Templates**
   ```html
   {% from 'components/sponsored_ads.html' import render_sponsored_ads %}
   {{ render_sponsored_ads('homepage_featured', 3) }}
   ```

## 🔧 Configuration

### Environment Variables
```bash
# Required for crypto payments
BTC_NODE_URL=your_btc_node_url
XMR_WALLET_RPC=your_xmr_wallet_rpc

# Optional settings
AD_MIN_BID_BTC=0.0001
AD_MIN_BID_XMR=0.005
AD_MAX_DAILY_BUDGET_BTC=0.01
AD_MAX_DAILY_BUDGET_XMR=0.5
```

### Settings Table
```sql
-- Add to settings table
INSERT INTO settings (key, value) VALUES
('ad_min_bid_btc', '0.0001'),
('ad_min_bid_xmr', '0.005'),
('ad_max_duration_days', '30'),
('ad_auto_pause_threshold', '0.1');
```

## 📊 Performance Optimization

### Database Indexes
```sql
CREATE INDEX idx_sponsored_ads_placement_status ON sponsored_ads(placement_type, status);
CREATE INDEX idx_sponsored_ads_bid_amount ON sponsored_ads(bid_amount DESC);
CREATE INDEX idx_ad_impressions_date ON ad_impressions(date);
CREATE INDEX idx_ad_impressions_ad_id ON ad_impressions(ad_id);
```

### Caching Strategy
- **Redis Caching**: Cache active ads for 5 minutes
- **Query Optimization**: Efficient database queries
- **Lazy Loading**: Load ads only when needed
- **CDN Integration**: Fast image delivery

## 🧪 Testing

### Unit Tests
```python
# Test ad creation
def test_create_ad():
    # Test valid ad creation
    # Test invalid data handling
    # Test budget validation

# Test impression tracking
def test_impression_tracking():
    # Test impression recording
    # Test click recording
    # Test cost calculation
```

### Integration Tests
```python
# Test full campaign lifecycle
def test_campaign_lifecycle():
    # Create campaign
    # Record impressions
    # Record clicks
    # End campaign
    # Verify refunds
```

## 🚨 Troubleshooting

### Common Issues

1. **Ads Not Displaying**
   - Check product status (must be active)
   - Verify vendor has sufficient balance
   - Check campaign status (must be active)

2. **Performance Issues**
   - Monitor database query performance
   - Check Redis connection
   - Verify image loading

3. **Payment Issues**
   - Verify cryptocurrency balances
   - Check transaction confirmations
   - Review payment logs

### Debug Mode
```python
# Enable debug logging
logging.getLogger('ads').setLevel(logging.DEBUG)

# Check ad loading
print(get_sponsored_ads('homepage_featured'))
```

## 🔮 Future Enhancements

### Planned Features
- **A/B Testing**: Test different ad creatives
- **Targeting Options**: Category and price targeting
- **Advanced Analytics**: Conversion tracking
- **Bulk Operations**: Manage multiple campaigns
- **API Access**: External campaign management

### Performance Improvements
- **Machine Learning**: Optimize bid suggestions
- **Predictive Analytics**: Forecast campaign performance
- **Real-time Bidding**: Dynamic bid adjustments
- **Advanced Targeting**: User behavior targeting

## 📚 API Documentation

### Endpoints

#### GET `/ads/api/get_ads/<placement_type>`
Returns active ads for specific placement.

**Response:**
```json
{
  "ads": [
    {
      "id": 1,
      "product_id": 123,
      "title": "Product Name",
      "price_usd": 99.99,
      "vendor_name": "VendorName",
      "featured_image": "path/to/image.jpg"
    }
  ]
}
```

#### POST `/ads/api/record_click/<ad_id>`
Records a click on an ad.

**Response:**
```json
{
  "success": true
}
```

## 🤝 Contributing

### Development Guidelines
1. **Privacy First**: Always prioritize user privacy
2. **Security**: Implement proper security measures
3. **Testing**: Write comprehensive tests
4. **Documentation**: Update documentation for changes
5. **Performance**: Optimize for speed and efficiency

### Code Style
- Follow PEP 8 for Python code
- Use meaningful variable names
- Add proper comments and docstrings
- Implement error handling

## 📄 License

This advertising system is part of the Sydney Marketplace project and follows the same licensing terms.

---

**Note**: This advertising system is designed specifically for privacy-focused marketplaces and may not be suitable for traditional e-commerce platforms that require extensive user tracking and profiling. 