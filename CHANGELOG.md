# Changelog

## [1.1.0] - Payment and Checkout System

### Added

#### New Pages
- **rent-checkout.html** - Complete checkout page for movie rentals
  - Shipping address form (street, city, state, ZIP, country)
  - Payment information form
  - Rental terms and conditions
  - Order summary with pricing
  
- **buy-checkout.html** - Complete checkout page for movie purchases
  - Payment information form
  - Purchase details (digital HD, lifetime access)
  - Tax calculation (8%)
  - Order summary with total

#### Backend Updates
- **Rental Model** - Extended with new fields:
  - `shippingAddress` object (for rentals)
  - `payment` object with masked card info
  - Transaction ID generation
  
- **Rental Routes** - Enhanced POST /api/rentals endpoint:
  - Validates payment information
  - Validates shipping address for rentals
  - Masks card numbers (stores only last 4 digits)
  - Generates unique transaction IDs
  - Never stores CVV or full card numbers

#### Frontend Updates
- **app.js** - Updated rent/buy flow:
  - Now redirects to checkout pages instead of direct purchase
  - Improved user experience with dedicated checkout flows
  
- **my-rentals.html** - Enhanced rental history:
  - Shows payment method (masked)
  - Displays transaction ID
  - Shows shipping address for rentals
  - Better formatting and organization
  
- **style.css** - New checkout styles:
  - Checkout container and forms
  - Payment form styling
  - Address form styling
  - Responsive design for mobile
  - Security badges and notices

#### Security Features
- Card number masking (only last 4 digits stored)
- CVV never stored
- Unique transaction ID generation
- Secure payment data handling
- No sensitive data in logs or responses

### Changed
- Rent/Buy buttons now redirect to checkout pages
- Payment is required for all transactions
- Enhanced order history display

### Security
- Implemented proper card number masking
- Added transaction ID tracking
- Improved data validation
- Never store CVV codes

---

## [1.0.0] - Initial Release

### Features
- User registration and authentication
- Movie catalog with search and filters
- Rent and buy movies
- User rental history
- Public API for movie management
- MongoDB database
- Docker and Kubernetes deployment
- Datadog APM and Application Security
- JWT authentication with hardcoded secret
