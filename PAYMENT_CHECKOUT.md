# Payment and Checkout Features

## Overview

The Video Rental Store now includes complete checkout flows for both renting and purchasing movies, including address collection for rentals and secure payment processing.

## Features Added

### 1. Rent Checkout Flow
When a user clicks "Rent" on a movie, they are taken to a dedicated checkout page that collects:

- **Shipping Address**
  - Street address
  - City
  - State
  - ZIP code
  - Country

- **Payment Information**
  - Cardholder name
  - Card number (masked for security)
  - Expiry date
  - CVV
  - Card type auto-detection (Visa, Mastercard, etc.)

- **Rental Terms**
  - 7-day rental period
  - Return conditions
  - Terms acceptance checkbox

### 2. Buy Checkout Flow
When a user clicks "Buy" on a movie, they are taken to a purchase checkout page that collects:

- **Payment Information**
  - Cardholder name
  - Card number (masked for security)
  - Expiry date
  - CVV
  - Billing ZIP code
  - Card type auto-detection

- **Purchase Details**
  - Digital download in HD
  - Lifetime streaming access
  - Up to 5 devices
  - 1080p quality
  - Offline viewing

- **Tax Calculation**
  - 8% tax applied to purchase price
  - Total amount displayed

### 3. Security Features

**Card Number Protection:**
- Full card numbers are NEVER stored
- Only the last 4 digits are saved
- CVV is never stored (only used for validation)
- Transaction IDs generated for tracking

**Data Masked in Database:**
```javascript
payment: {
  cardType: 'Visa',
  lastFourDigits: '1234',
  cardHolderName: 'John Doe',
  transactionId: 'TXN-1697654400-ABC123XYZ'
}
```

## File Structure

### New Frontend Files
- **[frontend/rent-checkout.html](frontend/rent-checkout.html)** - Rental checkout page with address form
- **[frontend/buy-checkout.html](frontend/buy-checkout.html)** - Purchase checkout page

### Updated Files
- **[backend/models/Rental.js](backend/models/Rental.js)** - Added shippingAddress and payment fields
- **[backend/routes/rentals.js](backend/routes/rentals.js)** - Updated to process payment and address
- **[frontend/app.js](frontend/app.js)** - Updated to redirect to checkout pages
- **[frontend/my-rentals.html](frontend/my-rentals.html)** - Shows payment and shipping info
- **[frontend/style.css](frontend/style.css)** - Added checkout page styles

## User Flow

### Renting a Movie

1. User browses movies on home page
2. Clicks "Rent" button on a movie
3. Redirected to **rent-checkout.html?movieId=123**
4. Fills out shipping address form
5. Enters payment information
6. Accepts rental terms
7. Clicks "Complete Rental"
8. Backend processes:
   - Validates all fields
   - Masks card number (stores only last 4 digits)
   - Generates transaction ID
   - Creates rental record with address and payment
   - Decrements movie stock
9. User redirected to "My Rentals" page
10. Rental shows shipping address and payment info

### Buying a Movie

1. User browses movies on home page
2. Clicks "Buy" button on a movie
3. Redirected to **buy-checkout.html?movieId=123**
4. Enters payment information
5. Reviews purchase details (digital HD, lifetime access)
6. Accepts terms of service
7. Clicks "Complete Purchase"
8. Backend processes:
   - Validates payment info
   - Masks card number
   - Generates transaction ID
   - Creates purchase record
   - Calculates tax (8%)
9. User redirected to "My Rentals" page
10. Purchase shows in digital library

## API Changes

### Updated POST /api/rentals

**Request Body (Rent):**
```json
{
  "movieId": "507f1f77bcf86cd799439011",
  "type": "rent",
  "shippingAddress": {
    "street": "123 Main St, Apt 4B",
    "city": "Los Angeles",
    "state": "CA",
    "zipCode": "90001",
    "country": "USA"
  },
  "payment": {
    "cardHolderName": "John Doe",
    "cardNumber": "4532123456789012",
    "cardType": "Visa",
    "cvv": "123",
    "expiryDate": "12/25"
  }
}
```

**Request Body (Buy):**
```json
{
  "movieId": "507f1f77bcf86cd799439011",
  "type": "buy",
  "payment": {
    "cardHolderName": "John Doe",
    "cardNumber": "5412123456789012",
    "cardType": "Mastercard",
    "cvv": "456",
    "expiryDate": "06/26",
    "billingZip": "90001"
  }
}
```

**Response:**
```json
{
  "message": "Movie rented successfully",
  "rental": {
    "_id": "507f1f77bcf86cd799439013",
    "user": "507f1f77bcf86cd799439010",
    "movie": {
      "title": "The Matrix",
      "director": "The Wachowskis"
    },
    "type": "rent",
    "price": 3.99,
    "shippingAddress": {
      "street": "123 Main St, Apt 4B",
      "city": "Los Angeles",
      "state": "CA",
      "zipCode": "90001",
      "country": "USA"
    },
    "payment": {
      "cardType": "Visa",
      "lastFourDigits": "9012",
      "cardHolderName": "John Doe",
      "transactionId": "TXN-1697654400-ABC123XYZ"
    },
    "rentalDate": "2024-10-18T10:30:00.000Z",
    "returnDate": "2024-10-25T10:30:00.000Z"
  },
  "transactionId": "TXN-1697654400-ABC123XYZ"
}
```

## Frontend Features

### Form Validation

**Card Number:**
- Auto-formats with spaces (e.g., "1234 5678 9012 3456")
- 13-19 digits accepted
- Detects card type automatically

**Expiry Date:**
- Auto-formats as MM/YY
- Validates format

**ZIP Code:**
- 5-digit numeric validation

**CVV:**
- 3-4 digits accepted

### Card Type Detection

```javascript
function detectCardType(cardNumber) {
    if (cardNumber.startsWith('4')) return 'Visa';
    if (cardNumber.startsWith('5')) return 'Mastercard';
    if (cardNumber.startsWith('3')) return 'American Express';
    if (cardNumber.startsWith('6')) return 'Discover';
    return 'Unknown';
}
```

### Real-time Formatting

- Card numbers automatically formatted with spaces
- Expiry dates auto-format to MM/YY pattern
- Form prevents invalid characters

## Database Schema

### Rental Model Updates

```javascript
const rentalSchema = new mongoose.Schema({
  user: { type: ObjectId, ref: 'User', required: true },
  movie: { type: ObjectId, ref: 'Movie', required: true },
  type: { type: String, enum: ['rent', 'buy'], required: true },
  price: { type: Number, required: true },
  rentalDate: { type: Date, default: Date.now },
  returnDate: { type: Date },
  returned: { type: Boolean, default: false },
  actualReturnDate: { type: Date },

  // NEW: Shipping address (for rent)
  shippingAddress: {
    street: String,
    city: String,
    state: String,
    zipCode: String,
    country: String
  },

  // NEW: Payment information (masked)
  payment: {
    cardType: String,
    lastFourDigits: String,    // Only last 4 digits
    cardHolderName: String,
    transactionId: String,
    paymentDate: { type: Date, default: Date.now }
  }
});
```

## Security Best Practices Implemented

✅ **Never store full card numbers** - Only last 4 digits saved
✅ **Never store CVV** - Used only for validation, immediately discarded
✅ **Generate unique transaction IDs** - For tracking and auditing
✅ **Mask sensitive data** - Card numbers never appear in logs or responses
✅ **HTTPS recommended** - For production deployment
✅ **Token-based authentication** - JWT tokens protect all transactions

## Testing the Checkout

### 1. Start the Application
```bash
cd video-rental-store
docker-compose up -d
```

### 2. Register and Login
- Go to http://localhost:8080/register.html
- Create an account
- Login

### 3. Test Renting
- Browse movies on home page
- Click "Rent" on any movie
- Fill out shipping address:
  - Street: 123 Test St
  - City: Los Angeles
  - State: CA
  - ZIP: 90001
  - Country: USA
- Fill out payment (test card):
  - Name: Test User
  - Card: 4532 1234 5678 9012 (Visa)
  - Expiry: 12/25
  - CVV: 123
- Accept terms
- Click "Complete Rental"

### 4. Test Buying
- Click "Buy" on any movie
- Fill out payment (test card):
  - Name: Test User
  - Card: 5412 1234 5678 9012 (Mastercard)
  - Expiry: 06/26
  - CVV: 456
  - Billing ZIP: 90001
- Accept terms
- Click "Complete Purchase"

### 5. View Your Rentals/Purchases
- Go to "My Rentals" page
- See transaction details including:
  - Payment method (last 4 digits)
  - Transaction ID
  - Shipping address (for rentals)
  - Status

## Important Notes

### Test Card Numbers
For development/testing, you can use these patterns:
- **Visa:** Starts with 4 (e.g., 4532123456789012)
- **Mastercard:** Starts with 5 (e.g., 5412123456789012)
- **American Express:** Starts with 3 (e.g., 371234567890123)
- **Discover:** Starts with 6 (e.g., 6011123456789012)

### Production Considerations
For production deployment, you should:
1. Integrate with real payment gateway (Stripe, PayPal, etc.)
2. Add PCI compliance measures
3. Use HTTPS/SSL certificates
4. Add fraud detection
5. Implement proper error handling
6. Add payment retry logic
7. Send confirmation emails
8. Add refund/cancellation functionality

### Future Enhancements
- Payment gateway integration (Stripe, PayPal)
- Multiple payment methods (Apple Pay, Google Pay)
- Save payment methods for future use
- Order history and invoices
- Email receipts
- Payment status tracking
- Refund processing
- Shipping tracking for physical rentals

## Troubleshooting

### Payment Not Processing
- Check all required fields are filled
- Verify card number is valid format
- Ensure terms checkbox is checked
- Check browser console for errors

### Address Not Saving
- Verify all required address fields filled
- Check for special characters in address
- Ensure ZIP code is 5 digits

### Transaction ID Not Showing
- Refresh the "My Rentals" page
- Check that rental was successfully created
- Verify you're logged in with correct account

## Summary

The payment and checkout system provides:
- ✅ Complete rental checkout with shipping address
- ✅ Complete purchase checkout with digital delivery
- ✅ Secure payment processing with card masking
- ✅ Transaction tracking with unique IDs
- ✅ Form validation and auto-formatting
- ✅ Responsive design for mobile/desktop
- ✅ User-friendly checkout experience
- ✅ Order history with full details

All sensitive payment data is properly masked and secured!
