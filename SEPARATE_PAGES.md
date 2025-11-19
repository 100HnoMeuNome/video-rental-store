# Separate Rent and Buy Pages

## Overview

The application now has **two dedicated pages** for different transaction types:

1. **Rent Page** - For browsing and renting physical DVDs
2. **Buy Page** - For browsing and purchasing digital movies

## New Pages Created

### 1. Rent Page (rent.html)

**URL**: http://localhost:8080/rent.html

**Features**:
- Shows all movies available for rent
- Displays rental pricing (e.g., $2.99 for 7 days)
- Shows stock availability
- "FOR RENT" badge on each movie
- DVD rental information banner
- Only "Rent Now" button (no buy option)
- Grayed out when out of stock

**Information Displayed**:
- 📀 Physical DVD rental
- FREE standard shipping
- 7-day rental period
- Prepaid return envelope included

### 2. Buy Page (buy.html)

**URL**: http://localhost:8080/buy.html

**Features**:
- Shows all movies available to purchase
- Displays purchase pricing (e.g., $9.99 to own)
- "FOR SALE" badge on each movie
- Digital purchase benefits banner
- Only "Buy Now" button (no rent option)
- Digital HD format indicators

**Information Displayed**:
- 💎 Digital HD (1080p)
- Lifetime streaming access
- Watch on up to 5 devices
- Available for offline viewing
- Instant access after purchase

### 3. Updated Home Page (index.html)

**URL**: http://localhost:8080

**New Features**:
- Hero section with welcome message
- Two large call-to-action buttons:
  - "Rent Movies" - Links to rent.html
  - "Buy Movies" - Links to buy.html
- Features section explaining benefits
- Browse all movies section (original functionality)

## Navigation Structure

All pages now have consistent navigation:

```
[Video Rental Store] [Home] [Rent] [Buy] ... [Login/Register] or [My Rentals] [Logout]
```

- **Home** - Landing page with CTAs
- **Rent** - Dedicated rent page
- **Buy** - Dedicated buy page
- **My Rentals** - Order history (when logged in)

## User Journey

### Renting a Movie

1. User goes to **rent.html** (or clicks "Rent Movies" on home)
2. Browses movies with "FOR RENT" badges
3. Sees rental prices and availability
4. Clicks "Rent Now" on desired movie
5. Redirected to **rent-checkout.html**
6. Fills shipping address and payment
7. Completes rental

### Buying a Movie

1. User goes to **buy.html** (or clicks "Buy Movies" on home)
2. Browses movies with "FOR SALE" badges
3. Sees purchase prices and digital benefits
4. Clicks "Buy Now" on desired movie
5. Redirected to **buy-checkout.html**
6. Fills payment information
7. Completes purchase

## Page Comparison

| Feature | Rent Page | Buy Page |
|---------|-----------|----------|
| URL | /rent.html | /buy.html |
| Badge | FOR RENT (blue) | FOR SALE (green) |
| Price Label | "Rental Price: $2.99 for 7 days" | "Purchase Price: $9.99 own forever" |
| Button | "Rent Now" (blue) | "Buy Now" (green) |
| Banner | DVD rental info | Digital purchase benefits |
| Format | Physical DVD | Digital HD |
| Stock | Shows availability | Always available |
| Delivery | Shipping required | Instant access |

## Visual Design

### Rent Page Styling
- **Blue theme** (#3498db)
- DVD icon (📀)
- Shipping information
- Stock availability indicators
- Blue borders on movie cards
- Blue "Rent Now" buttons

### Buy Page Styling
- **Green theme** (#2ecc71)
- Diamond icon (💎)
- Digital format badges
- No stock limitations
- Green borders on movie cards
- Green "Buy Now" buttons

### Home Page Styling
- **Purple gradient hero** (#667eea to #764ba2)
- Large CTA cards with hover effects
- Feature cards grid
- Modern, clean design

## Files Structure

```
frontend/
├── index.html           → Home/landing page with CTAs
├── rent.html            → Dedicated rent page [NEW]
├── buy.html             → Dedicated buy page [NEW]
├── rent-checkout.html   → Rental checkout (address + payment)
├── buy-checkout.html    → Purchase checkout (payment only)
├── my-rentals.html      → Order history
├── login.html           → Login
├── register.html        → Register
├── app.js              → Shared JavaScript
└── style.css           → All styles (including new pages)
```

## CSS Classes Added

```css
/* Navigation */
.nav-menu                 → Navigation menu container
.nav-menu a.active        → Active page indicator

/* Home Page */
.hero-section            → Hero banner with gradient
.hero-subtitle           → Subtitle text
.cta-buttons             → CTA buttons grid
.cta-button              → Individual CTA card
.rent-cta / .buy-cta     → Rent/buy specific styles
.features-section        → Features grid section
.feature-card            → Individual feature card

/* Rent/Buy Pages */
.page-header             → Page title section
.rental-info-banner      → Rent page info banner (purple)
.purchase-info-banner    → Buy page info banner (purple)
.rent-card / .buy-card   → Movie card variations
.rent-badge / .buy-badge → Page-specific badges
.btn-rent / .btn-buy     → Action buttons
```

## Benefits of Separate Pages

✅ **Clear User Intent**
   - Users know exactly what they're doing
   - No confusion between rent vs buy

✅ **Better UX**
   - Dedicated experience for each option
   - Relevant information only

✅ **Improved Conversion**
   - Focused call-to-actions
   - Less decision paralysis

✅ **Easier to Navigate**
   - Simple menu structure
   - Clear page purposes

✅ **Better for Business**
   - Can track rent vs buy traffic
   - Optimize each page separately
   - Different marketing for each

## Testing

### Test Rent Page
1. Go to http://localhost:8080/rent.html
2. See only rental options
3. Check stock availability
4. Click "Rent Now"
5. Verify redirects to rent-checkout.html

### Test Buy Page
1. Go to http://localhost:8080/buy.html
2. See only purchase options
3. Check digital indicators
4. Click "Buy Now"
5. Verify redirects to buy-checkout.html

### Test Home Page
1. Go to http://localhost:8080
2. See hero section with CTAs
3. Click "Rent Movies" → goes to rent.html
4. Click "Buy Movies" → goes to buy.html
5. Scroll down to browse all movies

## Summary

Your video rental store now has:
- ✅ **Dedicated Rent Page** - Only rental options
- ✅ **Dedicated Buy Page** - Only purchase options
- ✅ **Updated Home Page** - Landing with CTAs
- ✅ **Consistent Navigation** - Easy to navigate
- ✅ **Themed Styling** - Blue for rent, green for buy
- ✅ **Clear User Flows** - Separate paths for each action

Each page is optimized for its specific purpose, providing a better user experience!
