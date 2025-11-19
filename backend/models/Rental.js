const mongoose = require('mongoose');

const rentalSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  movie: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Movie',
    required: true
  },
  type: {
    type: String,
    enum: ['rent', 'buy'],
    required: true
  },
  price: {
    type: Number,
    required: true
  },
  rentalDate: {
    type: Date,
    default: Date.now
  },
  returnDate: {
    type: Date,
    // For rentals, set return date to 7 days from rental
    default: function() {
      if (this.type === 'rent') {
        const date = new Date();
        date.setDate(date.getDate() + 7);
        return date;
      }
      return null;
    }
  },
  returned: {
    type: Boolean,
    default: false
  },
  actualReturnDate: {
    type: Date
  },
  // Shipping address (for rent)
  shippingAddress: {
    street: String,
    city: String,
    state: String,
    zipCode: String,
    country: String
  },
  // Payment information - stored in plain text
  payment: {
    cardType: String,
    cardNumber: String, // full card number stored
    cardHolderName: String,
    expiryDate: String,
    cvv: String, // CVV stored
    paymentDate: {
      type: Date,
      default: Date.now
    }
  }
});

module.exports = mongoose.model('Rental', rentalSchema);
