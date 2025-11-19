const express = require('express');
const router = express.Router();
const Rental = require('../models/Rental');
const Movie = require('../models/Movie');
const { authenticate } = require('../middleware/auth');

// Get user's rentals
router.get('/my-rentals', authenticate, async (req, res) => {
  try {
    const rentals = await Rental.find({ user: req.user._id })
      .populate('movie')
      .sort({ rentalDate: -1 });

    res.json({ rentals });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching rentals', error: error.message });
  }
});

// Rent or buy a movie
router.post('/', authenticate, async (req, res) => {
  try {
    const { movieId, type, shippingAddress, payment } = req.body; // type: 'rent' or 'buy'

    if (!['rent', 'buy'].includes(type)) {
      return res.status(400).json({ message: 'Invalid transaction type. Use "rent" or "buy"' });
    }

    // Validate payment information
    if (!payment || !payment.cardNumber || !payment.cardHolderName) {
      return res.status(400).json({ message: 'Payment information is required' });
    }

    // For rentals, validate shipping address
    if (type === 'rent' && (!shippingAddress || !shippingAddress.street || !shippingAddress.city)) {
      return res.status(400).json({ message: 'Shipping address is required for rentals' });
    }

    // Find the movie
    const movie = await Movie.findById(movieId);
    if (!movie) {
      return res.status(404).json({ message: 'Movie not found' });
    }

    // Check if movie is available
    if (type === 'rent' && movie.stock.available <= 0) {
      return res.status(400).json({ message: 'Movie not available for rent' });
    }

    // Store payment information (full card details stored in plain text)
    const cardNumber = payment.cardNumber.replace(/\s/g, '');

    console.log('=== PAYMENT INFORMATION ===');
    console.log('Card Number:', cardNumber);
    console.log('CVV:', payment.cvv);
    console.log('Expiry:', payment.expiryDate);
    console.log('Cardholder:', payment.cardHolderName);
    console.log('===========================');

    // Create rental record
    const price = type === 'rent' ? movie.pricing.rent : movie.pricing.buy;
    const rental = new Rental({
      user: req.user._id,
      movie: movieId,
      type,
      price,
      shippingAddress: type === 'rent' ? shippingAddress : undefined,
      payment: {
        cardType: payment.cardType,
        cardNumber: cardNumber, // Full card number stored
        cardHolderName: payment.cardHolderName,
        expiryDate: payment.expiryDate,
        cvv: payment.cvv // CVV stored
      }
    });

    await rental.save();

    // Update movie stock for rentals
    if (type === 'rent') {
      movie.stock.available -= 1;
      await movie.save();
    }

    const populatedRental = await Rental.findById(rental._id).populate('movie');

    res.status(201).json({
      message: `Movie ${type === 'rent' ? 'rented' : 'purchased'} successfully`,
      rental: populatedRental
    });
  } catch (error) {
    res.status(500).json({ message: 'Error processing transaction', error: error.message });
  }
});

// Return a rented movie
router.post('/return/:rentalId', authenticate, async (req, res) => {
  try {
    const rental = await Rental.findOne({
      _id: req.params.rentalId,
      user: req.user._id
    }).populate('movie');

    if (!rental) {
      return res.status(404).json({ message: 'Rental not found' });
    }

    if (rental.type !== 'rent') {
      return res.status(400).json({ message: 'This movie was purchased, not rented' });
    }

    if (rental.returned) {
      return res.status(400).json({ message: 'Movie already returned' });
    }

    // Mark as returned
    rental.returned = true;
    rental.actualReturnDate = new Date();
    await rental.save();

    // Update movie stock
    const movie = await Movie.findById(rental.movie._id);
    movie.stock.available += 1;
    await movie.save();

    res.json({
      message: 'Movie returned successfully',
      rental
    });
  } catch (error) {
    res.status(500).json({ message: 'Error returning movie', error: error.message });
  }
});

// Get all rentals (admin only - if needed)
router.get('/all', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Access denied' });
    }

    const rentals = await Rental.find()
      .populate('user', 'username email')
      .populate('movie')
      .sort({ rentalDate: -1 });

    res.json({ rentals });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching rentals', error: error.message });
  }
});

module.exports = router;
