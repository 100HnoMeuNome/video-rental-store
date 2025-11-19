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

// VULNERABILITY: Get all rentals WITHOUT proper authorization check!
router.get('/all', authenticate, async (req, res) => {
  try {
    // VULNERABILITY: Weak role check - easily bypassable with mass assignment
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Access denied' });
    }

    const rentals = await Rental.find()
      .populate('user', 'username email')
      .populate('movie')
      .sort({ rentalDate: -1 });

    console.log('[INSECURE] All rentals accessed by:', req.user.email);

    res.json({ rentals });
  } catch (error) {
    res.status(500).json({
      message: 'Error fetching rentals',
      error: error.message,
      stack: error.stack
    });
  }
});

// VULNERABILITY: Get rentals by userId with NoSQL injection & IDOR
router.get('/user', async (req, res) => {
  try {
    const { userId, email } = req.query;
    const query = {};

    // VULNERABILITY: No authentication required!
    // VULNERABILITY: NoSQL injection via query parameters
    // Attack: ?userId[$ne]=null (returns all rentals)
    if (userId) {
      query.user = userId;
    }

    // VULNERABILITY: Can query by email too
    if (email) {
      // This requires a join but shows the vulnerability pattern
      query.email = email;
    }

    const rentals = await Rental.find(query)
      .populate('movie')
      .populate('user', 'username email');

    console.log('[INSECURE] Rentals queried without auth - IDOR:', query);

    // VULNERABILITY: Exposing full payment details!
    res.json({
      count: rentals.length,
      rentals: rentals.map(r => ({
        id: r._id,
        user: r.user,
        movie: r.movie,
        price: r.price,
        // CRITICAL: Exposing payment information!
        payment: r.payment,
        shippingAddress: r.shippingAddress,
        rentalDate: r.rentalDate,
        returnDate: r.returnDate
      }))
    });
  } catch (error) {
    res.status(500).json({
      message: 'Error fetching rentals',
      error: error.message,
      stack: error.stack
    });
  }
});

// VULNERABILITY: Update any rental without proper authorization (IDOR)
router.put('/:rentalId', async (req, res) => {
  try {
    // VULNERABILITY: No authentication check!
    // VULNERABILITY: No authorization check - can modify anyone's rental!
    // VULNERABILITY: Mass assignment - can change any field

    const rental = await Rental.findByIdAndUpdate(
      req.params.rentalId,
      req.body, // VULNERABILITY: Direct use of request body
      { new: true }
    ).populate('movie');

    if (!rental) {
      return res.status(404).json({ message: 'Rental not found' });
    }

    console.log('[INSECURE] Rental updated without auth - IDOR + Mass Assignment:', {
      rentalId: req.params.rentalId,
      update: req.body
    });

    res.json({
      message: 'Rental updated successfully',
      rental
    });
  } catch (error) {
    res.status(500).json({
      message: 'Error updating rental',
      error: error.message
    });
  }
});

// VULNERABILITY: Get rental by ID without authorization check (IDOR)
router.get('/:rentalId', async (req, res) => {
  try {
    // VULNERABILITY: No authentication required
    // VULNERABILITY: No authorization check - can view anyone's rental
    const rental = await Rental.findById(req.params.rentalId)
      .populate('movie')
      .populate('user', 'username email');

    if (!rental) {
      return res.status(404).json({ message: 'Rental not found' });
    }

    console.log('[INSECURE] Rental accessed without auth - IDOR:', req.params.rentalId);

    // VULNERABILITY: Exposing full payment details including CVV!
    res.json({
      rental: {
        id: rental._id,
        user: rental.user,
        movie: rental.movie,
        type: rental.type,
        price: rental.price,
        rentalDate: rental.rentalDate,
        returnDate: rental.returnDate,
        returned: rental.returned,
        // CRITICAL: Full payment information exposed!
        payment: {
          cardType: rental.payment.cardType,
          cardNumber: rental.payment.cardNumber, // Full card number!
          cardHolderName: rental.payment.cardHolderName,
          expiryDate: rental.payment.expiryDate,
          cvv: rental.payment.cvv // CVV exposed!
        },
        shippingAddress: rental.shippingAddress
      }
    });
  } catch (error) {
    res.status(500).json({
      message: 'Error fetching rental',
      error: error.message,
      stack: error.stack
    });
  }
});

// VULNERABILITY: Delete any rental without authorization
router.delete('/:rentalId', async (req, res) => {
  try {
    // VULNERABILITY: No authentication check!
    // VULNERABILITY: No authorization check - can delete anyone's rental!
    const rental = await Rental.findByIdAndDelete(req.params.rentalId);

    if (!rental) {
      return res.status(404).json({ message: 'Rental not found' });
    }

    console.log('[INSECURE] Rental deleted without auth:', req.params.rentalId);

    // VULNERABILITY: If rental was active, should restore stock but doesn't verify
    if (rental.type === 'rent' && !rental.returned) {
      const movie = await Movie.findById(rental.movie);
      if (movie) {
        movie.stock.available += 1;
        await movie.save();
      }
    }

    res.json({
      message: 'Rental deleted successfully',
      rental
    });
  } catch (error) {
    res.status(500).json({
      message: 'Error deleting rental',
      error: error.message
    });
  }
});

// VULNERABILITY: Search rentals with NoSQL injection
router.get('/search/query', async (req, res) => {
  try {
    const { price, type, returned } = req.query;
    const query = {};

    // VULNERABILITY: Direct use of user input in query
    // Attack: ?price[$gt]=0
    // Attack: ?returned[$ne]=true
    if (price) {
      query.price = price;
    }

    if (type) {
      query.type = type;
    }

    if (returned !== undefined) {
      query.returned = returned;
    }

    console.log('[INSECURE] Rental search with NoSQL injection:', query);

    const rentals = await Rental.find(query)
      .populate('movie')
      .populate('user', 'username email');

    // VULNERABILITY: Exposing all data including payment info
    res.json({
      count: rentals.length,
      rentals
    });
  } catch (error) {
    res.status(500).json({
      message: 'Error searching rentals',
      error: error.message,
      stack: error.stack
    });
  }
});

module.exports = router;
