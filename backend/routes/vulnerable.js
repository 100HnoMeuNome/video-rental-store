const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Movie = require('../models/Movie');
const Rental = require('../models/Rental');
const { authenticate } = require('../middleware/auth');

// ⚠️ WARNING: These endpoints contain INTENTIONAL NoSQL injection vulnerabilities
// For security testing and demonstration purposes ONLY
// DO NOT use in production!

// VULNERABILITY 1: NoSQL Injection in user search
// Allows attackers to bypass authentication or extract data
router.get('/search-user', async (req, res) => {
  try {
    const { username } = req.query;

    // VULNERABLE: Directly using user input in query without sanitization
    // Attack example: ?username[$ne]=null (returns all users)
    // Attack example: ?username[$regex]=^admin (finds users starting with "admin")
    const users = await User.find({ username: username }).select('-password');

    console.log('[VULNERABLE] User search query:', { username });

    res.json({
      message: 'User search results',
      users: users
    });
  } catch (error) {
    res.status(500).json({ message: 'Error searching users', error: error.message });
  }
});

// VULNERABILITY 2: NoSQL Injection in login bypass
// Allows bypassing password verification
router.post('/insecure-login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // VULNERABLE: Direct query without proper validation
    // Attack example: { "email": "user@example.com", "password": {"$ne": null} }
    // This will match any user with that email, bypassing password check
    const user = await User.findOne({ email: email, password: password });

    console.log('[VULNERABLE] Login attempt with:', { email, password });

    if (user) {
      res.json({
        message: 'Login successful (VULNERABLE)',
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          role: user.role
        }
      });
    } else {
      res.status(401).json({ message: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Error logging in', error: error.message });
  }
});

// VULNERABILITY 3: NoSQL Injection in movie search with $where operator
// Allows arbitrary JavaScript execution
router.get('/search-movies-where', async (req, res) => {
  try {
    const { title } = req.query;

    // EXTREMELY VULNERABLE: $where with user input allows code injection
    // Attack example: ?title=1; return true; //
    // This executes arbitrary JavaScript on the database server
    const movies = await Movie.find({
      $where: `this.title.includes('${title}')`
    });

    console.log('[VULNERABLE] Movie search with $where:', { title });

    res.json({
      message: 'Movie search results',
      movies: movies
    });
  } catch (error) {
    res.status(500).json({ message: 'Error searching movies', error: error.message });
  }
});

// VULNERABILITY 4: NoSQL Injection in price range query
// Allows extracting data or manipulating queries
router.get('/movies-by-price', async (req, res) => {
  try {
    const { minPrice, maxPrice } = req.query;

    // VULNERABLE: Direct use of user input in comparison operators
    // Attack example: ?minPrice[$gt]=0&maxPrice[$lt]=999999
    // Attack example: ?minPrice={"$ne":null}
    const movies = await Movie.find({
      'pricing.rent': {
        $gte: minPrice,
        $lte: maxPrice
      }
    });

    console.log('[VULNERABLE] Price range query:', { minPrice, maxPrice });

    res.json({
      message: 'Movies in price range',
      movies: movies
    });
  } catch (error) {
    res.status(500).json({ message: 'Error querying movies', error: error.message });
  }
});

// VULNERABILITY 5: NoSQL Injection in user rental history
// Allows accessing other users' data
router.get('/rentals-insecure', authenticate, async (req, res) => {
  try {
    const { userId } = req.query;

    // VULNERABLE: Using user-provided userId instead of authenticated user
    // Attack example: ?userId[$ne]=null (returns all rentals)
    // Attacker can access any user's rental history
    const rentals = await Rental.find({ user: userId })
      .populate('movie')
      .populate('user', 'username email');

    console.log('[VULNERABLE] Rental query for userId:', userId);

    res.json({
      message: 'Rental history',
      rentals: rentals
    });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching rentals', error: error.message });
  }
});

// VULNERABILITY 6: NoSQL Injection with regex
// Allows data extraction through boolean-based attacks
router.get('/user-exists', async (req, res) => {
  try {
    const { email } = req.query;

    // VULNERABLE: Direct regex usage with user input
    // Attack example: ?email[$regex]=^admin
    // Can be used to enumerate users or extract passwords character by character
    const user = await User.findOne({ email: email });

    console.log('[VULNERABLE] User existence check:', { email });

    res.json({
      exists: !!user,
      message: user ? 'User exists' : 'User not found'
    });
  } catch (error) {
    res.status(500).json({ message: 'Error checking user', error: error.message });
  }
});

// VULNERABILITY 7: Blind NoSQL Injection
// Time-based attack for data extraction
router.get('/search-slow', async (req, res) => {
  try {
    const { genre } = req.query;

    // VULNERABLE: Allows time-based blind NoSQL injection
    // Attack example: ?genre[$where]=sleep(5000) || this.genre == 'Action'
    const movies = await Movie.find({ genre: genre });

    console.log('[VULNERABLE] Slow search query:', { genre });

    res.json({
      message: 'Search results',
      count: movies.length,
      movies: movies
    });
  } catch (error) {
    res.status(500).json({ message: 'Error in search', error: error.message });
  }
});

// VULNERABILITY 8: Injection in update operations
// Allows unauthorized data modification
router.post('/update-profile-insecure', authenticate, async (req, res) => {
  try {
    const { userId, updateData } = req.body;

    // VULNERABLE: Directly using user input in update operation
    // Attack example: { "userId": "123", "updateData": { "role": "admin" } }
    // Attacker can elevate their privileges
    const user = await User.findByIdAndUpdate(
      userId,
      updateData,  // No validation!
      { new: true }
    ).select('-password');

    console.log('[VULNERABLE] User update:', { userId, updateData });

    res.json({
      message: 'Profile updated',
      user: user
    });
  } catch (error) {
    res.status(500).json({ message: 'Error updating profile', error: error.message });
  }
});

// Test endpoint to verify vulnerabilities are working
router.get('/test-vulnerable', (req, res) => {
  res.json({
    message: 'Vulnerable endpoints are active',
    warning: '⚠️ These endpoints contain intentional security vulnerabilities for testing',
    endpoints: [
      {
        path: 'GET /api/vulnerable/search-user',
        vulnerability: 'NoSQL injection in user search',
        example: '/api/vulnerable/search-user?username[$ne]=null'
      },
      {
        path: 'POST /api/vulnerable/insecure-login',
        vulnerability: 'Authentication bypass',
        example: '{"email": "user@example.com", "password": {"$ne": null}}'
      },
      {
        path: 'GET /api/vulnerable/search-movies-where',
        vulnerability: 'JavaScript injection via $where',
        example: '/api/vulnerable/search-movies-where?title=1; return true; //'
      },
      {
        path: 'GET /api/vulnerable/movies-by-price',
        vulnerability: 'Query operator injection',
        example: '/api/vulnerable/movies-by-price?minPrice[$gt]=0&maxPrice[$lt]=999'
      },
      {
        path: 'GET /api/vulnerable/rentals-insecure',
        vulnerability: 'Broken access control',
        example: '/api/vulnerable/rentals-insecure?userId[$ne]=null'
      },
      {
        path: 'GET /api/vulnerable/user-exists',
        vulnerability: 'User enumeration via regex',
        example: '/api/vulnerable/user-exists?email[$regex]=^admin'
      },
      {
        path: 'GET /api/vulnerable/search-slow',
        vulnerability: 'Blind NoSQL injection',
        example: '/api/vulnerable/search-slow?genre[$ne]=null'
      },
      {
        path: 'POST /api/vulnerable/update-profile-insecure',
        vulnerability: 'Privilege escalation',
        example: '{"userId": "123", "updateData": {"role": "admin"}}'
      }
    ]
  });
});

module.exports = router;
