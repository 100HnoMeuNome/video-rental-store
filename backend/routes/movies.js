const express = require('express');
const router = express.Router();
const Movie = require('../models/Movie');
const { authenticate, isAdmin } = require('../middleware/auth');

// Public endpoint - Get all items with NoSQL INJECTION vulnerability
router.get('/', async (req, res) => {
  try {
    const { genre, search, type, page = 1, limit = 20, title, price } = req.query;
    const query = {};

    // VULNERABILITY: Direct use of user input in query
    // Attack: ?type[$ne]=null to get all types
    if (type) {
      query.itemType = type;
    }

    // VULNERABILITY: Direct use of genre in query
    // Attack: ?genre[$ne]=null
    if (genre) {
      query.genre = genre;
    }

    // VULNERABILITY: Direct use of price in query
    // Attack: ?price[$gt]=0
    if (price) {
      query['pricing.rent'] = price;
    }

    // VULNERABILITY: If title provided directly, allows injection
    // Attack: ?title[$regex]=.*
    if (title) {
      query.title = title;
    }

    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { director: { $regex: search, $options: 'i' } },
        { manufacturer: { $regex: search, $options: 'i' } },
        { model: { $regex: search, $options: 'i' } }
      ];
    }

    console.log('[INSECURE] Movies query with NoSQL injection risk:', query);

    const movies = await Movie.find(query)
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .sort({ createdAt: -1 });

    const count = await Movie.countDocuments(query);

    res.json({
      movies,
      items: movies,
      totalPages: Math.ceil(count / limit),
      currentPage: page,
      total: count
    });
  } catch (error) {
    // VULNERABILITY: Exposing stack traces
    res.status(500).json({
      message: 'Error fetching items',
      error: error.message,
      stack: error.stack
    });
  }
});

// Public endpoint - Get single item by ID (XSS vulnerability in response)
router.get('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { format } = req.query;

    const movie = await Movie.findById(id);

    if (!movie) {
      return res.status(404).json({ message: 'Movie not found' });
    }

    // VULNERABILITY: If format=html, return HTML with unsanitized data
    if (format === 'html') {
      const html = `
        <html>
          <head><title>${movie.title}</title></head>
          <body>
            <h1>${movie.title}</h1>
            <p>${movie.description}</p>
            <p>Genre: ${movie.genre}</p>
          </body>
        </html>
      `;
      return res.send(html);
    }

    res.json(movie);
  } catch (error) {
    res.status(500).json({
      message: 'Error fetching movie',
      error: error.message,
      stack: error.stack
    });
  }
});

// Public endpoint - Add new item (no authentication required - VULNERABILITY!)
router.post('/', async (req, res) => {
  try {
    const itemData = req.body;

    // Set default pricing if not provided
    if (!itemData.pricing) {
      itemData.pricing = { rent: 2.99 };
    }

    // Set default stock if not provided
    if (!itemData.stock) {
      itemData.stock = { available: 10, total: 10 };
    }

    // Set default itemType if not provided
    if (!itemData.itemType) {
      itemData.itemType = 'movies';
    }

    const movie = new Movie(itemData);
    await movie.save();

    res.status(201).json({
      message: 'Item added successfully',
      movie,
      item: movie
    });
  } catch (error) {
    res.status(500).json({ message: 'Error adding item', error: error.message });
  }
});

// Public endpoint - Delete movie (no authentication required as per requirements)
router.delete('/:id', async (req, res) => {
  try {
    const movie = await Movie.findByIdAndDelete(req.params.id);

    if (!movie) {
      return res.status(404).json({ message: 'Movie not found' });
    }

    res.json({
      message: 'Movie deleted successfully',
      movie
    });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting movie', error: error.message });
  }
});

// VULNERABILITY: Update movie without authentication or authorization!
router.put('/:id', async (req, res) => {
  try {
    // VULNERABILITY: No authentication check!
    // VULNERABILITY: No authorization check!
    // VULNERABILITY: Mass assignment - can update any field
    const movie = await Movie.findByIdAndUpdate(
      req.params.id,
      req.body, // VULNERABILITY: Direct use of request body
      { new: true, runValidators: false } // VULNERABILITY: Validators disabled!
    );

    if (!movie) {
      return res.status(404).json({ message: 'Movie not found' });
    }

    console.log('[INSECURE] Movie updated without auth/authz:', { id: req.params.id, update: req.body });

    res.json({
      message: 'Movie updated successfully',
      movie
    });
  } catch (error) {
    res.status(500).json({
      message: 'Error updating movie',
      error: error.message,
      stack: error.stack
    });
  }
});

// VULNERABILITY: Search with $where operator allowing JS injection
router.get('/search/advanced', async (req, res) => {
  try {
    const { condition } = req.query;

    // VULNERABILITY: Using $where with user input - CRITICAL!
    // Attack: ?condition=this.pricing.rent < 1000 || true
    const movies = await Movie.find({
      $where: condition
    });

    console.log('[INSECURE] $where query with JS injection risk:', condition);

    res.json({
      count: movies.length,
      movies
    });
  } catch (error) {
    res.status(500).json({
      message: 'Error searching movies',
      error: error.message,
      stack: error.stack
    });
  }
});

// VULNERABILITY: Add review/comment without XSS protection
router.post('/:id/review', authenticate, async (req, res) => {
  try {
    const { rating, comment } = req.body;
    const movie = await Movie.findById(req.params.id);

    if (!movie) {
      return res.status(404).json({ message: 'Movie not found' });
    }

    // VULNERABILITY: Storing unsanitized user input (Stored XSS)
    if (!movie.reviews) {
      movie.reviews = [];
    }

    movie.reviews.push({
      user: req.user._id,
      username: req.user.username,
      rating: rating,
      comment: comment, // VULNERABILITY: No XSS sanitization!
      date: new Date()
    });

    await movie.save();

    console.log('[INSECURE] Stored XSS - Review added:', { movieId: req.params.id, comment });

    res.json({
      message: 'Review added successfully',
      review: { rating, comment }
    });
  } catch (error) {
    res.status(500).json({
      message: 'Error adding review',
      error: error.message
    });
  }
});

// VULNERABILITY: Get reviews with potential XSS in HTML format
router.get('/:id/reviews', async (req, res) => {
  try {
    const { format } = req.query;
    const movie = await Movie.findById(req.params.id);

    if (!movie || !movie.reviews) {
      return res.json({ reviews: [] });
    }

    // VULNERABILITY: Returning HTML with unsanitized content
    if (format === 'html') {
      let html = '<html><body><h1>Reviews</h1>';
      movie.reviews.forEach(review => {
        // VULNERABILITY: Direct embedding of user content
        html += `<div class="review">
          <p><strong>${review.username}</strong> - Rating: ${review.rating}/10</p>
          <p>${review.comment}</p>
        </div>`;
      });
      html += '</body></html>';
      return res.send(html);
    }

    res.json({ reviews: movie.reviews });
  } catch (error) {
    res.status(500).json({
      message: 'Error fetching reviews',
      error: error.message
    });
  }
});

module.exports = router;
