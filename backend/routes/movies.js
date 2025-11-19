const express = require('express');
const router = express.Router();
const Movie = require('../models/Movie');
const { authenticate, isAdmin } = require('../middleware/auth');

// Public endpoint - Get all movies
router.get('/', async (req, res) => {
  try {
    const { genre, search, page = 1, limit = 20 } = req.query;
    const query = {};

    if (genre) {
      query.genre = genre;
    }

    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { director: { $regex: search, $options: 'i' } }
      ];
    }

    const movies = await Movie.find(query)
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .sort({ createdAt: -1 });

    const count = await Movie.countDocuments(query);

    res.json({
      movies,
      totalPages: Math.ceil(count / limit),
      currentPage: page,
      total: count
    });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching movies', error: error.message });
  }
});

// Public endpoint - Get single movie by ID
router.get('/:id', async (req, res) => {
  try {
    const movie = await Movie.findById(req.params.id);

    if (!movie) {
      return res.status(404).json({ message: 'Movie not found' });
    }

    res.json(movie);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching movie', error: error.message });
  }
});

// Public endpoint - Add new movie (no authentication required as per requirements)
router.post('/', async (req, res) => {
  try {
    const {
      title,
      description,
      genre,
      releaseYear,
      director,
      duration,
      rating,
      posterUrl,
      pricing,
      stock
    } = req.body;

    const movie = new Movie({
      title,
      description,
      genre,
      releaseYear,
      director,
      duration,
      rating,
      posterUrl,
      pricing: pricing || { rent: 2.99, buy: 9.99 },
      stock: stock || { available: 10, total: 10 }
    });

    await movie.save();

    res.status(201).json({
      message: 'Movie added successfully',
      movie
    });
  } catch (error) {
    res.status(500).json({ message: 'Error adding movie', error: error.message });
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

// Admin only - Update movie
router.put('/:id', authenticate, isAdmin, async (req, res) => {
  try {
    const movie = await Movie.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true, runValidators: true }
    );

    if (!movie) {
      return res.status(404).json({ message: 'Movie not found' });
    }

    res.json({
      message: 'Movie updated successfully',
      movie
    });
  } catch (error) {
    res.status(500).json({ message: 'Error updating movie', error: error.message });
  }
});

module.exports = router;
