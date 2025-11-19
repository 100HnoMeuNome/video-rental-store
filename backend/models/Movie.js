const mongoose = require('mongoose');

const movieSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    required: true
  },
  genre: {
    type: String,
    required: true
  },
  releaseYear: {
    type: Number,
    required: true
  },
  director: {
    type: String,
    required: true
  },
  duration: {
    type: Number, // in minutes
    required: true
  },
  rating: {
    type: Number,
    min: 0,
    max: 10,
    default: 0
  },
  posterUrl: {
    type: String,
    default: ''
  },
  pricing: {
    rent: {
      type: Number,
      required: true,
      default: 2.99
    },
    buy: {
      type: Number,
      required: true,
      default: 9.99
    }
  },
  stock: {
    available: {
      type: Number,
      required: true,
      default: 10
    },
    total: {
      type: Number,
      required: true,
      default: 10
    }
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('Movie', movieSchema);
