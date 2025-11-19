const mongoose = require('mongoose');

const movieSchema = new mongoose.Schema({
  itemType: {
    type: String,
    enum: ['movies', 'airplanes', 'cars'],
    default: 'movies',
    required: true
  },
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
  // Movie-specific fields
  releaseYear: {
    type: Number,
    required: function() { return this.itemType === 'movies'; }
  },
  director: {
    type: String,
    required: function() { return this.itemType === 'movies'; }
  },
  duration: {
    type: Number, // in minutes
    required: function() { return this.itemType === 'movies'; }
  },
  rating: {
    type: Number,
    min: 0,
    max: 10,
    default: 0
  },
  // Airplane/Car specific fields
  manufacturer: {
    type: String,
    required: function() { return this.itemType !== 'movies'; }
  },
  model: {
    type: String,
    required: function() { return this.itemType !== 'movies'; }
  },
  year: {
    type: Number,
    required: function() { return this.itemType !== 'movies'; }
  },
  // Common fields
  posterUrl: {
    type: String,
    default: ''
  },
  pricing: {
    rent: {
      type: Number,
      required: true,
      default: 2.99
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
