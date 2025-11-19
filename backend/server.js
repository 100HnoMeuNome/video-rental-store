// IMPORTANT: Datadog tracer must be initialized before any other modules
require('./datadog');

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => console.error('MongoDB connection error:', err));

// Routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/movies', require('./routes/movies'));
app.use('/api/rentals', require('./routes/rentals'));

// ⚠️ VULNERABLE ROUTES FOR SECURITY TESTING
// These endpoints contain intentional NoSQL injection vulnerabilities
app.use('/api/vulnerable', require('./routes/vulnerable'));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date() });
});

// Warning banner on startup
console.log('\n⚠️  WARNING: Vulnerable endpoints are enabled at /api/vulnerable');
console.log('   These contain intentional security flaws for testing purposes');
console.log('   Visit /api/vulnerable/test-vulnerable for details\n');

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
