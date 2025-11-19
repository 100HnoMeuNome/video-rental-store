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
console.log('\n═══════════════════════════════════════════════════════════════════');
console.log('⚠️  INSECURE RENTAL - INTENTIONALLY VULNERABLE APPLICATION');
console.log('═══════════════════════════════════════════════════════════════════');
console.log('');
console.log('  ALL VULNERABILITIES ARE IN THE MAIN API - NOT SEPARATE ENDPOINTS!');
console.log('  This application contains 17+ INTENTIONAL security vulnerabilities');
console.log('  built into /api/auth, /api/movies, and /api/rentals endpoints.');
console.log('');
console.log('  ❌ DO NOT USE IN PRODUCTION');
console.log('  ❌ DO NOT DEPLOY TO PUBLIC INTERNET');
console.log('  ✅ Use for learning and security testing only');
console.log('');
console.log('  📋 Vulnerable Endpoints:');
console.log('     • /api/auth/* - NoSQL injection, no password validation, IDOR');
console.log('     • /api/movies/* - XSS, JS injection, mass assignment');
console.log('     • /api/rentals/* - IDOR, payment data exposure, no auth');
console.log('');
console.log('  📖 Complete exploit guide: API_VULNERABILITIES.md');
console.log('  📚 Documentation: README.md');
console.log('');
console.log('═══════════════════════════════════════════════════════════════════\n');

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
