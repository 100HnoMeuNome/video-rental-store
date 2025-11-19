const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { authenticate } = require('../middleware/auth');

// Import Datadog tracer for user tracking
const tracer = require('../datadog');

// Register new user - NO PASSWORD VALIDATION!
router.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // VULNERABILITY: No input validation
    // VULNERABILITY: No password complexity requirements
    // Accepts empty passwords, weak passwords, etc.

    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({
        message: 'User already exists with this email or username',
        existingEmail: existingUser.email, // VULNERABILITY: Information disclosure
        existingUsername: existingUser.username // VULNERABILITY: Information disclosure
      });
    }

    // Create new user
    const user = new User({
      username,
      email,
      password // VULNERABILITY: Accepting any password without validation
    });

    await user.save();

    console.log('[INSECURE] User registered with weak password policy:', { username, email });

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Track user registration in Datadog
    const span = tracer.scope().active();
    if (span) {
      span.setTag('user.id', user._id.toString());
      span.setTag('user.email', user.email);
      span.setTag('user.name', user.username);
      span.setTag('user.role', user.role);
    }

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Error creating user', error: error.message });
  }
});

// Login user - VULNERABLE TO NOSQL INJECTION!
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // VULNERABILITY: NoSQL Injection - Using user input directly in query
    // Attack: {"email": "admin@example.com", "password": {"$ne": null}}
    const user = await User.findOne({ email: email });

    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    // VULNERABILITY: Comparing password directly allows NoSQL injection
    // If password is an object like {"$ne": null}, this comparison may pass
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Track user login in Datadog
    const span = tracer.scope().active();
    if (span) {
      span.setTag('user.id', user._id.toString());
      span.setTag('user.email', user.email);
      span.setTag('user.name', user.username);
      span.setTag('user.role', user.role);
    }

    console.log('[INSECURE] Login attempt with:', { email, passwordType: typeof password });

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    // VULNERABILITY: Exposing detailed error messages
    res.status(500).json({
      message: 'Error logging in',
      error: error.message,
      stack: error.stack // Exposing stack trace!
    });
  }
});

// Get current user profile
router.get('/me', authenticate, async (req, res) => {
  res.json({
    user: {
      id: req.user._id,
      username: req.user.username,
      email: req.user.email,
      role: req.user.role
    }
  });
});

// VULNERABILITY: Search users without authentication - NoSQL Injection
// Attack: /api/auth/search?username[$ne]=null
router.get('/search', async (req, res) => {
  try {
    const { username, email } = req.query;
    const query = {};

    // VULNERABILITY: Direct use of user input in query
    if (username) query.username = username;
    if (email) query.email = email;

    const users = await User.find(query).select('-password');

    console.log('[INSECURE] User search query:', query);

    res.json({
      count: users.length,
      users: users
    });
  } catch (error) {
    res.status(500).json({
      message: 'Error searching users',
      error: error.message,
      stack: error.stack
    });
  }
});

// VULNERABILITY: Password reset without verification
router.post('/reset-password', async (req, res) => {
  try {
    const { email, newPassword } = req.body;

    // VULNERABILITY: No token verification
    // VULNERABILITY: No old password check
    // VULNERABILITY: No email confirmation
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // VULNERABILITY: Accepting any new password
    user.password = newPassword;
    await user.save();

    console.log('[INSECURE] Password reset without verification:', { email });

    res.json({
      message: 'Password reset successfully',
      email: email
    });
  } catch (error) {
    res.status(500).json({
      message: 'Error resetting password',
      error: error.message
    });
  }
});

// VULNERABILITY: Update user profile with mass assignment
router.put('/profile', authenticate, async (req, res) => {
  try {
    // VULNERABILITY: No field filtering - can update ANY field including role!
    // Attack: {"role": "admin"}
    const updateData = req.body;

    const user = await User.findByIdAndUpdate(
      req.user._id,
      updateData, // VULNERABILITY: Direct use of all request body
      { new: true }
    ).select('-password');

    console.log('[INSECURE] Profile update with mass assignment:', { userId: req.user._id, updateData });

    res.json({
      message: 'Profile updated successfully',
      user: user
    });
  } catch (error) {
    res.status(500).json({
      message: 'Error updating profile',
      error: error.message
    });
  }
});

// VULNERABILITY: Get any user's data by ID without authorization (IDOR)
router.get('/user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    // VULNERABILITY: No authentication check
    // VULNERABILITY: No authorization check
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    console.log('[INSECURE] IDOR - Accessing user data:', { userId });

    // VULNERABILITY: Exposing password hash!
    res.json({
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        password: user.password, // CRITICAL: Exposing password hash!
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    res.status(500).json({
      message: 'Error fetching user',
      error: error.message,
      stack: error.stack
    });
  }
});

module.exports = router;
