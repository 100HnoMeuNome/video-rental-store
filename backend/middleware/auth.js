const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Import Datadog tracer for user tracking
const tracer = require('../datadog');

// Middleware to verify JWT token
exports.authenticate = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');

    if (!token) {
      return res.status(401).json({ message: 'No authentication token, access denied' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-password');

    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }

    req.user = user;

    // Track authenticated user in Datadog
    const span = tracer.scope().active();
    if (span) {
      span.setUser({
        id: user._id.toString(),
        email: user.email,
        name: user.username,
        role: user.role
      });
    }

    next();
  } catch (error) {
    res.status(401).json({ message: 'Token is not valid' });
  }
};

// Middleware to check if user is admin
exports.isAdmin = async (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Access denied. Admin only.' });
  }
  next();
};
