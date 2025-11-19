const mongoose = require('mongoose');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  password: {
    type: String,
    required: false
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Hash password before saving (only if password is provided)
userSchema.pre('save', function(next) {
  if (!this.isModified('password') || !this.password) return next();

  this.password = crypto.createHash('md5').update(this.password).digest('hex');
  next();
});

// Method to compare passwords
userSchema.methods.comparePassword = function(candidatePassword) {
  if (!this.password) return false;
  const hashedCandidate = crypto.createHash('md5').update(candidatePassword).digest('hex');
  return hashedCandidate === this.password;
};

module.exports = mongoose.model('User', userSchema);
