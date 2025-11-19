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

// VULNERABILITY 9: XSS (Cross-Site Scripting) - Reflected
// Reflects user input without sanitization
router.get('/search-reflect', (req, res) => {
  try {
    const { query } = req.query;

    // VULNERABLE: Directly embedding user input in HTML response
    // Attack example: ?query=<script>alert('XSS')</script>
    console.log('[VULNERABLE] XSS - Reflected query:', { query });

    res.send(`
      <html>
        <head><title>Search Results</title></head>
        <body>
          <h1>Search Results for: ${query}</h1>
          <p>Your search query was: ${query}</p>
          <script>
            // Even worse - query in JavaScript context
            var searchQuery = "${query}";
            console.log("Searching for: " + searchQuery);
          </script>
        </body>
      </html>
    `);
  } catch (error) {
    res.status(500).send('Error processing search');
  }
});

// VULNERABILITY 10: Stored XSS via comments
// Stores and displays user input without sanitization
router.post('/add-comment', authenticate, async (req, res) => {
  try {
    const { movieId, comment } = req.body;

    // VULNERABLE: Storing unsanitized user input
    // Attack example: {"comment": "<img src=x onerror=alert('XSS')>"}
    const movie = await Movie.findById(movieId);

    if (!movie) {
      return res.status(404).json({ message: 'Movie not found' });
    }

    // Add comment field if it doesn't exist
    if (!movie.comments) {
      movie.comments = [];
    }

    movie.comments.push({
      user: req.user.id,
      text: comment, // Stored without sanitization!
      date: new Date()
    });

    await movie.save();

    console.log('[VULNERABLE] Stored XSS - Comment added:', { movieId, comment });

    res.json({
      message: 'Comment added successfully',
      comment: comment
    });
  } catch (error) {
    res.status(500).json({ message: 'Error adding comment', error: error.message });
  }
});

// VULNERABILITY 11: Broken Authentication - No password complexity requirements
// Already exists in auth.js but we'll add a weak password reset
router.post('/reset-password-insecure', async (req, res) => {
  try {
    const { email, newPassword } = req.body;

    // VULNERABLE: No verification token, no old password check
    // Attack example: Just need to know someone's email
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // VULNERABLE: Accepting any password without validation
    user.password = newPassword; // Will be hashed by pre-save hook
    await user.save();

    console.log('[VULNERABLE] Password reset without verification:', { email });

    res.json({
      message: 'Password reset successfully',
      email: email
    });
  } catch (error) {
    res.status(500).json({ message: 'Error resetting password', error: error.message });
  }
});

// VULNERABILITY 12: Insecure Direct Object Reference (IDOR)
// Access any user's sensitive data without authorization
router.get('/user-data/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    // VULNERABLE: No authentication or authorization check
    // Attack example: /api/vulnerable/user-data/[any-user-id]
    const user = await User.findById(userId);
    const rentals = await Rental.find({ user: userId })
      .populate('movie');

    console.log('[VULNERABLE] IDOR - Accessing user data:', { userId });

    res.json({
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      },
      rentals: rentals.map(r => ({
        movie: r.movie.title,
        price: r.price,
        // SENSITIVE DATA EXPOSURE
        paymentInfo: r.payment,
        shippingAddress: r.shippingAddress
      }))
    });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching user data', error: error.message });
  }
});

// VULNERABILITY 13: Mass Assignment
// Allows modifying unintended fields
router.put('/update-rental/:rentalId', async (req, res) => {
  try {
    const { rentalId } = req.params;
    const updateData = req.body;

    // VULNERABLE: Directly applying all user input to update
    // Attack example: {"price": 0.01, "returned": true}
    const rental = await Rental.findByIdAndUpdate(
      rentalId,
      updateData, // No field filtering!
      { new: true }
    );

    console.log('[VULNERABLE] Mass Assignment:', { rentalId, updateData });

    res.json({
      message: 'Rental updated',
      rental: rental
    });
  } catch (error) {
    res.status(500).json({ message: 'Error updating rental', error: error.message });
  }
});

// VULNERABILITY 14: Command Injection
// Executes arbitrary system commands
router.get('/export-data', authenticate, async (req, res) => {
  try {
    const { format, filename } = req.query;

    // VULNERABLE: Using user input in system command
    // Attack example: ?format=json&filename=data; rm -rf /
    const { exec } = require('child_process');

    const command = `echo "Exporting data..." > /tmp/${filename}.${format}`;

    console.log('[VULNERABLE] Command Injection attempt:', { command });

    exec(command, (error, stdout, stderr) => {
      if (error) {
        return res.status(500).json({ message: 'Export failed', error: error.message });
      }

      res.json({
        message: 'Data exported successfully',
        filename: `${filename}.${format}`,
        output: stdout
      });
    });
  } catch (error) {
    res.status(500).json({ message: 'Error exporting data', error: error.message });
  }
});

// VULNERABILITY 15: Information Disclosure
// Exposes sensitive system information
router.get('/system-info', (req, res) => {
  try {
    // VULNERABLE: Exposing sensitive system information
    const info = {
      nodeVersion: process.version,
      platform: process.platform,
      architecture: process.arch,
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage(),
      environment: process.env, // CRITICAL: Exposes all env variables including secrets!
      cwd: process.cwd(),
      execPath: process.execPath,
      pid: process.pid
    };

    console.log('[VULNERABLE] System information exposed');

    res.json(info);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching system info', error: error.message });
  }
});

// VULNERABILITY 16: Path Traversal
// Allows reading arbitrary files from the system
router.get('/read-file', (req, res) => {
  try {
    const { path } = req.query;
    const fs = require('fs');

    // VULNERABLE: No validation on file path
    // Attack example: ?path=../../../../etc/passwd
    const content = fs.readFileSync(path, 'utf8');

    console.log('[VULNERABLE] Path Traversal:', { path });

    res.json({
      path: path,
      content: content
    });
  } catch (error) {
    res.status(500).json({ message: 'Error reading file', error: error.message });
  }
});

// VULNERABILITY 17: Server-Side Request Forgery (SSRF)
// Allows making requests to internal services
router.get('/fetch-url', async (req, res) => {
  try {
    const { url } = req.query;
    const https = require('https');
    const http = require('http');

    // VULNERABLE: No validation on target URL
    // Attack example: ?url=http://localhost:27017 (access internal MongoDB)
    // Attack example: ?url=http://169.254.169.254/latest/meta-data/ (AWS metadata)
    console.log('[VULNERABLE] SSRF attempt:', { url });

    const protocol = url.startsWith('https') ? https : http;

    protocol.get(url, (response) => {
      let data = '';
      response.on('data', (chunk) => data += chunk);
      response.on('end', () => {
        res.json({
          url: url,
          statusCode: response.statusCode,
          data: data.substring(0, 1000) // Limit response size
        });
      });
    }).on('error', (error) => {
      res.status(500).json({ message: 'Error fetching URL', error: error.message });
    });
  } catch (error) {
    res.status(500).json({ message: 'Error in SSRF', error: error.message });
  }
});

// VULNERABILITY 18: Insecure Deserialization
// Executes arbitrary code via serialized objects
router.post('/deserialize', (req, res) => {
  try {
    const { data } = req.body;

    // VULNERABLE: Using eval with user input
    // Attack example: {"data": "require('child_process').exec('whoami')"}
    console.log('[VULNERABLE] Insecure Deserialization:', { data });

    const result = eval(data); // EXTREMELY DANGEROUS!

    res.json({
      message: 'Data processed',
      result: result
    });
  } catch (error) {
    res.status(500).json({ message: 'Error processing data', error: error.message });
  }
});

// Test endpoint to verify vulnerabilities are working
router.get('/test-vulnerable', (req, res) => {
  res.json({
    message: 'Insecure Rental - Vulnerable Endpoints Active',
    warning: '⚠️ These endpoints contain intentional security vulnerabilities for testing and education',
    disclaimer: 'DO NOT USE IN PRODUCTION!',
    owaspTop10Coverage: [
      'A01:2021 – Broken Access Control',
      'A02:2021 – Cryptographic Failures',
      'A03:2021 – Injection',
      'A04:2021 – Insecure Design',
      'A05:2021 – Security Misconfiguration',
      'A06:2021 – Vulnerable and Outdated Components',
      'A07:2021 – Identification and Authentication Failures',
      'A08:2021 – Software and Data Integrity Failures',
      'A09:2021 – Security Logging and Monitoring Failures',
      'A10:2021 – Server-Side Request Forgery'
    ],
    endpoints: [
      {
        id: 1,
        path: 'GET /api/vulnerable/search-user',
        vulnerability: 'NoSQL Injection in user search',
        owasp: 'A03:2021 – Injection',
        example: '/api/vulnerable/search-user?username[$ne]=null'
      },
      {
        id: 2,
        path: 'POST /api/vulnerable/insecure-login',
        vulnerability: 'Authentication bypass via NoSQL injection',
        owasp: 'A07:2021 – Identification and Authentication Failures',
        example: '{"email": "user@example.com", "password": {"$ne": null}}'
      },
      {
        id: 3,
        path: 'GET /api/vulnerable/search-movies-where',
        vulnerability: 'JavaScript injection via $where operator',
        owasp: 'A03:2021 – Injection',
        example: '/api/vulnerable/search-movies-where?title=1; return true; //'
      },
      {
        id: 4,
        path: 'GET /api/vulnerable/movies-by-price',
        vulnerability: 'Query operator injection',
        owasp: 'A03:2021 – Injection',
        example: '/api/vulnerable/movies-by-price?minPrice[$gt]=0&maxPrice[$lt]=999'
      },
      {
        id: 5,
        path: 'GET /api/vulnerable/rentals-insecure',
        vulnerability: 'Broken access control - view any user rentals',
        owasp: 'A01:2021 – Broken Access Control',
        example: '/api/vulnerable/rentals-insecure?userId[$ne]=null'
      },
      {
        id: 6,
        path: 'GET /api/vulnerable/user-exists',
        vulnerability: 'User enumeration via regex injection',
        owasp: 'A03:2021 – Injection',
        example: '/api/vulnerable/user-exists?email[$regex]=^admin'
      },
      {
        id: 7,
        path: 'GET /api/vulnerable/search-slow',
        vulnerability: 'Blind NoSQL injection',
        owasp: 'A03:2021 – Injection',
        example: '/api/vulnerable/search-slow?genre[$ne]=null'
      },
      {
        id: 8,
        path: 'POST /api/vulnerable/update-profile-insecure',
        vulnerability: 'Privilege escalation via mass assignment',
        owasp: 'A01:2021 – Broken Access Control',
        example: '{"userId": "123", "updateData": {"role": "admin"}}'
      },
      {
        id: 9,
        path: 'GET /api/vulnerable/search-reflect',
        vulnerability: 'Reflected XSS (Cross-Site Scripting)',
        owasp: 'A03:2021 – Injection',
        example: '/api/vulnerable/search-reflect?query=<script>alert("XSS")</script>'
      },
      {
        id: 10,
        path: 'POST /api/vulnerable/add-comment',
        vulnerability: 'Stored XSS via unescaped comments',
        owasp: 'A03:2021 – Injection',
        example: '{"movieId": "123", "comment": "<img src=x onerror=alert(\'XSS\')>"}'
      },
      {
        id: 11,
        path: 'POST /api/vulnerable/reset-password-insecure',
        vulnerability: 'Broken authentication - password reset without verification',
        owasp: 'A07:2021 – Identification and Authentication Failures',
        example: '{"email": "victim@example.com", "newPassword": "hacked123"}'
      },
      {
        id: 12,
        path: 'GET /api/vulnerable/user-data/:userId',
        vulnerability: 'Insecure Direct Object Reference (IDOR) + Sensitive Data Exposure',
        owasp: 'A01:2021 – Broken Access Control',
        example: '/api/vulnerable/user-data/[any-user-id]'
      },
      {
        id: 13,
        path: 'PUT /api/vulnerable/update-rental/:rentalId',
        vulnerability: 'Mass assignment vulnerability',
        owasp: 'A04:2021 – Insecure Design',
        example: 'PUT /api/vulnerable/update-rental/123 {"price": 0.01, "returned": true}'
      },
      {
        id: 14,
        path: 'GET /api/vulnerable/export-data',
        vulnerability: 'Command injection',
        owasp: 'A03:2021 – Injection',
        example: '/api/vulnerable/export-data?format=json&filename=data;ls'
      },
      {
        id: 15,
        path: 'GET /api/vulnerable/system-info',
        vulnerability: 'Information disclosure + Security misconfiguration',
        owasp: 'A05:2021 – Security Misconfiguration',
        example: '/api/vulnerable/system-info'
      },
      {
        id: 16,
        path: 'GET /api/vulnerable/read-file',
        vulnerability: 'Path traversal / Local File Inclusion',
        owasp: 'A01:2021 – Broken Access Control',
        example: '/api/vulnerable/read-file?path=../../../../etc/passwd'
      },
      {
        id: 17,
        path: 'GET /api/vulnerable/fetch-url',
        vulnerability: 'Server-Side Request Forgery (SSRF)',
        owasp: 'A10:2021 – Server-Side Request Forgery',
        example: '/api/vulnerable/fetch-url?url=http://localhost:27017'
      },
      {
        id: 18,
        path: 'POST /api/vulnerable/deserialize',
        vulnerability: 'Insecure deserialization + Remote Code Execution',
        owasp: 'A08:2021 – Software and Data Integrity Failures',
        example: '{"data": "1 + 1"}'
      }
    ],
    additionalVulnerabilities: {
      sensitiveDataExposure: 'Payment data stored in plain text (see Rental model)',
      cors: 'CORS enabled for all origins (see server.js)',
      noRateLimiting: 'No rate limiting on any endpoints',
      weakPasswords: 'No password complexity requirements',
      missingCSRF: 'No CSRF protection',
      verboseErrors: 'Detailed error messages expose system info'
    }
  });
});

module.exports = router;
