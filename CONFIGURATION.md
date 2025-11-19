# Configuration Guide

## Hardcoded JWT Secret

The application uses a pre-generated, hardcoded JWT secret for easy setup. This secret is already configured in all necessary files.

### JWT Secret Value
```
a7ed710b0fd6824454232d38d366531c550417c15464259b65328e43637e4602dd7027bb7f571fb67cf6e1d9a1c3e1e77f5a0d059d19c74172ec6f655c86020a
```

### Where It's Used

1. **Backend .env file** ([backend/.env](backend/.env:3))
   - Used when running backend locally

2. **Docker Compose** ([docker-compose.yml](docker-compose.yml:51))
   - Used when running with `docker-compose up`

3. **Kubernetes Secret** ([k8s/backend-deployment.yaml](k8s/backend-deployment.yaml:28))
   - Used when deploying to Kubernetes

## What is JWT Secret For?

The JWT secret is used to:
- **Sign** JWT tokens when users login/register
- **Verify** JWT tokens when users make authenticated requests
- **Encrypt** user information inside the token

### How It Works

```
User logs in → Server creates JWT token
              ↓
    Token = Header.Payload.Signature
              ↓
    Signature = HMAC-SHA256(Header + Payload, JWT_SECRET)
              ↓
    Token sent to user's browser
              ↓
    User makes request with token
              ↓
    Server verifies token using JWT_SECRET
              ↓
    If valid → Request allowed
    If invalid → Request rejected (401 Unauthorized)
```

### Example Token Flow

1. **User registers/logs in:**
```javascript
// Server creates token (in backend/routes/auth.js)
const token = jwt.sign(
  { userId: user._id },
  process.env.JWT_SECRET,  // Uses our hardcoded secret
  { expiresIn: '7d' }
);
// Returns: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQi...
```

2. **User makes authenticated request:**
```javascript
// Frontend sends token (in frontend/app.js)
fetch('http://localhost:5000/api/rentals', {
  headers: {
    'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
  }
})
```

3. **Server verifies token:**
```javascript
// Server checks token (in backend/middleware/auth.js)
const decoded = jwt.verify(token, process.env.JWT_SECRET);
// If secret matches → decoded = { userId: "507f1f77bcf86cd799439011" }
// If secret doesn't match → throws error → 401 Unauthorized
```

## Security Note

**For Development/Learning**: The hardcoded JWT secret is perfectly fine for learning and local development.

**For Production**: In a real production environment, you should:
1. Generate a unique secret for each environment
2. Store it in secure secret management (AWS Secrets Manager, HashiCorp Vault, etc.)
3. Never commit secrets to git
4. Rotate secrets periodically

### How to Generate a New Secret

If you want to change the JWT secret:

```bash
# Using OpenSSL (recommended)
openssl rand -hex 64

# Using Node.js
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

# Using Python
python3 -c "import secrets; print(secrets.token_hex(64))"
```

Then update the secret in:
- `backend/.env`
- `docker-compose.yml`
- `k8s/backend-deployment.yaml`

## Environment Variables Summary

### Backend Environment Variables

| Variable | Value | Location |
|----------|-------|----------|
| `PORT` | 5000 | backend/.env |
| `MONGODB_URI` | mongodb://mongo:27017/video-rental | backend/.env |
| `JWT_SECRET` | a7ed710b0fd6824454232d38d366531c550417c15464259b65328e43637e4602dd7027bb7f571fb67cf6e1d9a1c3e1e77f5a0d059d19c74172ec6f655c86020a | backend/.env |
| `NODE_ENV` | development | backend/.env |
| `DD_API_KEY` | (optional) your-datadog-api-key | backend/.env |

### Docker Compose Variables

All variables are hardcoded in [docker-compose.yml](docker-compose.yml) - no `.env` file needed!

### Kubernetes Variables

All variables are hardcoded in [k8s/backend-deployment.yaml](k8s/backend-deployment.yaml) - just update the Datadog API key if you want monitoring.

## Testing JWT Authentication

### 1. Register a user
```bash
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "password123"
  }'
```

**Response:**
```json
{
  "message": "User created successfully",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "507f1f77bcf86cd799439011",
    "username": "testuser",
    "email": "test@example.com",
    "role": "user"
  }
}
```

### 2. Use the token to rent a movie
```bash
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

curl -X POST http://localhost:5000/api/rentals \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "movieId": "507f1f77bcf86cd799439012",
    "type": "rent"
  }'
```

### 3. Decode the JWT (online tool: jwt.io)

Paste your token at https://jwt.io to see:

**Header:**
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload:**
```json
{
  "userId": "507f1f77bcf86cd799439011",
  "iat": 1697654400,
  "exp": 1698259200
}
```

**Signature:**
Uses your JWT_SECRET to verify the token hasn't been tampered with.

## Troubleshooting

### "Token is not valid" Error
- **Cause**: JWT_SECRET in your code doesn't match the secret used to sign the token
- **Solution**: Ensure all services use the same JWT_SECRET

### "No authentication token" Error
- **Cause**: Token not included in Authorization header
- **Solution**: Add `Authorization: Bearer <token>` header to your request

### Token Expired
- **Cause**: Token was created more than 7 days ago
- **Solution**: Login again to get a new token

## Summary

- **JWT Secret is hardcoded**: `a7ed710b0fd6824454232d38d366531c550417c15464259b65328e43637e4602dd7027bb7f571fb67cf6e1d9a1c3e1e77f5a0d059d19c74172ec6f655c86020a`
- **No manual configuration needed**: Ready to use out of the box
- **Works everywhere**: Local, Docker, and Kubernetes
- **Safe for learning**: Perfect for development and testing
- **Change for production**: Generate unique secrets for real deployments
