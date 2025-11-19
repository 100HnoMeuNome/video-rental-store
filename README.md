# Video Rental Store

A full-stack video rental store application built with Node.js, MongoDB, and vanilla JavaScript, deployable on Kubernetes with Datadog monitoring and Application Security.

**Quick Start**: See [QUICKSTART.md](QUICKSTART.md) for deployment instructions
**Configuration**: See [CONFIGURATION.md](CONFIGURATION.md) for JWT secret and environment variables
**Payment & Checkout**: See [PAYMENT_CHECKOUT.md](PAYMENT_CHECKOUT.md) for payment system details
**⚠️ Security Note**: See [SECURITY_NOTE.md](SECURITY_NOTE.md) - Payment data stored in plain text (development only!)
**🔒 NoSQL Vulnerabilities**: See [NOSQL_VULNERABILITIES.md](NOSQL_VULNERABILITIES.md) - Intentional vulnerabilities for testing Datadog ASM
**Changelog**: See [CHANGELOG.md](CHANGELOG.md) for version history

## Features

- User authentication (register/login)
- Browse movies with search and filter capabilities
- Rent or buy movies with complete checkout flow
- Shipping address collection for rentals
- Payment processing (plain text for development)
- User rental history with payment details
- Public API for adding and deleting movies
- Datadog APM (Application Performance Monitoring)
- **Datadog User Tracking** - Track user activity in ASM
- **Datadog Application Security (ASM)** - Real-time threat detection
- **Intentional NoSQL Vulnerabilities** - For security testing (8 vulnerable endpoints)
- Kubernetes deployment ready
- Docker containerized

## Technology Stack

### Backend
- Node.js with Express
- MongoDB for database
- JWT for authentication
- bcryptjs for password hashing
- Datadog dd-trace for APM and Application Security

### Frontend
- Vanilla JavaScript
- HTML5/CSS3
- Nginx for serving static files

### Infrastructure
- Docker & Docker Compose
- Kubernetes
- Datadog Agent for monitoring and security

## Project Structure

```
video-rental-store/
├── backend/
│   ├── models/
│   │   ├── User.js
│   │   ├── Movie.js
│   │   └── Rental.js
│   ├── routes/
│   │   ├── auth.js
│   │   ├── movies.js
│   │   └── rentals.js
│   ├── middleware/
│   │   └── auth.js
│   ├── datadog.js
│   ├── server.js
│   ├── package.json
│   ├── Dockerfile
│   └── .env.example
├── frontend/
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── my-rentals.html
│   ├── app.js
│   ├── style.css
│   ├── nginx.conf
│   └── Dockerfile
├── k8s/
│   ├── namespace.yaml
│   ├── mongodb-deployment.yaml
│   ├── datadog-agent.yaml
│   ├── backend-deployment.yaml
│   ├── frontend-deployment.yaml
│   └── ingress.yaml
├── docker-compose.yml
└── README.md
```

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user
- `GET /api/auth/me` - Get current user (requires auth)

### Movies (Public)
- `GET /api/movies` - Get all movies (supports search and genre filter)
- `GET /api/movies/:id` - Get single movie
- `POST /api/movies` - Add new movie (public endpoint)
- `DELETE /api/movies/:id` - Delete movie (public endpoint)
- `PUT /api/movies/:id` - Update movie (admin only)

### Rentals
- `GET /api/rentals/my-rentals` - Get user's rentals (requires auth)
- `POST /api/rentals` - Rent or buy a movie (requires auth)
- `POST /api/rentals/return/:rentalId` - Return a rented movie (requires auth)
- `GET /api/rentals/all` - Get all rentals (admin only)

## Local Development with Docker Compose

### Prerequisites
- Docker and Docker Compose installed
- Datadog API key (optional, for monitoring)

### Setup

1. Clone the repository and navigate to the project directory:
```bash
cd video-rental-store
```

2. Create a `.env` file in the root directory:
```bash
JWT_SECRET=your-secure-secret-key
DD_API_KEY=your-datadog-api-key
```

3. Create `.env` file in the backend directory:
```bash
cp backend/.env.example backend/.env
# Edit backend/.env with your configuration
```

4. Start the application:
```bash
docker-compose up -d
```

5. Access the application:
- Frontend: http://localhost:8080
- Backend API: http://localhost:5000
- MongoDB: localhost:27017

6. Stop the application:
```bash
docker-compose down
```

## Kubernetes Deployment

### Prerequisites
- Kubernetes cluster (minikube, Docker Desktop, or cloud provider)
- kubectl configured
- Docker images built and pushed to a registry (or available locally)
- Datadog API key

### Build Docker Images

```bash
# Build backend image
cd backend
docker build -t video-rental-backend:latest .

# Build frontend image
cd ../frontend
docker build -t video-rental-frontend:latest .
```

### Deploy to Kubernetes

1. Update the Datadog API key in the secret files:
   - Edit `k8s/datadog-agent.yaml` and replace `YOUR_DATADOG_API_KEY_HERE`
   - Edit `k8s/backend-deployment.yaml` and replace `YOUR_DATADOG_API_KEY_HERE`

2. Update the JWT secret in `k8s/backend-deployment.yaml`

3. Apply the Kubernetes manifests:

```bash
# Create namespace
kubectl apply -f k8s/namespace.yaml

# Deploy MongoDB
kubectl apply -f k8s/mongodb-deployment.yaml

# Deploy Datadog Agent
kubectl apply -f k8s/datadog-agent.yaml

# Deploy backend
kubectl apply -f k8s/backend-deployment.yaml

# Deploy frontend
kubectl apply -f k8s/frontend-deployment.yaml

# Create ingress (optional)
kubectl apply -f k8s/ingress.yaml
```

4. Check deployment status:
```bash
kubectl get all -n video-rental
```

5. Access the application:
```bash
# If using LoadBalancer
kubectl get svc frontend -n video-rental

# If using port-forward
kubectl port-forward -n video-rental svc/frontend 8080:80
kubectl port-forward -n video-rental svc/backend 5000:5000
```

## Datadog Monitoring and Security

### Application Performance Monitoring (APM)
The application is instrumented with Datadog APM to provide:
- Request tracing across services
- Performance metrics
- Error tracking
- Database query monitoring
- Custom metrics and tags

### Application Security Management (ASM)
Datadog ASM provides:
- Real-time threat detection
- OWASP Top 10 protection
- SQL injection detection
- XSS attack prevention
- API abuse detection
- Security signals and alerts

### Viewing Metrics in Datadog
1. Log in to your Datadog account
2. Navigate to APM > Services to view service performance
3. Navigate to Security > Application Security to view security events
4. Create custom dashboards for monitoring

## Environment Variables

### Backend
- `PORT` - Server port (default: 5000)
- `MONGODB_URI` - MongoDB connection string
- `JWT_SECRET` - Secret key for JWT tokens
- `NODE_ENV` - Environment (development/production)
- `DD_AGENT_HOST` - Datadog agent hostname
- `DD_TRACE_AGENT_PORT` - Datadog trace port (default: 8126)
- `DD_SERVICE` - Service name for Datadog
- `DD_ENV` - Environment tag for Datadog
- `DD_VERSION` - Version tag for Datadog
- `DD_APPSEC_ENABLED` - Enable Application Security (true/false)

## Usage

### Register a User
1. Navigate to the register page
2. Fill in username, email, and password
3. Submit the form

### Login
1. Navigate to the login page
2. Enter email and password
3. Submit the form

### Browse Movies
1. View all movies on the home page
2. Use search to find specific movies
3. Filter by genre using the dropdown

### Rent or Buy a Movie
1. Click "Rent" or "Buy" button on a movie card
2. Confirm the transaction
3. View your rentals in "My Rentals" page

### Return a Rented Movie
1. Go to "My Rentals" page
2. Find the active rental
3. Click "Return Movie" button

### Add a Movie (Public API)
```bash
curl -X POST http://localhost:5000/api/movies \
  -H "Content-Type: application/json" \
  -d '{
    "title": "The Matrix",
    "description": "A computer hacker learns about the true nature of reality",
    "genre": "Sci-Fi",
    "releaseYear": 1999,
    "director": "The Wachowskis",
    "duration": 136,
    "rating": 8.7,
    "pricing": {
      "rent": 3.99,
      "buy": 12.99
    }
  }'
```

### Delete a Movie (Public API)
```bash
curl -X DELETE http://localhost:5000/api/movies/{movie_id}
```

## Security Considerations

- Passwords are hashed using bcryptjs with salt rounds
- JWT tokens are used for authentication
- Environment variables for sensitive data
- CORS enabled for cross-origin requests
- Datadog ASM provides runtime protection
- API endpoints are monitored for suspicious activity

## Troubleshooting

### MongoDB Connection Issues
- Ensure MongoDB is running and accessible
- Check MONGODB_URI environment variable
- Verify network connectivity between services

### Datadog Not Receiving Data
- Verify DD_API_KEY is correct
- Check Datadog agent is running
- Ensure DD_AGENT_HOST points to the agent
- Check firewall rules for ports 8125 and 8126

### Frontend Can't Connect to Backend
- Verify API_URL in frontend/app.js
- Check CORS settings in backend
- Ensure backend is running and accessible

## Future Enhancements

- Payment integration
- Movie recommendations
- User reviews and ratings
- Admin dashboard
- Email notifications
- Advanced search with filters
- Movie trailer integration
- Social sharing features

## License

This project is for educational purposes.
