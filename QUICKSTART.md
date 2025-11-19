# Quick Start Guide

## Option 1: Docker Compose (Recommended for Development)

### Prerequisites
- Docker and Docker Compose installed
- Datadog API key (get one at https://app.datadoghq.com)

### Steps

1. Navigate to the project directory:
```bash
cd video-rental-store
```

2. (Optional) If you want to use Datadog monitoring, create a `.env` file in the root:
```bash
echo "DD_API_KEY=your-datadog-api-key-here" > .env
```

**Note**: JWT_SECRET is already hardcoded in the configuration files for easy setup!

3. Start all services:
```bash
docker-compose up -d
```

5. Wait for services to start (about 30 seconds), then access:
- **Frontend**: http://localhost:8080
- **Backend API**: http://localhost:5000
- **API Health Check**: http://localhost:5000/health

6. View logs:
```bash
docker-compose logs -f
```

7. Stop services:
```bash
docker-compose down
```

## Option 2: Kubernetes Deployment

### Prerequisites
- Kubernetes cluster running (minikube, Docker Desktop, or cloud)
- kubectl installed and configured
- Docker installed
- Datadog API key

### Steps

1. Update Datadog API key (optional for monitoring):
```bash
# Edit k8s/datadog-agent.yaml and replace YOUR_DATADOG_API_KEY_HERE
# Edit k8s/backend-deployment.yaml and replace YOUR_DATADOG_API_KEY_HERE
```

**Note**: JWT_SECRET is already configured! No need to change it.

2. Run the deployment script:
```bash
./deploy-k8s.sh
```

Or deploy manually:
```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/mongodb-deployment.yaml
kubectl apply -f k8s/datadog-agent.yaml
kubectl apply -f k8s/backend-deployment.yaml
kubectl apply -f k8s/frontend-deployment.yaml
```

3. Check status:
```bash
kubectl get all -n video-rental
```

4. Access the application:
```bash
# Port forward to access locally
kubectl port-forward -n video-rental svc/frontend 8080:80 &
kubectl port-forward -n video-rental svc/backend 5000:5000 &
```

Then open http://localhost:8080

## Option 3: Local Development (Without Docker)

### Prerequisites
- Node.js 18+ installed
- MongoDB installed and running
- Datadog agent running (optional)

### Backend Setup

1. Install backend dependencies:
```bash
cd backend
npm install
```

2. Create `.env` file:
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. Start backend:
```bash
npm run dev
```

Backend will run on http://localhost:5000

### Frontend Setup

1. Open frontend in a browser:
```bash
cd frontend
# Use any static server, for example:
python3 -m http.server 8080
# or
npx http-server -p 8080
```

Frontend will be available at http://localhost:8080

## Testing the Application

### 1. Register a User
- Go to http://localhost:8080/register.html
- Create a new account

### 2. Add Sample Movies via API
```bash
# Add The Matrix
curl -X POST http://localhost:5000/api/movies \
  -H "Content-Type: application/json" \
  -d '{
    "title": "The Matrix",
    "description": "A computer hacker learns about the true nature of reality and his role in the war against its controllers.",
    "genre": "Sci-Fi",
    "releaseYear": 1999,
    "director": "The Wachowskis",
    "duration": 136,
    "rating": 8.7,
    "posterUrl": "",
    "pricing": {
      "rent": 3.99,
      "buy": 12.99
    },
    "stock": {
      "available": 5,
      "total": 5
    }
  }'

# Add Inception
curl -X POST http://localhost:5000/api/movies \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Inception",
    "description": "A thief who steals corporate secrets through dream-sharing technology is given the inverse task of planting an idea.",
    "genre": "Sci-Fi",
    "releaseYear": 2010,
    "director": "Christopher Nolan",
    "duration": 148,
    "rating": 8.8,
    "pricing": {
      "rent": 2.99,
      "buy": 9.99
    }
  }'

# Add The Godfather
curl -X POST http://localhost:5000/api/movies \
  -H "Content-Type: application/json" \
  -d '{
    "title": "The Godfather",
    "description": "The aging patriarch of an organized crime dynasty transfers control to his reluctant son.",
    "genre": "Drama",
    "releaseYear": 1972,
    "director": "Francis Ford Coppola",
    "duration": 175,
    "rating": 9.2,
    "pricing": {
      "rent": 2.99,
      "buy": 14.99
    }
  }'
```

### 3. Browse and Rent Movies
- Login with your account
- Browse movies on the home page
- Click "Rent" or "Buy" to make a transaction
- View your rentals in "My Rentals"

## Viewing Datadog Metrics

1. Log in to https://app.datadoghq.com
2. Go to **APM** > **Services** to see your services
3. Go to **Security** > **Application Security** to see security events
4. Go to **Infrastructure** > **Containers** to see container metrics

## Troubleshooting

### Backend won't start
- Check MongoDB is running: `docker ps | grep mongo`
- Check logs: `docker-compose logs backend`
- Verify `.env` file exists and has correct values

### Frontend can't connect to backend
- Check API_URL in `frontend/app.js` (should be http://localhost:5000)
- Ensure backend is running and accessible
- Check browser console for errors

### Datadog not receiving data
- Verify DD_API_KEY is correct
- Check Datadog agent logs: `docker-compose logs datadog-agent`
- Verify agent is running: `docker ps | grep datadog`

### MongoDB connection failed
- Ensure MongoDB is running
- Check MONGODB_URI in backend/.env
- Verify network connectivity: `docker network ls`

## Next Steps

- Explore the API documentation in [README.md](README.md)
- Customize the frontend styling in `frontend/style.css`
- Add more movies via the API
- Create custom Datadog dashboards
- Set up alerts for application errors
- Implement additional features

## Useful Commands

```bash
# Docker Compose
docker-compose up -d              # Start all services
docker-compose down               # Stop all services
docker-compose logs -f backend    # View backend logs
docker-compose ps                 # List running services
docker-compose restart backend    # Restart backend

# Kubernetes
kubectl get pods -n video-rental              # List pods
kubectl logs -f <pod-name> -n video-rental   # View pod logs
kubectl describe pod <pod-name> -n video-rental  # Pod details
kubectl delete -f k8s/                        # Delete all resources

# Testing API
curl http://localhost:5000/health             # Health check
curl http://localhost:5000/api/movies         # List movies
```

For more detailed information, see [README.md](README.md)
