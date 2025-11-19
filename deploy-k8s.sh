#!/bin/bash

# Video Rental Store - Kubernetes Deployment Script

echo "==================================="
echo "Video Rental Store - K8s Deployment"
echo "==================================="
echo ""

# Check if kubectl is installed
if ! command -v kubectl &> /dev/null; then
    echo "Error: kubectl is not installed"
    exit 1
fi

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Error: docker is not installed"
    exit 1
fi

echo "Step 1: Building Docker images..."
echo ""

# Build backend image
echo "Building backend image..."
cd backend
docker build -t video-rental-backend:latest .
if [ $? -ne 0 ]; then
    echo "Error: Failed to build backend image"
    exit 1
fi

# Build frontend image
echo "Building frontend image..."
cd ../frontend
docker build -t video-rental-frontend:latest .
if [ $? -ne 0 ]; then
    echo "Error: Failed to build frontend image"
    exit 1
fi

cd ..
echo ""
echo "Step 2: Deploying to Kubernetes..."
echo ""

# Create namespace
echo "Creating namespace..."
kubectl apply -f k8s/namespace.yaml

# Deploy MongoDB
echo "Deploying MongoDB..."
kubectl apply -f k8s/mongodb-deployment.yaml

# Wait for MongoDB to be ready
echo "Waiting for MongoDB to be ready..."
kubectl wait --for=condition=ready pod -l app=mongodb -n video-rental --timeout=120s

# Deploy Datadog Agent
echo "Deploying Datadog Agent..."
kubectl apply -f k8s/datadog-agent.yaml

# Deploy backend
echo "Deploying backend..."
kubectl apply -f k8s/backend-deployment.yaml

# Wait for backend to be ready
echo "Waiting for backend to be ready..."
kubectl wait --for=condition=ready pod -l app=backend -n video-rental --timeout=120s

# Deploy frontend
echo "Deploying frontend..."
kubectl apply -f k8s/frontend-deployment.yaml

# Wait for frontend to be ready
echo "Waiting for frontend to be ready..."
kubectl wait --for=condition=ready pod -l app=frontend -n video-rental --timeout=120s

# Optional: Deploy ingress
read -p "Do you want to deploy the ingress? (y/n) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Deploying ingress..."
    kubectl apply -f k8s/ingress.yaml
fi

echo ""
echo "==================================="
echo "Deployment Complete!"
echo "==================================="
echo ""
echo "Check deployment status:"
echo "  kubectl get all -n video-rental"
echo ""
echo "Access the application:"
echo "  kubectl port-forward -n video-rental svc/frontend 8080:80"
echo "  kubectl port-forward -n video-rental svc/backend 5000:5000"
echo ""
echo "View logs:"
echo "  kubectl logs -f -l app=backend -n video-rental"
echo "  kubectl logs -f -l app=frontend -n video-rental"
echo ""
