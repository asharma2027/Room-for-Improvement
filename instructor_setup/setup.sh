#!/bin/bash

echo "================================"
echo "  Room for Improvement - Setup  "
echo "================================"
echo ""

# Check for Node.js
if ! command -v node &> /dev/null; then
  echo "ERROR: Node.js is not installed."
  echo "Please download and install it from https://nodejs.org, then run this script again."
  exit 1
fi

echo "Node.js found: $(node -v)"
echo ""

# Install dependencies
echo "Installing dependencies (this may take ~30 seconds the first time)..."
npm install

if [ $? -ne 0 ]; then
  echo ""
  echo "ERROR: npm install failed. Make sure you're running this from the project root folder."
  exit 1
fi

echo ""
echo "Starting server..."
echo ""
echo "================================"
echo "  Site is running!"
echo "  Open: http://localhost:3000"
echo ""
echo "  Login with:"
echo "    Email:    test@uchicago.edu"
echo "    Password: test"
echo ""
echo "  Press Ctrl+C to stop."
echo "================================"
echo ""

# Open browser (works on Mac; harmless if it fails)
sleep 1 && open "http://localhost:3000" &

npm start
