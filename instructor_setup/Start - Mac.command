#!/bin/bash

# ─────────────────────────────────────────────
#  Room for Improvement — One-Click Mac Launcher
# ─────────────────────────────────────────────

# Change to the project root (parent of this script's folder)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR" || exit 1

clear
echo "╔══════════════════════════════════════╗"
echo "║   Room for Improvement — Starting    ║"
echo "╚══════════════════════════════════════╝"
echo ""

# ── 1. Install Node.js if missing ──────────────────────────────────────────────
install_node_mac() {
  echo "Node.js not found. Installing now (this only happens once)..."
  echo ""

  # Try Homebrew first (silent install of brew if needed)
  if ! command -v brew &>/dev/null; then
    echo "Installing Homebrew (package manager)..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    # Add brew to PATH for Apple Silicon
    if [ -f "/opt/homebrew/bin/brew" ]; then
      eval "$(/opt/homebrew/bin/brew shellenv)"
    fi
  fi

  if command -v brew &>/dev/null; then
    echo "Installing Node.js via Homebrew..."
    brew install node
  else
    # Fallback: download the official .pkg installer
    echo "Downloading Node.js installer..."
    NODE_PKG="/tmp/node_installer.pkg"
    curl -fsSL "https://nodejs.org/dist/v20.12.2/node-v20.12.2.pkg" -o "$NODE_PKG"
    echo "Running Node.js installer (you may be prompted for your password)..."
    sudo installer -pkg "$NODE_PKG" -target /
    rm -f "$NODE_PKG"
  fi

  # Reload PATH
  export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH"
}

if ! command -v node &>/dev/null; then
  install_node_mac
fi

if ! command -v node &>/dev/null; then
  echo ""
  echo "ERROR: Could not install Node.js automatically."
  echo "Please install it manually from https://nodejs.org and try again."
  echo ""
  read -p "Press Enter to close..."
  exit 1
fi

echo "✓ Node.js $(node -v)"
echo ""

# ── 2. Copy .env if missing ────────────────────────────────────────────────────
if [ ! -f ".env" ]; then
  if [ -f "instructor_setup/.env.example" ]; then
    cp "instructor_setup/.env.example" ".env"
    echo "✓ Created .env from example"
  fi
fi

# ── 3. Install npm dependencies ────────────────────────────────────────────────
echo "Installing dependencies (first run takes ~30 seconds)..."
npm install --prefer-offline --no-audit --no-fund 2>&1 | tail -5

if [ $? -ne 0 ]; then
  echo ""
  echo "ERROR: npm install failed."
  read -p "Press Enter to close..."
  exit 1
fi
echo "✓ Dependencies ready"
echo ""

# ── 4. Kill any existing process on port 3000 ─────────────────────────────────
PORT=3000
EXISTING_PID=$(lsof -ti tcp:$PORT 2>/dev/null)
if [ -n "$EXISTING_PID" ]; then
  echo "Stopping previous server on port $PORT..."
  kill -9 $EXISTING_PID 2>/dev/null
  sleep 1
fi

# ── 5. Start the server ────────────────────────────────────────────────────────
echo "Starting server..."
node server.js &
SERVER_PID=$!

# Wait for server to be ready (up to 15 seconds)
echo "Waiting for server to be ready..."
for i in $(seq 1 15); do
  sleep 1
  if curl -s "http://localhost:$PORT" >/dev/null 2>&1; then
    break
  fi
done

# ── 6. Open browser ────────────────────────────────────────────────────────────
open "http://localhost:$PORT"

echo ""
echo "╔══════════════════════════════════════╗"
echo "║   ✓ Site is running!                 ║"
echo "║   http://localhost:3000              ║"
echo "║                                      ║"
echo "║   Login:  test@uchicago.edu          ║"
echo "║   Password: test                     ║"
echo "║                                      ║"
echo "║   Close this window to stop.         ║"
echo "╚══════════════════════════════════════╝"
echo ""

# Keep running until this window is closed (which kills the server)
trap "echo ''; echo 'Stopping server...'; kill $SERVER_PID 2>/dev/null; exit 0" INT TERM EXIT

wait $SERVER_PID
