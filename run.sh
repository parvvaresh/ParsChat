#!/bin/bash

echo "Starting Chat Server..."
echo ""

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No color

# Check Go installation
if ! command -v go &> /dev/null; then
    echo -e "${RED}[ERROR] Go is not installed. Please install Go 1.21+${NC}"
    exit 1
fi

echo -e "${GREEN}[OK] Go found${NC}"

# Download dependencies
echo -e "${BLUE}[INFO] Downloading sqlite3...${NC}"
GOPROXY=https://goproxy.io,direct go mod download 2>/dev/null || go mod download 2>/dev/null || true

# Build the application
echo -e "${BLUE}[INFO] Building server...${NC}"
CGO_ENABLED=1 go build -o chat-server ./cmd/server/main.go

if [ $? -ne 0 ]; then
    echo -e "${RED}[ERROR] Failed to build server${NC}"
    echo -e "${BLUE}[INFO] Make sure gcc and sqlite3-dev are installed:${NC}"
    echo "  sudo apt install gcc libsqlite3-dev"
    exit 1
fi

echo -e "${GREEN}[OK] Server built successfully${NC}"

# Create uploads directory
mkdir -p uploads

# Run the server
echo ""
echo -e "${GREEN}[OK] Server is ready!${NC}"
echo -e "${BLUE}[INFO] Running on http://localhost:8080${NC}"
echo ""
echo -e "To stop the server: ${RED}Ctrl+C${NC}"
echo ""
echo "========================================"

./chat-server
