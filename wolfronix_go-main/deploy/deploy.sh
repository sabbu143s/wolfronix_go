#!/bin/bash

# =============================================================================
# Wolfronix Production Deployment Script
# 
# Usage: ./deploy.sh [domain]
# Example: ./deploy.sh api.wolfronix.com
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
DOMAIN="${1:-localhost}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_PATH="/opt/wolfronix/data"

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║           WOLFRONIX PRODUCTION DEPLOYMENT                     ║"
echo "║           Zero-Knowledge Encryption Engine                    ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# =============================================================================
# Pre-flight checks
# =============================================================================

echo -e "${YELLOW}[1/8] Running pre-flight checks...${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root (sudo ./deploy.sh)${NC}"
    exit 1
fi

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${YELLOW}Docker not found. Installing...${NC}"
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
fi

# Determine docker compose command (v2 plugin preferred over standalone)
if docker compose version &> /dev/null; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
else
    echo -e "${YELLOW}Docker Compose not found. Installing...${NC}"
    apt-get update
    apt-get install -y docker-compose-plugin
    COMPOSE_CMD="docker compose"
fi
echo -e "${GREEN}Using: ${COMPOSE_CMD}${NC}"

echo -e "${GREEN}✓ Pre-flight checks passed${NC}"

# =============================================================================
# Create directories
# =============================================================================

echo -e "${YELLOW}[2/8] Creating directories...${NC}"

mkdir -p "${DATA_PATH}"
mkdir -p "${DATA_PATH}/postgres"
mkdir -p "${SCRIPT_DIR}/nginx/ssl"
mkdir -p "${SCRIPT_DIR}/certbot/www"
mkdir -p "${SCRIPT_DIR}/certbot/conf"
mkdir -p "${SCRIPT_DIR}/logs"

chmod -R 755 "${DATA_PATH}"

echo -e "${GREEN}✓ Directories created${NC}"

# =============================================================================
# Generate secrets if not exists
# =============================================================================

echo -e "${YELLOW}[3/8] Configuring environment...${NC}"

if [ ! -f "${SCRIPT_DIR}/.env" ]; then
    echo -e "${YELLOW}Creating .env file with secure secrets...${NC}"
    
    DB_PASSWORD=$(openssl rand -hex 16)
    JWT_SECRET=$(openssl rand -hex 32)
    MASTER_KEY=$(openssl rand -hex 32)
    ADMIN_API_KEY=$(openssl rand -hex 32)
    
    # Default to letsencrypt if a real domain is provided, otherwise selfsigned
    if [ "${DOMAIN}" != "localhost" ]; then
        DEFAULT_SSL_MODE="letsencrypt"
    else
        DEFAULT_SSL_MODE="selfsigned"
    fi

    cat > "${SCRIPT_DIR}/.env" << EOF
# Wolfronix Production Configuration
# Generated on $(date)

# Database
DB_PASSWORD=${DB_PASSWORD}

# Security Keys
JWT_SECRET=${JWT_SECRET}
MASTER_KEY=${MASTER_KEY}
ADMIN_API_KEY=${ADMIN_API_KEY}

# Server
DOMAIN=${DOMAIN}
DATA_PATH=${DATA_PATH}
WOLFRONIX_ENV=production
GOMEMLIMIT=24GiB

# CORS (comma-separated origins, or * for all)
ALLOWED_ORIGINS=https://${DOMAIN}

# Enterprise Client DB (configure if using enterprise mode)
# CLIENT_DB_API_ENDPOINT=http://your-client-api:8080/api
# CLIENT_DB_API_KEY=your-client-api-key
# CLIENT_DB_TYPE=custom_api
# CLIENT_DB_TIMEOUT=30s
# CLIENT_DB_RETRY_COUNT=3

# SSL
SSL_MODE=${DEFAULT_SSL_MODE}
SSL_EMAIL=admin@${DOMAIN}
EOF
    
    chmod 600 "${SCRIPT_DIR}/.env"
    echo -e "${GREEN}✓ Environment configured with secure secrets${NC}"
else
    echo -e "${GREEN}✓ Using existing .env file${NC}"
fi

# Load environment
source "${SCRIPT_DIR}/.env"

# =============================================================================
# Generate SSL certificates
# =============================================================================

echo -e "${YELLOW}[4/8] Setting up SSL certificates...${NC}"

SSL_DIR="${SCRIPT_DIR}/nginx/ssl"

if [ "${DOMAIN}" != "localhost" ] && [ "${SSL_MODE}" == "letsencrypt" ]; then
    # Use Let's Encrypt
    echo -e "${YELLOW}Obtaining Let's Encrypt certificate for ${DOMAIN}...${NC}"
    
    # First, start nginx with self-signed cert for challenge
    openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
        -keyout "${SSL_DIR}/privkey.pem" \
        -out "${SSL_DIR}/fullchain.pem" \
        -subj "/CN=${DOMAIN}" 2>/dev/null
    
    # Start nginx temporarily
    ${COMPOSE_CMD} -f "${SCRIPT_DIR}/docker-compose.prod.yml" up -d nginx
    sleep 5
    
    # Get real certificate
    ${COMPOSE_CMD} -f "${SCRIPT_DIR}/docker-compose.prod.yml" run --rm certbot certonly \
        --webroot -w /var/www/certbot \
        --email "${SSL_EMAIL}" \
        --agree-tos --no-eff-email \
        -d "${DOMAIN}"
    
    # Copy certificates
    cp "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "${SSL_DIR}/"
    cp "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "${SSL_DIR}/"
    
    ${COMPOSE_CMD} -f "${SCRIPT_DIR}/docker-compose.prod.yml" down
    
    echo -e "${GREEN}✓ Let's Encrypt certificate obtained${NC}"
else
    # Generate self-signed certificate
    echo -e "${YELLOW}Generating self-signed certificate...${NC}"
    
    openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
        -keyout "${SSL_DIR}/privkey.pem" \
        -out "${SSL_DIR}/fullchain.pem" \
        -subj "/C=US/ST=State/L=City/O=Wolfronix/CN=${DOMAIN}" \
        -addext "subjectAltName=DNS:${DOMAIN},DNS:localhost,IP:127.0.0.1" \
        2>/dev/null
    
    echo -e "${GREEN}✓ Self-signed certificate generated${NC}"
fi

# Fix SSL permissions for nginx container (644 so nginx can read inside container)
chmod 755 "${SSL_DIR}"
chmod 644 "${SSL_DIR}"/*.pem

# =============================================================================
# Build and start services
# =============================================================================

echo -e "${YELLOW}[5/8] Building Wolfronix...${NC}"

cd "${SCRIPT_DIR}"
${COMPOSE_CMD} -f docker-compose.prod.yml build --no-cache wolfronix

echo -e "${GREEN}✓ Build complete${NC}"

echo -e "${YELLOW}[6/8] Starting services...${NC}"

# Stop existing containers (keep volumes to preserve data)
echo -e "${YELLOW}Stopping any previous containers...${NC}"
${COMPOSE_CMD} -f docker-compose.prod.yml down 2>/dev/null || true

# Ensure data directories exist
mkdir -p "${DATA_PATH}"
mkdir -p "${DATA_PATH}/postgres"

${COMPOSE_CMD} -f docker-compose.prod.yml up -d

echo -e "${GREEN}✓ Services started${NC}"

# =============================================================================
# Wait for services to be healthy
# =============================================================================

echo -e "${YELLOW}[7/8] Waiting for services to be healthy...${NC}"

MAX_RETRIES=30
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if curl -sk "https://localhost:9443/health" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Wolfronix is healthy${NC}"
        break
    fi
    
    RETRY_COUNT=$((RETRY_COUNT + 1))
    echo -e "${YELLOW}Waiting for Wolfronix to start... (${RETRY_COUNT}/${MAX_RETRIES})${NC}"
    sleep 2
done

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
    echo -e "${RED}Warning: Health check timed out. Check logs with: ${COMPOSE_CMD} -f docker-compose.prod.yml logs${NC}"
fi

# =============================================================================
# Configure firewall
# =============================================================================

echo -e "${YELLOW}[8/8] Configuring firewall...${NC}"

if command -v ufw &> /dev/null; then
    ufw allow 9080/tcp
    ufw allow 9443/tcp
    ufw allow 22/tcp
    echo -e "${GREEN}✓ UFW firewall configured${NC}"
elif command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --add-port=9080/tcp
    firewall-cmd --permanent --add-port=9443/tcp
    firewall-cmd --permanent --add-service=ssh
    firewall-cmd --reload
    echo -e "${GREEN}✓ Firewalld configured${NC}"
else
    echo -e "${YELLOW}No firewall detected. Please configure manually.${NC}"
fi

# =============================================================================
# Done!
# =============================================================================

echo ""
echo -e "${GREEN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║           WOLFRONIX DEPLOYMENT COMPLETE!                      ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""
echo -e "${BLUE}Server Information:${NC}"
echo "  URL:        https://${DOMAIN}:9443"
echo "  Health:     https://${DOMAIN}:9443/health"
echo "  API:        https://${DOMAIN}:9443/api/v1/"
echo "  WebSocket:  wss://${DOMAIN}:9443/api/v1/stream"
echo ""
echo -e "${BLUE}Admin API Key (save this!):${NC}"
echo "  ${ADMIN_API_KEY:-<check .env file>}"
echo ""
echo -e "${BLUE}Service Status:${NC}"
${COMPOSE_CMD} -f docker-compose.prod.yml ps
echo ""
echo -e "${BLUE}Useful Commands:${NC}"
echo "  View logs:      ${COMPOSE_CMD} -f docker-compose.prod.yml logs -f"
echo "  Restart:        ${COMPOSE_CMD} -f docker-compose.prod.yml restart"
echo "  Stop:           ${COMPOSE_CMD} -f docker-compose.prod.yml down"
echo "  Update:         ${COMPOSE_CMD} -f docker-compose.prod.yml up -d --build"
echo ""
echo -e "${YELLOW}Security Note:${NC}"
echo "  Your secrets are stored in: ${SCRIPT_DIR}/.env"
echo "  Keep this file secure and backed up!"
echo ""
echo -e "${GREEN}Wolfronix is ready to accept connections!${NC}"
