# Wolfronix Production Deployment Guide

> **Engine v2** · SDK v2.3.0 · Last updated: February 2026

## Server Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| RAM | 4 GB | 16+ GB |
| Storage | 50 GB | 500+ GB |
| CPU | 2 cores | 4+ cores |
| OS | Ubuntu 20.04+ | Ubuntu 22.04 LTS |

---

## Quick Start (5 Minutes)

### 1. Prepare Your Server

```bash
# Ubuntu 22.04 LTS
sudo apt update && sudo apt upgrade -y
sudo apt install git -y
```

### 2. Download Wolfronix

```bash
cd /opt
sudo git clone https://github.com/YOUR_REPO/wolfronix_go.git wolfronix
cd wolfronix/deploy
```

Or copy from your local machine:
```bash
# From Windows (PowerShell)
scp -r E:\Projects_office\Wolfronix_up_to_500\wolfronix_go-main\wolfronix_go-main user@YOUR_SERVER_IP:/opt/wolfronix
```

### 3. Run Deployment Script

```bash
cd /opt/wolfronix/deploy
chmod +x deploy.sh
sudo ./deploy.sh your-domain.com

# Or without a domain (uses localhost + self-signed cert)
sudo ./deploy.sh
```

The script will:
- Install Docker if missing
- Generate secure secrets (DB_PASSWORD, JWT_SECRET, MASTER_KEY, ADMIN_API_KEY)
- Build the Wolfronix Docker image
- Set up nginx with SSL (Let's Encrypt or self-signed)
- Start all services
- Configure firewall

### 4. Done!

```
https://YOUR_SERVER:9443/health          → Health check
https://YOUR_SERVER:9443/api/v1/...      → API endpoints
wss://YOUR_SERVER:9443/api/v1/stream     → WebSocket streaming
```

---

## What Gets Deployed

```
┌─────────────────────────────────────────────────────────────┐
│                        INTERNET                              │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼ (Port 9443 HTTPS + WSS)
┌─────────────────────────────────────────────────────────────┐
│                    YOUR SERVER                                │
│                                                               │
│  ┌───────────────────────────────────────────────────────┐   │
│  │  NGINX (Alpine) — Port 9443                           │   │
│  │  • SSL termination (Let's Encrypt / self-signed)      │   │
│  │  • Rate limiting (100 req/s burst 50)                 │   │
│  │  • WebSocket proxy (Connection: Upgrade)              │   │
│  │  • 500MB upload limit                                 │   │
│  └───────────────────────┬───────────────────────────────┘   │
│                          │ internal :5001                     │
│  ┌───────────────────────▼───────────────────────────────┐   │
│  │  WOLFRONIX ENGINE (Go 1.22)                           │   │
│  │  • File encrypt/decrypt (4-layer)                     │   │
│  │  • Message encrypt/decrypt (dual-key AES-GCM)         │   │
│  │  • WebSocket streaming (real-time)                    │   │
│  │  • Enterprise client management                       │   │
│  │  • Zero-knowledge key storage                         │   │
│  └────────┬──────────────────────────────┬───────────────┘   │
│           │                              │                    │
│  ┌────────▼────────┐           ┌─────────▼──────────┐        │
│  │  PostgreSQL 15  │           │  Redis 7 (cache)   │        │
│  │  (client_reg,   │           │  (optional)         │        │
│  │   user_keys,    │           └────────────────────┘        │
│  │   metrics)      │                                          │
│  └─────────────────┘                                          │
└───────────────────────────────────────────────────────────────┘
```

---

## Detailed Setup

### Network / Port Forwarding

If your server is behind a router:

```bash
ip addr show  # Get server's local IP

# Forward on your router:
#   External 9080  → Internal YOUR_SERVER_IP:9080   (HTTP → HTTPS redirect)
#   External 9443  → Internal YOUR_SERVER_IP:9443   (HTTPS + WSS)
```

### Domain Setup (Optional but Recommended)

1. Buy a domain (Namecheap, Cloudflare, etc.)
2. Add DNS A record: `api.wolfronix.com → YOUR_PUBLIC_IP`
3. Wait 5-30 minutes for propagation
4. Run: `sudo ./deploy.sh api.wolfronix.com`

### Configure Environment

The deploy script auto-generates `.env`. To customize:

```bash
sudo nano /opt/wolfronix/deploy/.env
```

| Variable | Required | Description |
|----------|----------|-------------|
| `DB_PASSWORD` | Yes | PostgreSQL password (auto-generated) |
| `JWT_SECRET` | Yes | JWT signing key (auto-generated) |
| `MASTER_KEY` | Yes | Master encryption key (auto-generated) |
| `ADMIN_API_KEY` | Yes | Admin key for enterprise endpoints (auto-generated) |
| `ALLOWED_ORIGINS` | No | CORS origins, comma-separated (default: your domain) |
| `CLIENT_DB_API_ENDPOINT` | No | Client DB URL for enterprise mode |
| `CLIENT_DB_API_KEY` | No | Client DB auth key |
| `GOMEMLIMIT` | No | Go memory limit (default: 24GiB) |
| `SSL_MODE` | No | `letsencrypt` or `selfsigned` |
| `DOMAIN` | No | Your domain (default: localhost) |

Generate secrets manually:
```bash
openssl rand -hex 32  # For JWT_SECRET, MASTER_KEY, ADMIN_API_KEY
openssl rand -hex 16  # For DB_PASSWORD
```

---

## Auto-Start on Boot

```bash
sudo cp /opt/wolfronix/deploy/wolfronix.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable wolfronix

# Control commands
sudo systemctl start wolfronix
sudo systemctl stop wolfronix
sudo systemctl restart wolfronix
sudo systemctl status wolfronix
```

---

## Useful Commands

### View Logs
```bash
cd /opt/wolfronix/deploy

# All services
docker compose -f docker-compose.prod.yml logs -f

# Specific service
docker compose -f docker-compose.prod.yml logs -f wolfronix
docker compose -f docker-compose.prod.yml logs -f nginx
docker compose -f docker-compose.prod.yml logs -f wolfronix_db
```

### Restart Services
```bash
docker compose -f docker-compose.prod.yml restart

# Or just the engine
docker compose -f docker-compose.prod.yml restart wolfronix
```

### Update Wolfronix
```bash
cd /opt/wolfronix
git pull origin main
cd deploy
docker compose -f docker-compose.prod.yml up -d --build wolfronix
```

### Backup Database
```bash
# Backup
docker exec wolfronix_db pg_dump -U wolfuser wolfronix > backup_$(date +%Y%m%d).sql

# Restore
cat backup_20260212.sql | docker exec -i wolfronix_db psql -U wolfuser wolfronix
```

### Run E2E Tests
```bash
cd /opt/wolfronix/deploy
chmod +x test_enterprise.sh
./test_enterprise.sh https://localhost:9443 your-admin-api-key

# Tests: health → register → keys → encrypt → messages → deactivate
```

### Check Resource Usage
```bash
docker stats
```

---

## Firewall Configuration

### UFW (Ubuntu)
```bash
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 9080/tcp  # HTTP redirect
sudo ufw allow 9443/tcp  # HTTPS + WSS
sudo ufw enable
sudo ufw status
```

### Firewalld (CentOS/RHEL)
```bash
sudo firewall-cmd --permanent --add-port=9080/tcp
sudo firewall-cmd --permanent --add-port=9443/tcp
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --reload
```

---

## Endpoints Available After Deployment

| Category | Endpoint | Auth |
|----------|----------|------|
| **Health** | `GET /health` | None |
| **Files** | `POST /api/v1/encrypt` | X-Wolfronix-Key |
| | `GET /api/v1/files` | X-Wolfronix-Key |
| | `GET /api/v1/files/{id}/key` | X-Wolfronix-Key |
| | `POST /api/v1/files/{id}/decrypt` | X-Wolfronix-Key |
| | `DELETE /api/v1/files/{id}` | X-Wolfronix-Key |
| **Messages** | `POST /api/v1/messages/encrypt` | X-Wolfronix-Key |
| | `POST /api/v1/messages/decrypt` | X-Wolfronix-Key |
| | `POST /api/v1/messages/batch/encrypt` | X-Wolfronix-Key |
| **Streaming** | `WSS /api/v1/stream` | `wolfronix_key` query param |
| **Keys** | `POST /api/v1/keys/register` | X-Wolfronix-Key |
| | `POST /api/v1/keys/login` | X-Wolfronix-Key |
| **Enterprise** | `POST /api/v1/enterprise/register` | X-Admin-Key |
| | `GET /api/v1/enterprise/clients` | X-Admin-Key |
| | `DELETE /api/v1/enterprise/clients/{id}` | X-Admin-Key |

---

## Troubleshooting

### Container won't start
```bash
docker compose -f docker-compose.prod.yml logs wolfronix
sudo netstat -tlnp | grep -E '9080|9443'
```

### Database connection error
```bash
docker compose -f docker-compose.prod.yml ps wolfronix_db
docker compose -f docker-compose.prod.yml logs wolfronix_db
```

### SSL certificate issues
```bash
openssl s_client -connect localhost:9443 -servername your-domain.com

# Regenerate self-signed cert
cd /opt/wolfronix/deploy/nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
    -keyout privkey.pem -out fullchain.pem \
    -subj "/CN=your-domain.com"
docker compose -f docker-compose.prod.yml restart nginx
```

### WebSocket not connecting
```bash
# Verify nginx proxies WebSocket correctly
curl -sk -i -N \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGVzdA==" \
  "https://localhost:9443/api/v1/stream?wolfronix_key=test"
# Should return HTTP 101 Switching Protocols
```

### Out of memory
```bash
free -h
docker stats
# Edit GOMEMLIMIT in .env, then:
docker compose -f docker-compose.prod.yml restart wolfronix
```

---

## Security Checklist

- [ ] Default passwords changed in `.env` (auto-generated by deploy.sh)
- [ ] `.env` file has restricted permissions (`chmod 600`)
- [ ] Firewall configured (only SSH + 9080 + 9443 open)
- [ ] SSL certificate installed (Let's Encrypt for production)
- [ ] ADMIN_API_KEY stored securely (needed for enterprise management)
- [ ] ALLOWED_ORIGINS set to your frontend domain (not `*`)
- [ ] Regular database backups configured
- [ ] SSH key authentication enabled (disable password login)

---

## Support

- Documentation: https://wolfronix.com/docs
- Issues: https://github.com/wolfronix/wolfronix_go/issues
- Email: support@wolfronix.com
