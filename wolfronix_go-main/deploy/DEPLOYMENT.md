# Wolfronix Production Deployment Guide

## Server Requirements

| Component | Minimum | Recommended | Your Server |
|-----------|---------|-------------|-------------|
| RAM | 4 GB | 16 GB | 32 GB ✅ |
| Storage | 50 GB | 500 GB | 3 TB ✅ |
| CPU | 2 cores | 4+ cores | Check |
| OS | Ubuntu 20.04+ | Ubuntu 22.04 | - |

---

## Quick Start (5 Minutes)

### 1. Prepare Your Server

```bash
# Install Ubuntu 22.04 LTS on your physical server
# Connect via SSH or directly

# Update system
sudo apt update && sudo apt upgrade -y

# Install Git
sudo apt install git -y
```

### 2. Download Wolfronix

```bash
# Clone repository
cd /opt
sudo git clone https://github.com/YOUR_REPO/wolfronix_go.git wolfronix
cd wolfronix/deploy
```

Or copy from your local machine:
```bash
# From your Windows machine (PowerShell)
scp -r E:\Projects_office\Wolfronix_up_to_500\wolfronix_go-main\wolfronix_go-main user@YOUR_SERVER_IP:/opt/wolfronix
```

### 3. Run Deployment Script

```bash
cd /opt/wolfronix/deploy
chmod +x deploy.sh
sudo ./deploy.sh your-domain.com

# Or without a domain (uses IP address)
sudo ./deploy.sh
```

### 4. Done!

Your Wolfronix server is now running at:
- `https://YOUR_SERVER_IP` (if no domain)
- `https://your-domain.com` (if using domain)

---

## Detailed Setup

### Step 1: Network Configuration

If your server is behind a router:

```bash
# Check your server's local IP
ip addr show

# Configure port forwarding on your router:
# External 80  → Internal YOUR_SERVER_IP:80
# External 443 → Internal YOUR_SERVER_IP:443
```

### Step 2: Domain Setup (Optional but Recommended)

1. Buy a domain from Namecheap, GoDaddy, Cloudflare, etc.
2. Add DNS A record:
   - Type: `A`
   - Name: `api` (or `@` for root domain)
   - Value: `YOUR_PUBLIC_IP`
   - TTL: `Auto` or `3600`

3. Wait for DNS propagation (5-30 minutes)

### Step 3: SSL Certificate

The deployment script handles SSL automatically:

| Scenario | SSL Type | Notes |
|----------|----------|-------|
| With domain | Let's Encrypt | Free, auto-renews |
| Without domain | Self-signed | Works, but browsers show warning |

For Let's Encrypt, ensure:
- Domain points to your server
- Ports 80 and 443 are open

### Step 4: Configure Environment

Edit `/opt/wolfronix/deploy/.env`:

```bash
sudo nano /opt/wolfronix/deploy/.env
```

Important settings:
```env
# Change these!
DB_PASSWORD=your-secure-password
JWT_SECRET=your-64-char-secret
MASTER_KEY=your-64-char-key

# Your domain
DOMAIN=api.wolfronix.com

# Memory (adjust based on your server)
GOMEMLIMIT=24GiB
```

Generate secure secrets:
```bash
# Generate random secrets
openssl rand -hex 32  # For JWT_SECRET
openssl rand -hex 32  # For MASTER_KEY
openssl rand -hex 16  # For DB_PASSWORD
```

---

## Auto-Start on Boot

```bash
# Copy service file
sudo cp /opt/wolfronix/deploy/wolfronix.service /etc/systemd/system/

# Enable auto-start
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

# All logs
docker-compose -f docker-compose.prod.yml logs -f

# Specific service
docker-compose -f docker-compose.prod.yml logs -f wolfronix
docker-compose -f docker-compose.prod.yml logs -f nginx
docker-compose -f docker-compose.prod.yml logs -f wolfronix_db
```

### Restart Services
```bash
docker-compose -f docker-compose.prod.yml restart

# Or specific service
docker-compose -f docker-compose.prod.yml restart wolfronix
```

### Update Wolfronix
```bash
cd /opt/wolfronix
git pull origin main
cd deploy
docker-compose -f docker-compose.prod.yml up -d --build
```

### Backup Database
```bash
# Backup
docker exec wolfronix_db pg_dump -U wolfuser wolfronix > backup_$(date +%Y%m%d).sql

# Restore
cat backup_20260206.sql | docker exec -i wolfronix_db psql -U wolfuser wolfronix
```

### Check Resource Usage
```bash
docker stats
```

---

## Firewall Configuration

### UFW (Ubuntu)
```bash
sudo ufw allow 22/tcp   # SSH
sudo ufw allow 80/tcp   # HTTP
sudo ufw allow 443/tcp  # HTTPS
sudo ufw enable
sudo ufw status
```

### Firewalld (CentOS/RHEL)
```bash
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

---

## Monitoring

### Health Check
```bash
curl -k https://localhost/health
```

### API Status
```bash
curl -k https://localhost/api/v1/metrics
```

### Container Status
```bash
docker-compose -f docker-compose.prod.yml ps
```

---

## Troubleshooting

### Container won't start
```bash
# Check logs
docker-compose -f docker-compose.prod.yml logs wolfronix

# Check if port is in use
sudo netstat -tlnp | grep -E '80|443'
```

### Database connection error
```bash
# Check database is running
docker-compose -f docker-compose.prod.yml ps wolfronix_db

# Check database logs
docker-compose -f docker-compose.prod.yml logs wolfronix_db
```

### SSL certificate issues
```bash
# Check certificate
openssl s_client -connect localhost:443 -servername your-domain.com

# Regenerate self-signed cert
cd /opt/wolfronix/deploy/nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
    -keyout privkey.pem -out fullchain.pem \
    -subj "/CN=your-domain.com"
```

### Out of memory
```bash
# Check memory usage
free -h
docker stats

# Reduce memory limit in docker-compose.prod.yml
# Edit GOMEMLIMIT in .env
```

---

## Architecture (Production)

```
┌─────────────────────────────────────────────────────────────┐
│                    INTERNET                                  │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼ (Port 443)
┌─────────────────────────────────────────────────────────────┐
│                    YOUR SERVER (32GB RAM, 3TB)               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                    NGINX                              │   │
│  │              (SSL Termination)                        │   │
│  │              (Rate Limiting)                          │   │
│  │              (Load Balancing)                         │   │
│  └──────────────────────┬───────────────────────────────┘   │
│                         │                                    │
│                         ▼ (Internal)                         │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              WOLFRONIX ENGINE                         │   │
│  │              (24GB Memory)                            │   │
│  │              (Go 1.22)                                │   │
│  └────────┬─────────────────────────────┬───────────────┘   │
│           │                             │                    │
│           ▼                             ▼                    │
│  ┌────────────────┐           ┌────────────────────┐        │
│  │  PostgreSQL    │           │  Encrypted Files   │        │
│  │  (4GB Memory)  │           │  (3TB Storage)     │        │
│  └────────────────┘           └────────────────────┘        │
└─────────────────────────────────────────────────────────────┘
```

---

## Security Checklist

- [ ] Changed default passwords in `.env`
- [ ] Firewall configured (only 22, 80, 443 open)
- [ ] SSL certificate installed (Let's Encrypt or trusted CA)
- [ ] `.env` file has restricted permissions (`chmod 600`)
- [ ] Regular backups configured
- [ ] Monitoring set up
- [ ] SSH key authentication (disable password login)

---

## Support

- Documentation: https://wolfronix.com/docs
- GitHub Issues: https://github.com/wolfronix/wolfronix_go/issues
- Email: support@wolfronix.com
