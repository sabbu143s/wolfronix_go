# Wolfronix MongoDB Connector

Bridges the Wolfronix Engine to **MongoDB** (local or Atlas) for encrypted file and key storage.

## Quick Start

```bash
# 1. Configure
cp .env.example .env
# Edit .env with your MongoDB connection string

# 2. Install & Run
npm install
npm start
```

No schema migration needed — MongoDB creates collections automatically.

## Docker

```bash
docker build -t wolfronix-mongodb-connector .
docker run -d --env-file .env -p 8080:8080 wolfronix-mongodb-connector
```

## Connection to Wolfronix Engine

Set these in your Wolfronix engine `.env`:

```
CLIENT_DB_API_ENDPOINT=http://your-connector-host:8080
CLIENT_DB_API_KEY=your-connector-api-key
CLIENT_DB_TYPE=custom_api
```

## Endpoints Implemented

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| POST | `/wolfronix/files` | Store file metadata |
| POST | `/wolfronix/files/upload` | Store metadata + encrypted data (multipart) |
| GET | `/wolfronix/files/:id` | Get file metadata |
| GET | `/wolfronix/files/:id/data` | Get encrypted file data (raw bytes) |
| GET | `/wolfronix/files?user_id=X` | List files for user |
| DELETE | `/wolfronix/files/:id` | Delete file |
| POST | `/wolfronix/keys` | Store user's wrapped key |
| GET | `/wolfronix/keys/:userId` | Get user's wrapped key |
| GET | `/wolfronix/keys/:userId/public` | Get user's public key |
| POST | `/wolfronix/dev/files` | Store fake/dev data |

## Collections

- `wolfronixfiles` — Encrypted file metadata
- `wolfronixfiledatas` — Encrypted file binary data (Buffer)
- `wolfronixkeys` — User encryption keys (wrapped)
- `wolfronixdevfiles` — Fake data for dev environments
