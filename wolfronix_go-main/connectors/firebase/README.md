# Wolfronix Firebase Connector

Bridges the Wolfronix Engine to **Firebase** (Firestore + Cloud Storage) for encrypted file and key storage.

- **Metadata** → Firestore collections
- **Encrypted file data** → Cloud Storage bucket

## Quick Start

```bash
# 1. Download your Firebase service account key
#    Firebase Console → Project Settings → Service Accounts → Generate New Private Key
#    Save as serviceAccountKey.json in this directory

# 2. Configure
cp .env.example .env
# Edit .env with your Firebase project details

# 3. Install & Run
npm install
npm start
```

No schema migration needed — Firestore creates collections automatically.

## Firestore Indexes

Create a composite index for file listing (required by the orderBy query):

```
Collection: wolfronix_files
Fields: client_id (Ascending), user_id (Ascending), created_at (Descending)
```

You can create this in Firebase Console → Firestore → Indexes, or it will auto-prompt on first query.

## Docker

```bash
docker build -t wolfronix-firebase-connector .
docker run -d --env-file .env \
  -v $(pwd)/serviceAccountKey.json:/app/serviceAccountKey.json:ro \
  -p 8080:8080 wolfronix-firebase-connector
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

## Firestore Collections

- `wolfronix_files` — Encrypted file metadata
- `wolfronix_keys` — User encryption keys (wrapped)
- `wolfronix_dev_files` — Fake data for dev environments
- `wolfronix_counters` — Auto-increment ID counters

## Cloud Storage Structure

```
wolfronix/encrypted/{fileId}.enc  — Encrypted file blobs
```
