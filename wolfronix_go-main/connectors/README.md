# Wolfronix Database Connectors

Pre-built connector servers that bridge the **Wolfronix Engine** to your choice of database. Each connector implements all required HTTP endpoints — just configure, deploy, and connect.

## How It Works

```
┌──────────────┐    HTTP/REST    ┌─────────────────┐    Native Driver    ┌──────────────┐
│   Wolfronix  │ ──────────────► │   Connector     │ ──────────────────► │  Your        │
│   Engine     │ ◄────────────── │   Server        │ ◄────────────────── │  Database    │
└──────────────┘                 └─────────────────┘                     └──────────────┘
```

The Wolfronix Engine sends encrypted file metadata, encryption keys, and binary data to the connector via HTTP. The connector stores it in your database using native drivers.

## Pick Your Database

| Connector | Database | Best For |
|-----------|----------|----------|
| [supabase/](supabase/) | Supabase (PostgreSQL) | Teams already on Supabase, serverless setups |
| [mongodb/](mongodb/) | MongoDB / Atlas | Document-oriented apps, flexible schemas |
| [mysql/](mysql/) | MySQL / MariaDB | Traditional web apps, WordPress-style stacks |
| [firebase/](firebase/) | Firebase Firestore + Storage | Google Cloud / mobile-first teams |
| [postgresql/](postgresql/) | PostgreSQL (self-hosted/RDS/Neon) | Maximum control, raw performance |

## Quick Setup (Any Connector)

```bash
# 1. Pick a connector
cd connectors/postgresql   # or supabase, mongodb, mysql, firebase

# 2. Run schema (SQL-based connectors only)
#    - Supabase:   paste schema.sql into Supabase SQL Editor
#    - MySQL:      mysql -u root -p < schema.sql  
#    - PostgreSQL: psql -d wolfronix -f schema.sql
#    - MongoDB:    no schema needed (auto-creates collections)
#    - Firebase:   no schema needed (auto-creates collections)

# 3. Configure
cp .env.example .env
nano .env   # fill in your database credentials + API key

# 4. Install & Start
npm install
npm start   # connector runs on port 8080

# 5. Connect to Wolfronix Engine
#    Add to engine's .env:
#    CLIENT_DB_API_ENDPOINT=http://connector-host:8080
#    CLIENT_DB_API_KEY=your-connector-api-key
#    CLIENT_DB_TYPE=custom_api
```

## Docker Deployment

Each connector includes a Dockerfile:

```bash
cd connectors/postgresql
docker build -t wolfronix-pg-connector .
docker run -d --env-file .env -p 8080:8080 wolfronix-pg-connector
```

Or add to your `docker-compose.prod.yml` (see deploy/ folder for examples).

## Endpoints Each Connector Implements

Every connector provides these **11 endpoints** that the Wolfronix Engine expects:

### File Storage
| Method | Path | Description |
|--------|------|-------------|
| POST | `/wolfronix/files` | Store encrypted file metadata |
| POST | `/wolfronix/files/upload` | Store metadata + encrypted data (multipart) |
| GET | `/wolfronix/files/:id` | Get file metadata (ownership verified) |
| GET | `/wolfronix/files/:id/data` | Get encrypted file data as raw bytes |
| GET | `/wolfronix/files?user_id=X` | List all files for a user |
| DELETE | `/wolfronix/files/:id` | Delete file + data (ownership verified) |

### Key Management
| Method | Path | Description |
|--------|------|-------------|
| POST | `/wolfronix/keys` | Store user's wrapped encryption key |
| GET | `/wolfronix/keys/:userId` | Get user's full wrapped key |
| GET | `/wolfronix/keys/:userId/public` | Get user's public key only |

### Dev Data
| Method | Path | Description |
|--------|------|-------------|
| POST | `/wolfronix/dev/files` | Store fake/masked data for dev environments |

### Health
| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Connector + database health check |

## Auth Headers

The Wolfronix Engine sends these headers with every request:

| Header | Description |
|--------|-------------|
| `X-Wolfronix-API-Key` | API key for authentication (matches `CONNECTOR_API_KEY`) |
| `X-Client-ID` | The registered client/app ID |
| `X-User-ID` | The user performing the operation |

## Building Your Own Connector

If your database isn't listed, implement the 11 endpoints above in any language/framework. The engine only cares about:

1. **Correct URL paths** (e.g., `/wolfronix/files`, `/wolfronix/files/:id/data`)
2. **Standard JSON responses** (metadata as JSON, file data as raw bytes)
3. **Status codes**: 200/201 for success, 404 for not found, 403 for access denied
4. **Ownership checks**: Verify `X-User-ID` + `X-Client-ID` match the stored record

See [internal/clientdb/clientdb.go](../internal/clientdb/clientdb.go) for the exact contract.
