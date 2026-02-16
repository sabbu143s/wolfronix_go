/**
 * Wolfronix PostgreSQL Connector
 * 
 * Bridges Wolfronix Engine ↔ PostgreSQL (self-hosted, RDS, Neon, etc.)
 * Implements all required endpoints for file storage, key management, and dev data.
 * 
 * Supports two modes:
 *   1. Dynamic config — engine passes JSON db_config via X-Wolfronix-API-Key header
 *   2. Static config  — uses POSTGRES_URI env var + CONNECTOR_API_KEY for auth
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const { Pool } = require('pg');

const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 500 * 1024 * 1024 } });

// ─── Config ──────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 4005;
const CONNECTOR_API_KEY = process.env.CONNECTOR_API_KEY;
const DEFAULT_POSTGRES_URI = process.env.DEFAULT_POSTGRES_URI || process.env.POSTGRES_URI;

// ─── Connection Pool Cache ───────────────────────────────────────────────────
const poolCache = new Map();
let defaultPool = null;

async function resolvePoolFromConfig(config) {
  const uri = config.postgres_uri;
  if (!uri) throw new Error('postgres_uri required in config');

  if (poolCache.has(uri)) return poolCache.get(uri);

  const pool = new Pool({
    connectionString: uri,
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
  });

  // Verify the connection works
  const client = await pool.connect();
  client.release();

  poolCache.set(uri, pool);
  return pool;
}

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '50mb' }));

/**
 * resolvePostgres — replaces simple authenticate middleware.
 * 
 * 1. Try to parse X-Wolfronix-API-Key as JSON → extract postgres_uri → create/cache pool
 * 2. Fallback: validate as static API key → use default pool
 * 3. Attach req.pool
 */
async function resolvePostgres(req, res, next) {
  const apiKey = req.headers['x-wolfronix-api-key'];

  // Mode 1: Dynamic config from engine
  if (apiKey && apiKey.startsWith('{')) {
    try {
      const config = JSON.parse(apiKey);
      req.pool = await resolvePoolFromConfig(config);
      return next();
    } catch (e) {
      if (e instanceof SyntaxError) {
        // Not JSON — fall through to static auth
      } else {
        console.error('PostgreSQL dynamic connection error:', e.message);
        return res.status(500).json({ error: 'Failed to connect to PostgreSQL: ' + e.message });
      }
    }
  }

  // Mode 2: Static API key auth → use default pool
  if (CONNECTOR_API_KEY && apiKey !== CONNECTOR_API_KEY) {
    return res.status(401).json({ error: 'Invalid API key' });
  }

  if (!defaultPool) {
    return res.status(503).json({ error: 'No default PostgreSQL connection configured' });
  }

  req.pool = defaultPool;
  next();
}

app.use('/wolfronix', resolvePostgres);

// ─── Health ──────────────────────────────────────────────────────────────────
app.get('/health', async (req, res) => {
  try {
    if (defaultPool) {
      await defaultPool.query('SELECT 1');
      res.json({ status: 'healthy', database: 'connected', dynamic_pools: poolCache.size, connector: 'postgresql' });
    } else {
      res.json({ status: poolCache.size > 0 ? 'healthy' : 'waiting', database: 'not_configured', dynamic_pools: poolCache.size, connector: 'postgresql' });
    }
  } catch (e) {
    res.status(500).json({ status: 'unhealthy', error: e.message, connector: 'postgresql' });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// FILE ENDPOINTS
// ═════════════════════════════════════════════════════════════════════════════

// POST /wolfronix/files
app.post('/wolfronix/files', async (req, res) => {
  try {
    const { filename, file_size, key_part_a, key_part_b, iv, enc_time_ms, client_id, user_id, storage_type } = req.body;
    const result = await req.pool.query(
      `INSERT INTO wolfronix_files (filename, file_size, key_part_a, key_part_b, iv, enc_time_ms, client_id, user_id, storage_type)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
      [filename, file_size || 0, key_part_a, key_part_b, iv, enc_time_ms || 0, client_id, user_id, storage_type || 'blob']
    );
    res.status(201).json({ id: result.rows[0].id });
  } catch (e) {
    console.error('POST /wolfronix/files error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// POST /wolfronix/files/upload — multipart
app.post('/wolfronix/files/upload', upload.single('encrypted_data'), async (req, res) => {
  const client = await req.pool.connect();
  try {
    const metadata = JSON.parse(req.body.metadata);
    const encryptedData = req.file?.buffer;
    if (!encryptedData) return res.status(400).json({ error: 'Missing encrypted_data file' });

    await client.query('BEGIN');

    const fileResult = await client.query(
      `INSERT INTO wolfronix_files (filename, file_size, key_part_a, key_part_b, iv, enc_time_ms, client_id, user_id, storage_type)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
      [metadata.filename, metadata.file_size || 0, metadata.key_part_a, metadata.key_part_b,
       metadata.iv, metadata.enc_time_ms || 0, metadata.client_id, metadata.user_id, metadata.storage_type || 'blob']
    );

    const fileId = fileResult.rows[0].id;

    await client.query(
      'INSERT INTO wolfronix_file_data (file_id, encrypted_data) VALUES ($1, $2)',
      [fileId, encryptedData]
    );

    await client.query('COMMIT');
    res.status(201).json({ id: fileId });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('POST /wolfronix/files/upload error:', e.message);
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

// GET /wolfronix/files/:id
app.get('/wolfronix/files/:id', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const clientId = req.headers['x-client-id'];

    const result = await req.pool.query('SELECT * FROM wolfronix_files WHERE id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'File not found' });

    const file = result.rows[0];
    if (file.user_id !== userId || file.client_id !== clientId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    res.json(file);
  } catch (e) {
    console.error('GET /wolfronix/files/:id error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /wolfronix/files/:id/data
app.get('/wolfronix/files/:id/data', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const clientId = req.headers['x-client-id'];

    const meta = await req.pool.query('SELECT user_id, client_id FROM wolfronix_files WHERE id = $1', [req.params.id]);
    if (!meta.rows.length) return res.status(404).json({ error: 'File not found' });
    if (meta.rows[0].user_id !== userId || meta.rows[0].client_id !== clientId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const data = await req.pool.query('SELECT encrypted_data FROM wolfronix_file_data WHERE file_id = $1', [req.params.id]);
    if (!data.rows.length) return res.status(404).json({ error: 'File data not found' });

    const buffer = data.rows[0].encrypted_data;
    res.set('Content-Type', 'application/octet-stream');
    res.set('Content-Length', buffer.length);
    res.send(buffer);
  } catch (e) {
    console.error('GET /wolfronix/files/:id/data error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /wolfronix/files?user_id=X
app.get('/wolfronix/files', async (req, res) => {
  try {
    const userId = req.query.user_id || req.headers['x-user-id'];
    const clientId = req.headers['x-client-id'];
    if (!userId) return res.status(400).json({ error: 'user_id is required' });

    const result = await req.pool.query(
      'SELECT * FROM wolfronix_files WHERE client_id = $1 AND user_id = $2 ORDER BY created_at DESC',
      [clientId, userId]
    );

    res.json(result.rows);
  } catch (e) {
    console.error('GET /wolfronix/files error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// DELETE /wolfronix/files/:id
app.delete('/wolfronix/files/:id', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const clientId = req.headers['x-client-id'];

    const meta = await req.pool.query('SELECT user_id, client_id FROM wolfronix_files WHERE id = $1', [req.params.id]);
    if (!meta.rows.length) return res.status(404).json({ error: 'File not found' });
    if (meta.rows[0].user_id !== userId || meta.rows[0].client_id !== clientId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // CASCADE handles file_data deletion
    await req.pool.query('DELETE FROM wolfronix_files WHERE id = $1', [req.params.id]);
    res.status(204).send();
  } catch (e) {
    console.error('DELETE /wolfronix/files/:id error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// KEY ENDPOINTS
// ═════════════════════════════════════════════════════════════════════════════

// POST /wolfronix/keys
app.post('/wolfronix/keys', async (req, res) => {
  try {
    const { user_id, client_id, public_key_pem, encrypted_private_key, salt } = req.body;
    await req.pool.query(
      `INSERT INTO wolfronix_keys (user_id, client_id, public_key_pem, encrypted_private_key, salt)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (user_id, client_id)
       DO UPDATE SET public_key_pem = EXCLUDED.public_key_pem,
         encrypted_private_key = EXCLUDED.encrypted_private_key, salt = EXCLUDED.salt`,
      [user_id, client_id, public_key_pem, encrypted_private_key, salt]
    );
    res.status(201).json({ success: true });
  } catch (e) {
    console.error('POST /wolfronix/keys error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /wolfronix/keys/:userId
app.get('/wolfronix/keys/:userId', async (req, res) => {
  try {
    const clientId = req.headers['x-client-id'];
    const result = await req.pool.query(
      'SELECT * FROM wolfronix_keys WHERE user_id = $1 AND client_id = $2',
      [req.params.userId, clientId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'User key not found' });
    res.json(result.rows[0]);
  } catch (e) {
    console.error('GET /wolfronix/keys/:userId error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /wolfronix/keys/:userId/public
app.get('/wolfronix/keys/:userId/public', async (req, res) => {
  try {
    const clientId = req.headers['x-client-id'];
    const result = await req.pool.query(
      'SELECT public_key_pem FROM wolfronix_keys WHERE user_id = $1 AND client_id = $2',
      [req.params.userId, clientId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });
    res.json({ public_key_pem: result.rows[0].public_key_pem });
  } catch (e) {
    console.error('GET /wolfronix/keys/:userId/public error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// DEV/FAKE DATA ENDPOINT
// ═════════════════════════════════════════════════════════════════════════════

// POST /wolfronix/dev/files
app.post('/wolfronix/dev/files', async (req, res) => {
  try {
    const { prod_file_id, filename, fake_data } = req.body;
    const result = await req.pool.query(
      'INSERT INTO wolfronix_dev_files (prod_file_id, filename, fake_data) VALUES ($1, $2, $3) RETURNING id',
      [prod_file_id, filename, Buffer.from(fake_data)]
    );
    res.status(201).json({ id: result.rows[0].id });
  } catch (e) {
    console.error('POST /wolfronix/dev/files error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ─── Start ───────────────────────────────────────────────────────────────────
async function start() {
  if (DEFAULT_POSTGRES_URI) {
    try {
      defaultPool = new Pool({
        connectionString: DEFAULT_POSTGRES_URI,
        max: 20,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 5000,
      });
      await defaultPool.query('SELECT 1');
      console.log('✅ Connected to default PostgreSQL');
    } catch (err) {
      console.warn('⚠️  Default PostgreSQL connection failed:', err.message);
      console.warn('   Running in dynamic-config-only mode');
      defaultPool = null;
    }
  } else {
    console.log('ℹ️  No DEFAULT_POSTGRES_URI set — running in dynamic-config-only mode');
  }

  app.listen(PORT, () => {
    console.log(`🔌 Wolfronix PostgreSQL Connector running on port ${PORT}`);
    console.log(`   Mode: ${defaultPool ? 'static + dynamic' : 'dynamic-only'}`);
    console.log(`   Health check: http://localhost:${PORT}/health`);
  });
}

start().catch(err => {
  console.error('❌ PostgreSQL connector startup failed:', err.message);
  process.exit(1);
});
