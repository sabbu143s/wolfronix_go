/**
 * Wolfronix PostgreSQL Connector
 * 
 * Bridges Wolfronix Engine ↔ PostgreSQL (self-hosted, RDS, Neon, etc.)
 * Implements all required endpoints for file storage, key management, and dev data.
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const { Pool } = require('pg');

const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 500 * 1024 * 1024 } });

// ─── Config ──────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 8080;
const CONNECTOR_API_KEY = process.env.CONNECTOR_API_KEY;

const pool = new Pool({
  connectionString: process.env.POSTGRES_URI,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '50mb' }));

function authenticate(req, res, next) {
  if (CONNECTOR_API_KEY && req.headers['x-wolfronix-api-key'] !== CONNECTOR_API_KEY) {
    return res.status(401).json({ error: 'Invalid API key' });
  }
  next();
}
app.use('/wolfronix', authenticate);

// ─── Health ──────────────────────────────────────────────────────────────────
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'healthy', database: 'connected', connector: 'postgresql' });
  } catch (e) {
    res.status(500).json({ status: 'unhealthy', error: e.message });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// FILE ENDPOINTS
// ═════════════════════════════════════════════════════════════════════════════

// POST /wolfronix/files
app.post('/wolfronix/files', async (req, res) => {
  try {
    const { filename, file_size, key_part_a, key_part_b, iv, enc_time_ms, client_id, user_id, storage_type } = req.body;
    const result = await pool.query(
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
  const client = await pool.connect();
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

    const result = await pool.query('SELECT * FROM wolfronix_files WHERE id = $1', [req.params.id]);
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

    const meta = await pool.query('SELECT user_id, client_id FROM wolfronix_files WHERE id = $1', [req.params.id]);
    if (!meta.rows.length) return res.status(404).json({ error: 'File not found' });
    if (meta.rows[0].user_id !== userId || meta.rows[0].client_id !== clientId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const data = await pool.query('SELECT encrypted_data FROM wolfronix_file_data WHERE file_id = $1', [req.params.id]);
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

    const result = await pool.query(
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

    const meta = await pool.query('SELECT user_id, client_id FROM wolfronix_files WHERE id = $1', [req.params.id]);
    if (!meta.rows.length) return res.status(404).json({ error: 'File not found' });
    if (meta.rows[0].user_id !== userId || meta.rows[0].client_id !== clientId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // CASCADE handles file_data deletion
    await pool.query('DELETE FROM wolfronix_files WHERE id = $1', [req.params.id]);
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
    await pool.query(
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
    const result = await pool.query(
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
    const result = await pool.query(
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
    const result = await pool.query(
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
pool.query('SELECT 1').then(() => {
  console.log('✅ Connected to PostgreSQL');
  app.listen(PORT, () => {
    console.log(`🔌 Wolfronix PostgreSQL Connector running on port ${PORT}`);
    console.log(`   Health check: http://localhost:${PORT}/health`);
  });
}).catch(err => {
  console.error('❌ PostgreSQL connection failed:', err.message);
  process.exit(1);
});
