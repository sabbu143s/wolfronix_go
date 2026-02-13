/**
 * Wolfronix MySQL Connector
 * 
 * Bridges Wolfronix Engine ↔ MySQL / MariaDB
 * Implements all required endpoints for file storage, key management, and dev data.
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const mysql = require('mysql2/promise');

const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 500 * 1024 * 1024 } });

// ─── Config ──────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 8080;
const CONNECTOR_API_KEY = process.env.CONNECTOR_API_KEY;

let pool;

async function initDB() {
  pool = mysql.createPool({
    host: process.env.MYSQL_HOST || 'localhost',
    port: parseInt(process.env.MYSQL_PORT || '3306'),
    user: process.env.MYSQL_USER || 'wolfronix',
    password: process.env.MYSQL_PASSWORD,
    database: process.env.MYSQL_DATABASE || 'wolfronix',
    waitForConnections: true,
    connectionLimit: 20,
    queueLimit: 0,
    charset: 'utf8mb4'
  });

  // Verify connection
  const conn = await pool.getConnection();
  conn.release();
  console.log('✅ Connected to MySQL');
}

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
    res.json({ status: 'healthy', database: 'connected', connector: 'mysql' });
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
    const [result] = await pool.execute(
      `INSERT INTO wolfronix_files (filename, file_size, key_part_a, key_part_b, iv, enc_time_ms, client_id, user_id, storage_type)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [filename, file_size || 0, key_part_a, key_part_b, iv, enc_time_ms || 0, client_id, user_id, storage_type || 'blob']
    );
    res.status(201).json({ id: result.insertId });
  } catch (e) {
    console.error('POST /wolfronix/files error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// POST /wolfronix/files/upload — multipart
app.post('/wolfronix/files/upload', upload.single('encrypted_data'), async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const metadata = JSON.parse(req.body.metadata);
    const encryptedData = req.file?.buffer;
    if (!encryptedData) return res.status(400).json({ error: 'Missing encrypted_data file' });

    await conn.beginTransaction();

    const [fileResult] = await conn.execute(
      `INSERT INTO wolfronix_files (filename, file_size, key_part_a, key_part_b, iv, enc_time_ms, client_id, user_id, storage_type)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [metadata.filename, metadata.file_size || 0, metadata.key_part_a, metadata.key_part_b,
       metadata.iv, metadata.enc_time_ms || 0, metadata.client_id, metadata.user_id, metadata.storage_type || 'blob']
    );

    await conn.execute(
      'INSERT INTO wolfronix_file_data (file_id, encrypted_data) VALUES (?, ?)',
      [fileResult.insertId, encryptedData]
    );

    await conn.commit();
    res.status(201).json({ id: fileResult.insertId });
  } catch (e) {
    await conn.rollback();
    console.error('POST /wolfronix/files/upload error:', e.message);
    res.status(500).json({ error: e.message });
  } finally {
    conn.release();
  }
});

// GET /wolfronix/files/:id
app.get('/wolfronix/files/:id', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const clientId = req.headers['x-client-id'];

    const [rows] = await pool.execute('SELECT * FROM wolfronix_files WHERE id = ?', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'File not found' });

    const file = rows[0];
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

    const [meta] = await pool.execute('SELECT user_id, client_id FROM wolfronix_files WHERE id = ?', [req.params.id]);
    if (!meta.length) return res.status(404).json({ error: 'File not found' });
    if (meta[0].user_id !== userId || meta[0].client_id !== clientId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const [data] = await pool.execute('SELECT encrypted_data FROM wolfronix_file_data WHERE file_id = ?', [req.params.id]);
    if (!data.length) return res.status(404).json({ error: 'File data not found' });

    res.set('Content-Type', 'application/octet-stream');
    res.set('Content-Length', data[0].encrypted_data.length);
    res.send(data[0].encrypted_data);
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

    const [rows] = await pool.execute(
      'SELECT * FROM wolfronix_files WHERE client_id = ? AND user_id = ? ORDER BY created_at DESC',
      [clientId, userId]
    );

    res.json(rows);
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

    const [meta] = await pool.execute('SELECT user_id, client_id FROM wolfronix_files WHERE id = ?', [req.params.id]);
    if (!meta.length) return res.status(404).json({ error: 'File not found' });
    if (meta[0].user_id !== userId || meta[0].client_id !== clientId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // CASCADE handles file_data deletion
    await pool.execute('DELETE FROM wolfronix_files WHERE id = ?', [req.params.id]);
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
    await pool.execute(
      `INSERT INTO wolfronix_keys (user_id, client_id, public_key_pem, encrypted_private_key, salt)
       VALUES (?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE public_key_pem = VALUES(public_key_pem),
         encrypted_private_key = VALUES(encrypted_private_key), salt = VALUES(salt)`,
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
    const [rows] = await pool.execute(
      'SELECT * FROM wolfronix_keys WHERE user_id = ? AND client_id = ?',
      [req.params.userId, clientId]
    );
    if (!rows.length) return res.status(404).json({ error: 'User key not found' });
    res.json(rows[0]);
  } catch (e) {
    console.error('GET /wolfronix/keys/:userId error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /wolfronix/keys/:userId/public
app.get('/wolfronix/keys/:userId/public', async (req, res) => {
  try {
    const clientId = req.headers['x-client-id'];
    const [rows] = await pool.execute(
      'SELECT public_key_pem FROM wolfronix_keys WHERE user_id = ? AND client_id = ?',
      [req.params.userId, clientId]
    );
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    res.json({ public_key_pem: rows[0].public_key_pem });
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
    const [result] = await pool.execute(
      'INSERT INTO wolfronix_dev_files (prod_file_id, filename, fake_data) VALUES (?, ?, ?)',
      [prod_file_id, filename, Buffer.from(fake_data)]
    );
    res.status(201).json({ id: result.insertId });
  } catch (e) {
    console.error('POST /wolfronix/dev/files error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ─── Start ───────────────────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🔌 Wolfronix MySQL Connector running on port ${PORT}`);
    console.log(`   Health check: http://localhost:${PORT}/health`);
  });
}).catch(err => {
  console.error('❌ MySQL connection failed:', err.message);
  process.exit(1);
});
