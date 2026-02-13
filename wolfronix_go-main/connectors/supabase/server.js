/**
 * Wolfronix Supabase Connector
 * 
 * Bridges Wolfronix Engine ↔ Supabase PostgreSQL
 * Implements all required endpoints for file storage, key management, and dev data.
 * 
 * Setup:
 *   1. Run schema.sql in Supabase SQL Editor
 *   2. Copy .env.example → .env and fill in values
 *   3. npm install && npm start
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 500 * 1024 * 1024 } });

// ─── Config ──────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 8080;
const CONNECTOR_API_KEY = process.env.CONNECTOR_API_KEY;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('❌ SUPABASE_URL and SUPABASE_SERVICE_KEY are required');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Auth middleware — verify X-Wolfronix-API-Key
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
    const { error } = await supabase.from('wolfronix_files').select('id').limit(1);
    res.json({ status: 'healthy', database: error ? 'error' : 'connected', connector: 'supabase' });
  } catch (e) {
    res.status(500).json({ status: 'unhealthy', error: e.message });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// FILE ENDPOINTS
// ═════════════════════════════════════════════════════════════════════════════

// POST /wolfronix/files — Store file metadata
app.post('/wolfronix/files', async (req, res) => {
  try {
    const { filename, file_size, key_part_a, key_part_b, iv, enc_time_ms, client_id, user_id, storage_type } = req.body;

    const { data, error } = await supabase
      .from('wolfronix_files')
      .insert({
        filename, file_size, key_part_a, key_part_b, iv,
        enc_time_ms, client_id, user_id, storage_type: storage_type || 'blob'
      })
      .select('id')
      .single();

    if (error) throw error;
    res.status(201).json({ id: data.id });
  } catch (e) {
    console.error('POST /wolfronix/files error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// POST /wolfronix/files/upload — Store metadata + encrypted file data (multipart)
app.post('/wolfronix/files/upload', upload.single('encrypted_data'), async (req, res) => {
  try {
    const metadata = JSON.parse(req.body.metadata);
    const encryptedData = req.file?.buffer;

    if (!encryptedData) {
      return res.status(400).json({ error: 'Missing encrypted_data file' });
    }

    // Insert metadata
    const { data: fileRow, error: fileErr } = await supabase
      .from('wolfronix_files')
      .insert({
        filename: metadata.filename,
        file_size: metadata.file_size,
        key_part_a: metadata.key_part_a,
        key_part_b: metadata.key_part_b,
        iv: metadata.iv,
        enc_time_ms: metadata.enc_time_ms,
        client_id: metadata.client_id,
        user_id: metadata.user_id,
        storage_type: metadata.storage_type || 'blob'
      })
      .select('id')
      .single();

    if (fileErr) throw fileErr;

    // Insert encrypted data
    // Supabase doesn't support raw bytea via REST easily, so we base64 encode
    const { error: dataErr } = await supabase
      .from('wolfronix_file_data')
      .insert({
        file_id: fileRow.id,
        encrypted_data: encryptedData.toString('base64')
      });

    if (dataErr) {
      // Rollback metadata
      await supabase.from('wolfronix_files').delete().eq('id', fileRow.id);
      throw dataErr;
    }

    res.status(201).json({ id: fileRow.id });
  } catch (e) {
    console.error('POST /wolfronix/files/upload error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /wolfronix/files/:id — Get file metadata
app.get('/wolfronix/files/:id', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const clientId = req.headers['x-client-id'];

    const { data, error } = await supabase
      .from('wolfronix_files')
      .select('*')
      .eq('id', req.params.id)
      .single();

    if (error || !data) return res.status(404).json({ error: 'File not found' });

    // Verify ownership
    if (data.user_id !== userId || data.client_id !== clientId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    res.json(data);
  } catch (e) {
    console.error('GET /wolfronix/files/:id error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /wolfronix/files/:id/data — Get encrypted file data (raw bytes)
app.get('/wolfronix/files/:id/data', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const clientId = req.headers['x-client-id'];

    // Verify ownership first
    const { data: fileMeta, error: metaErr } = await supabase
      .from('wolfronix_files')
      .select('user_id, client_id')
      .eq('id', req.params.id)
      .single();

    if (metaErr || !fileMeta) return res.status(404).json({ error: 'File not found' });
    if (fileMeta.user_id !== userId || fileMeta.client_id !== clientId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Get encrypted data
    const { data, error } = await supabase
      .from('wolfronix_file_data')
      .select('encrypted_data')
      .eq('file_id', req.params.id)
      .single();

    if (error || !data) return res.status(404).json({ error: 'File data not found' });

    const buffer = Buffer.from(data.encrypted_data, 'base64');
    res.set('Content-Type', 'application/octet-stream');
    res.set('Content-Length', buffer.length);
    res.send(buffer);
  } catch (e) {
    console.error('GET /wolfronix/files/:id/data error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /wolfronix/files?user_id=X — List files for a user
app.get('/wolfronix/files', async (req, res) => {
  try {
    const userId = req.query.user_id || req.headers['x-user-id'];
    const clientId = req.headers['x-client-id'];

    if (!userId) return res.status(400).json({ error: 'user_id is required' });

    const { data, error } = await supabase
      .from('wolfronix_files')
      .select('*')
      .eq('client_id', clientId)
      .eq('user_id', userId)
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json(data || []);
  } catch (e) {
    console.error('GET /wolfronix/files error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// DELETE /wolfronix/files/:id — Delete a file
app.delete('/wolfronix/files/:id', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'];
    const clientId = req.headers['x-client-id'];

    // Verify ownership
    const { data: fileMeta, error: metaErr } = await supabase
      .from('wolfronix_files')
      .select('user_id, client_id')
      .eq('id', req.params.id)
      .single();

    if (metaErr || !fileMeta) return res.status(404).json({ error: 'File not found' });
    if (fileMeta.user_id !== userId || fileMeta.client_id !== clientId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Delete (cascade removes file_data too)
    const { error } = await supabase
      .from('wolfronix_files')
      .delete()
      .eq('id', req.params.id);

    if (error) throw error;
    res.status(204).send();
  } catch (e) {
    console.error('DELETE /wolfronix/files/:id error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// KEY ENDPOINTS
// ═════════════════════════════════════════════════════════════════════════════

// POST /wolfronix/keys — Store user's wrapped key
app.post('/wolfronix/keys', async (req, res) => {
  try {
    const { user_id, client_id, public_key_pem, encrypted_private_key, salt } = req.body;

    const { error } = await supabase
      .from('wolfronix_keys')
      .upsert({
        user_id, client_id, public_key_pem, encrypted_private_key, salt
      }, { onConflict: 'user_id,client_id' });

    if (error) throw error;
    res.status(201).json({ success: true });
  } catch (e) {
    console.error('POST /wolfronix/keys error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /wolfronix/keys/:userId — Get user's wrapped key
app.get('/wolfronix/keys/:userId', async (req, res) => {
  try {
    const clientId = req.headers['x-client-id'];

    const { data, error } = await supabase
      .from('wolfronix_keys')
      .select('*')
      .eq('user_id', req.params.userId)
      .eq('client_id', clientId)
      .single();

    if (error || !data) return res.status(404).json({ error: 'User key not found' });
    res.json(data);
  } catch (e) {
    console.error('GET /wolfronix/keys/:userId error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /wolfronix/keys/:userId/public — Get user's public key only
app.get('/wolfronix/keys/:userId/public', async (req, res) => {
  try {
    const clientId = req.headers['x-client-id'];

    const { data, error } = await supabase
      .from('wolfronix_keys')
      .select('public_key_pem')
      .eq('user_id', req.params.userId)
      .eq('client_id', clientId)
      .single();

    if (error || !data) return res.status(404).json({ error: 'User not found' });
    res.json({ public_key_pem: data.public_key_pem });
  } catch (e) {
    console.error('GET /wolfronix/keys/:userId/public error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// DEV/FAKE DATA ENDPOINT
// ═════════════════════════════════════════════════════════════════════════════

// POST /wolfronix/dev/files — Store fake/masked data for dev environments
app.post('/wolfronix/dev/files', async (req, res) => {
  try {
    const { prod_file_id, filename, fake_data } = req.body;

    const { data, error } = await supabase
      .from('wolfronix_dev_files')
      .insert({
        prod_file_id,
        filename,
        fake_data: Buffer.from(fake_data).toString('base64')
      })
      .select('id')
      .single();

    if (error) throw error;
    res.status(201).json({ id: data.id });
  } catch (e) {
    console.error('POST /wolfronix/dev/files error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ─── Start Server ────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🔌 Wolfronix Supabase Connector running on port ${PORT}`);
  console.log(`   Supabase URL: ${SUPABASE_URL}`);
  console.log(`   Health check: http://localhost:${PORT}/health`);
});
