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
const PORT = process.env.PORT || 4001;
const CONNECTOR_API_KEY = process.env.CONNECTOR_API_KEY;

// Default Supabase connection (used when no per-request config is provided)
const DEFAULT_SUPABASE_URL = process.env.SUPABASE_URL;
const DEFAULT_SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;

let defaultSupabase = null;
if (DEFAULT_SUPABASE_URL && DEFAULT_SUPABASE_KEY) {
  defaultSupabase = createClient(DEFAULT_SUPABASE_URL, DEFAULT_SUPABASE_KEY);
}

// Client cache: avoid recreating Supabase clients on every request
const clientCache = new Map();
function getSupabaseClient(url, serviceKey) {
  const cacheKey = `${url}::${serviceKey.slice(0, 8)}`;
  if (clientCache.has(cacheKey)) return clientCache.get(cacheKey);
  const client = createClient(url, serviceKey);
  clientCache.set(cacheKey, client);
  return client;
}

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Resolve Supabase client per-request: dynamic config from X-Wolfronix-API-Key
// or fallback to default env config
function resolveSupabase(req, res, next) {
  const apiKeyHeader = req.headers['x-wolfronix-api-key'] || '';

  // Try parsing as JSON (dynamic per-client config from engine)
  if (apiKeyHeader.startsWith('{')) {
    try {
      const dbConfig = JSON.parse(apiKeyHeader);
      if (dbConfig.supabase_url && dbConfig.supabase_service_key) {
        req.supabase = getSupabaseClient(dbConfig.supabase_url, dbConfig.supabase_service_key);
        return next();
      }
    } catch (e) { /* not JSON, treat as static key */ }
  }

  // Static API key auth
  if (CONNECTOR_API_KEY && apiKeyHeader !== CONNECTOR_API_KEY) {
    return res.status(401).json({ error: 'Invalid API key' });
  }

  // Use default Supabase connection
  if (!defaultSupabase) {
    return res.status(503).json({ error: 'No Supabase configuration available' });
  }
  req.supabase = defaultSupabase;
  next();
}
app.use('/wolfronix', resolveSupabase);

// ─── Health ──────────────────────────────────────────────────────────────────
app.get('/health', async (req, res) => {
  try {
    const sb = defaultSupabase;
    if (!sb) return res.json({ status: 'healthy', database: 'dynamic-only', connector: 'supabase' });
    const { error } = await sb.from('wolfronix_files').select('id').limit(1);
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
    const supabase = req.supabase;
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
    const supabase = req.supabase;
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

    // Insert encrypted data (hex format for PostgreSQL BYTEA compatibility)
    const { error: dataErr } = await supabase
      .from('wolfronix_file_data')
      .insert({
        file_id: fileRow.id,
        encrypted_data: '\\x' + encryptedData.toString('hex')
      });

    if (dataErr) {
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
    const supabase = req.supabase;
    const userId = req.headers['x-user-id'];
    const clientId = req.headers['x-client-id'];

    const { data, error } = await supabase
      .from('wolfronix_files')
      .select('*')
      .eq('id', req.params.id)
      .single();

    if (error || !data) return res.status(404).json({ error: 'File not found' });

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
    const supabase = req.supabase;
    const userId = req.headers['x-user-id'];
    const clientId = req.headers['x-client-id'];

    const { data: fileMeta, error: metaErr } = await supabase
      .from('wolfronix_files')
      .select('user_id, client_id')
      .eq('id', req.params.id)
      .single();

    if (metaErr || !fileMeta) return res.status(404).json({ error: 'File not found' });
    if (fileMeta.user_id !== userId || fileMeta.client_id !== clientId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const { data, error } = await supabase
      .from('wolfronix_file_data')
      .select('encrypted_data')
      .eq('file_id', req.params.id)
      .single();

    if (error || !data) return res.status(404).json({ error: 'File data not found' });

    // Decode BYTEA: Supabase/PostgREST returns hex format (\x...) or base64
    let buffer;
    const raw = data.encrypted_data;
    if (typeof raw === 'string' && raw.startsWith('\\x')) {
      buffer = Buffer.from(raw.slice(2), 'hex');
    } else if (typeof raw === 'string') {
      buffer = Buffer.from(raw, 'base64');
    } else {
      buffer = Buffer.from(raw);
    }
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
    const supabase = req.supabase;
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
    const supabase = req.supabase;
    const userId = req.headers['x-user-id'];
    const clientId = req.headers['x-client-id'];

    const { data: fileMeta, error: metaErr } = await supabase
      .from('wolfronix_files')
      .select('user_id, client_id')
      .eq('id', req.params.id)
      .single();

    if (metaErr || !fileMeta) return res.status(404).json({ error: 'File not found' });
    if (fileMeta.user_id !== userId || fileMeta.client_id !== clientId) {
      return res.status(403).json({ error: 'Access denied' });
    }

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
    const supabase = req.supabase;
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
    const supabase = req.supabase;
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
    const supabase = req.supabase;
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
    const supabase = req.supabase;
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
  console.log(`   Mode: ${defaultSupabase ? 'Default + Dynamic' : 'Dynamic-only (per-request config)'}`);
  console.log(`   Health check: http://localhost:${PORT}/health`);
});
