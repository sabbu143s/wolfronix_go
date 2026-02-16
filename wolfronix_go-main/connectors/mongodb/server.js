/**
 * Wolfronix MongoDB Connector
 * 
 * Bridges Wolfronix Engine ↔ MongoDB (local or Atlas)
 * Implements all required endpoints for file storage, key management, and dev data.
 * 
 * Supports two modes:
 *   1. Dynamic config — engine passes JSON db_config via X-Wolfronix-API-Key header
 *   2. Static config  — uses DEFAULT_MONGODB_URI env var + CONNECTOR_API_KEY for auth
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const mongoose = require('mongoose');

const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 500 * 1024 * 1024 } });

// ─── Config ──────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 4002;
const CONNECTOR_API_KEY = process.env.CONNECTOR_API_KEY;
const DEFAULT_MONGODB_URI = process.env.DEFAULT_MONGODB_URI || process.env.MONGODB_URI;

// ─── Mongoose Schemas ────────────────────────────────────────────────────────
const fileSchema = new mongoose.Schema({
  filename:     { type: String, required: true },
  file_size:    { type: Number, default: 0 },
  key_part_a:   { type: String, required: true },
  key_part_b:   { type: String, required: true },
  iv:           { type: String, required: true },
  enc_time_ms:  { type: Number, default: 0 },
  client_id:    { type: String, required: true, index: true },
  user_id:      { type: String, required: true, index: true },
  storage_type: { type: String, default: 'blob' },
  created_at:   { type: Date, default: Date.now }
});
fileSchema.index({ client_id: 1, user_id: 1 });

const fileDataSchema = new mongoose.Schema({
  file_id:        { type: mongoose.Schema.Types.ObjectId, ref: 'WolfronixFile', required: true, unique: true },
  encrypted_data: { type: Buffer, required: true }
});

const keySchema = new mongoose.Schema({
  user_id:               { type: String, required: true },
  client_id:             { type: String, required: true },
  public_key_pem:        { type: String, required: true },
  encrypted_private_key: { type: String, required: true },
  salt:                  { type: String, required: true },
  created_at:            { type: Date, default: Date.now }
});
keySchema.index({ user_id: 1, client_id: 1 }, { unique: true });

const devFileSchema = new mongoose.Schema({
  prod_file_id: { type: Number },
  filename:     { type: String },
  fake_data:    { type: Buffer },
  created_at:   { type: Date, default: Date.now }
});

// ─── Connection Cache ────────────────────────────────────────────────────────
// Maps MongoDB URI → { connection, models }
const connectionCache = new Map();

function getModelsForConnection(conn) {
  return {
    WolfronixFile:     conn.model('WolfronixFile', fileSchema),
    WolfronixFileData: conn.model('WolfronixFileData', fileDataSchema),
    WolfronixKey:      conn.model('WolfronixKey', keySchema),
    WolfronixDevFile:  conn.model('WolfronixDevFile', devFileSchema),
  };
}

async function resolveConnection(uri) {
  if (connectionCache.has(uri)) {
    const cached = connectionCache.get(uri);
    if (cached.connection.readyState === 1) return cached;
    connectionCache.delete(uri);
  }
  const connection = mongoose.createConnection(uri);
  await connection.asPromise();
  const models = getModelsForConnection(connection);
  const entry = { connection, models };
  connectionCache.set(uri, entry);
  return entry;
}

// Default connection models (global mongoose)
let defaultModels = null;

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '50mb' }));

/**
 * resolveMongoDB — replaces simple authenticate middleware.
 * 
 * 1. Try to parse X-Wolfronix-API-Key as JSON → extract mongodb_uri → create/cache connection
 * 2. Fallback: validate as static API key → use default connection
 * 3. Attach req.db = { WolfronixFile, WolfronixFileData, WolfronixKey, WolfronixDevFile }
 */
async function resolveMongoDB(req, res, next) {
  const apiKey = req.headers['x-wolfronix-api-key'];

  // Mode 1: Dynamic config from engine (JSON in header)
  if (apiKey && apiKey.startsWith('{')) {
    try {
      const config = JSON.parse(apiKey);
      const uri = config.mongodb_uri;
      if (!uri) return res.status(400).json({ error: 'mongodb_uri required in config' });

      const { models } = await resolveConnection(uri);
      req.db = models;
      return next();
    } catch (e) {
      if (e instanceof SyntaxError) {
        // Not JSON — fall through to static auth
      } else {
        console.error('MongoDB dynamic connection error:', e.message);
        return res.status(500).json({ error: 'Failed to connect to MongoDB: ' + e.message });
      }
    }
  }

  // Mode 2: Static API key auth → use default connection
  if (CONNECTOR_API_KEY && apiKey !== CONNECTOR_API_KEY) {
    return res.status(401).json({ error: 'Invalid API key' });
  }

  if (!defaultModels) {
    return res.status(503).json({ error: 'No default MongoDB connection configured' });
  }

  req.db = defaultModels;
  next();
}

app.use('/wolfronix', resolveMongoDB);

// ─── Health ──────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  const defaultState = mongoose.connection.readyState;
  const dynamicConnections = connectionCache.size;
  res.json({
    status: defaultState === 1 || dynamicConnections > 0 ? 'healthy' : 'waiting',
    default_db: defaultState === 1 ? 'connected' : (DEFAULT_MONGODB_URI ? 'disconnected' : 'not_configured'),
    dynamic_connections: dynamicConnections,
    connector: 'mongodb'
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// FILE ENDPOINTS
// ═════════════════════════════════════════════════════════════════════════════

// POST /wolfronix/files — Store file metadata
app.post('/wolfronix/files', async (req, res) => {
  try {
    const doc = await req.db.WolfronixFile.create(req.body);
    res.status(201).json({ id: doc._id });
  } catch (e) {
    console.error('POST /wolfronix/files error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// POST /wolfronix/files/upload — Store metadata + encrypted data (multipart)
app.post('/wolfronix/files/upload', upload.single('encrypted_data'), async (req, res) => {
  try {
    const metadata = JSON.parse(req.body.metadata);
    const encryptedData = req.file?.buffer;
    if (!encryptedData) return res.status(400).json({ error: 'Missing encrypted_data file' });

    const doc = await req.db.WolfronixFile.create(metadata);

    try {
      await req.db.WolfronixFileData.create({ file_id: doc._id, encrypted_data: encryptedData });
    } catch (dataErr) {
      await req.db.WolfronixFile.deleteOne({ _id: doc._id });
      throw dataErr;
    }

    res.status(201).json({ id: doc._id });
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

    const doc = await req.db.WolfronixFile.findById(req.params.id).lean();
    if (!doc) return res.status(404).json({ error: 'File not found' });
    if (doc.user_id !== userId || doc.client_id !== clientId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    res.json({ ...doc, id: doc._id });
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

    const fileMeta = await req.db.WolfronixFile.findById(req.params.id).lean();
    if (!fileMeta) return res.status(404).json({ error: 'File not found' });
    if (fileMeta.user_id !== userId || fileMeta.client_id !== clientId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const fileData = await req.db.WolfronixFileData.findOne({ file_id: req.params.id });
    if (!fileData) return res.status(404).json({ error: 'File data not found' });

    res.set('Content-Type', 'application/octet-stream');
    res.set('Content-Length', fileData.encrypted_data.length);
    res.send(fileData.encrypted_data);
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

    const docs = await req.db.WolfronixFile.find({ client_id: clientId, user_id: userId })
      .sort({ created_at: -1 }).lean();

    res.json(docs.map(d => ({ ...d, id: d._id })));
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

    const doc = await req.db.WolfronixFile.findById(req.params.id).lean();
    if (!doc) return res.status(404).json({ error: 'File not found' });
    if (doc.user_id !== userId || doc.client_id !== clientId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    await req.db.WolfronixFileData.deleteOne({ file_id: req.params.id });
    await req.db.WolfronixFile.deleteOne({ _id: req.params.id });
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
    await req.db.WolfronixKey.findOneAndUpdate(
      { user_id, client_id },
      { public_key_pem, encrypted_private_key, salt },
      { upsert: true, new: true }
    );
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
    const doc = await req.db.WolfronixKey.findOne({ user_id: req.params.userId, client_id: clientId }).lean();
    if (!doc) return res.status(404).json({ error: 'User key not found' });
    res.json(doc);
  } catch (e) {
    console.error('GET /wolfronix/keys/:userId error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /wolfronix/keys/:userId/public — Get user's public key only
app.get('/wolfronix/keys/:userId/public', async (req, res) => {
  try {
    const clientId = req.headers['x-client-id'];
    const doc = await req.db.WolfronixKey.findOne({ user_id: req.params.userId, client_id: clientId })
      .select('public_key_pem').lean();
    if (!doc) return res.status(404).json({ error: 'User not found' });
    res.json({ public_key_pem: doc.public_key_pem });
  } catch (e) {
    console.error('GET /wolfronix/keys/:userId/public error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// DEV/FAKE DATA ENDPOINT
// ═════════════════════════════════════════════════════════════════════════════

// POST /wolfronix/dev/files — Store fake/masked data
app.post('/wolfronix/dev/files', async (req, res) => {
  try {
    const { prod_file_id, filename, fake_data } = req.body;
    const doc = await req.db.WolfronixDevFile.create({
      prod_file_id, filename, fake_data: Buffer.from(fake_data)
    });
    res.status(201).json({ id: doc._id });
  } catch (e) {
    console.error('POST /wolfronix/dev/files error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ─── Connect & Start ─────────────────────────────────────────────────────────
async function start() {
  if (DEFAULT_MONGODB_URI) {
    try {
      await mongoose.connect(DEFAULT_MONGODB_URI);
      console.log('✅ Connected to default MongoDB');
      defaultModels = {
        WolfronixFile:     mongoose.model('WolfronixFile', fileSchema),
        WolfronixFileData: mongoose.model('WolfronixFileData', fileDataSchema),
        WolfronixKey:      mongoose.model('WolfronixKey', keySchema),
        WolfronixDevFile:  mongoose.model('WolfronixDevFile', devFileSchema),
      };
    } catch (err) {
      console.warn('⚠️  Default MongoDB connection failed:', err.message);
      console.warn('   Running in dynamic-config-only mode');
    }
  } else {
    console.log('ℹ️  No DEFAULT_MONGODB_URI set — running in dynamic-config-only mode');
  }

  app.listen(PORT, () => {
    console.log(`🔌 Wolfronix MongoDB Connector running on port ${PORT}`);
    console.log(`   Mode: ${defaultModels ? 'static + dynamic' : 'dynamic-only'}`);
    console.log(`   Health check: http://localhost:${PORT}/health`);
  });
}

start().catch(err => {
  console.error('❌ MongoDB connector startup failed:', err.message);
  process.exit(1);
});
