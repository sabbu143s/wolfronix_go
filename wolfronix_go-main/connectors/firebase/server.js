/**
 * Wolfronix Firebase Connector
 * 
 * Bridges Wolfronix Engine ↔ Firebase (Firestore + Cloud Storage)
 * Implements all required endpoints for file storage, key management, and dev data.
 * 
 * Metadata → Firestore collections
 * Encrypted file data → Cloud Storage bucket
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const admin = require('firebase-admin');
const path = require('path');

const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 500 * 1024 * 1024 } });

// ─── Config ──────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 8080;
const CONNECTOR_API_KEY = process.env.CONNECTOR_API_KEY;
const SERVICE_ACCOUNT_PATH = process.env.FIREBASE_SERVICE_ACCOUNT || './serviceAccountKey.json';
const STORAGE_BUCKET = process.env.FIREBASE_STORAGE_BUCKET;

// Initialize Firebase Admin
const serviceAccount = require(path.resolve(SERVICE_ACCOUNT_PATH));
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  storageBucket: STORAGE_BUCKET
});

const db = admin.firestore();
const bucket = admin.storage().bucket();

// Firestore collections
const FILES_COL = 'wolfronix_files';
const KEYS_COL = 'wolfronix_keys';
const DEV_FILES_COL = 'wolfronix_dev_files';

// Auto-increment counter (Firestore doesn't have auto-increment)
async function getNextId(counterName) {
  const ref = db.collection('wolfronix_counters').doc(counterName);
  const result = await db.runTransaction(async (t) => {
    const doc = await t.get(ref);
    const next = (doc.exists ? doc.data().value : 0) + 1;
    t.set(ref, { value: next });
    return next;
  });
  return result;
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
    await db.collection(FILES_COL).limit(1).get();
    res.json({ status: 'healthy', database: 'connected', connector: 'firebase' });
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
    const id = await getNextId('files');
    const { filename, file_size, key_part_a, key_part_b, iv, enc_time_ms, client_id, user_id, storage_type } = req.body;

    await db.collection(FILES_COL).doc(String(id)).set({
      id, filename, file_size: file_size || 0, key_part_a, key_part_b, iv,
      enc_time_ms: enc_time_ms || 0, client_id, user_id,
      storage_type: storage_type || 'blob',
      created_at: admin.firestore.FieldValue.serverTimestamp()
    });

    res.status(201).json({ id });
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

    const id = await getNextId('files');

    // Store metadata in Firestore
    await db.collection(FILES_COL).doc(String(id)).set({
      id, filename: metadata.filename, file_size: metadata.file_size || 0,
      key_part_a: metadata.key_part_a, key_part_b: metadata.key_part_b,
      iv: metadata.iv, enc_time_ms: metadata.enc_time_ms || 0,
      client_id: metadata.client_id, user_id: metadata.user_id,
      storage_type: metadata.storage_type || 'blob',
      created_at: admin.firestore.FieldValue.serverTimestamp()
    });

    // Store encrypted data in Cloud Storage
    const file = bucket.file(`wolfronix/encrypted/${id}.enc`);
    await file.save(encryptedData, { contentType: 'application/octet-stream' });

    res.status(201).json({ id });
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

    const doc = await db.collection(FILES_COL).doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'File not found' });

    const data = doc.data();
    if (data.user_id !== userId || data.client_id !== clientId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Normalize timestamp for JSON
    const result = { ...data };
    if (result.created_at && result.created_at.toDate) {
      result.created_at = result.created_at.toDate().toISOString();
    }
    res.json(result);
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

    // Verify ownership
    const doc = await db.collection(FILES_COL).doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'File not found' });

    const meta = doc.data();
    if (meta.user_id !== userId || meta.client_id !== clientId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Download from Cloud Storage
    const file = bucket.file(`wolfronix/encrypted/${req.params.id}.enc`);
    const [exists] = await file.exists();
    if (!exists) return res.status(404).json({ error: 'File data not found' });

    const [buffer] = await file.download();
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

    const snapshot = await db.collection(FILES_COL)
      .where('client_id', '==', clientId)
      .where('user_id', '==', userId)
      .orderBy('created_at', 'desc')
      .get();

    const files = snapshot.docs.map(d => {
      const data = d.data();
      if (data.created_at && data.created_at.toDate) {
        data.created_at = data.created_at.toDate().toISOString();
      }
      return data;
    });

    res.json(files);
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

    const doc = await db.collection(FILES_COL).doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ error: 'File not found' });

    const data = doc.data();
    if (data.user_id !== userId || data.client_id !== clientId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Delete encrypted data from Storage
    try {
      await bucket.file(`wolfronix/encrypted/${req.params.id}.enc`).delete();
    } catch (storageErr) {
      // File may not exist in storage (metadata-only)
    }

    // Delete metadata from Firestore
    await db.collection(FILES_COL).doc(req.params.id).delete();
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
    const docId = `${user_id}_${client_id}`;

    await db.collection(KEYS_COL).doc(docId).set({
      user_id, client_id, public_key_pem, encrypted_private_key, salt,
      created_at: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

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
    const docId = `${req.params.userId}_${clientId}`;

    const doc = await db.collection(KEYS_COL).doc(docId).get();
    if (!doc.exists) return res.status(404).json({ error: 'User key not found' });
    res.json(doc.data());
  } catch (e) {
    console.error('GET /wolfronix/keys/:userId error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /wolfronix/keys/:userId/public — Get user's public key only
app.get('/wolfronix/keys/:userId/public', async (req, res) => {
  try {
    const clientId = req.headers['x-client-id'];
    const docId = `${req.params.userId}_${clientId}`;

    const doc = await db.collection(KEYS_COL).doc(docId).get();
    if (!doc.exists) return res.status(404).json({ error: 'User not found' });
    res.json({ public_key_pem: doc.data().public_key_pem });
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
    const id = await getNextId('dev_files');

    await db.collection(DEV_FILES_COL).doc(String(id)).set({
      id, prod_file_id, filename,
      fake_data: Buffer.from(fake_data).toString('base64'),
      created_at: admin.firestore.FieldValue.serverTimestamp()
    });

    res.status(201).json({ id });
  } catch (e) {
    console.error('POST /wolfronix/dev/files error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ─── Start Server ────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🔌 Wolfronix Firebase Connector running on port ${PORT}`);
  console.log(`   Storage Bucket: ${STORAGE_BUCKET}`);
  console.log(`   Health check: http://localhost:${PORT}/health`);
});
