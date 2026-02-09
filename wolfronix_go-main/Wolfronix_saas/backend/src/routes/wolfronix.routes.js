/**
 * Wolfronix API Routes
 * Routes for API key management
 */

import express from 'express';
import auth from '../middleware/auth.middleware.js';
import { 
    getApiKey, 
    generateApiKey, 
    revokeApiKey,
    getUsage 
} from '../controllers/wolfronix.controller.js';

const router = express.Router();

// All routes require authentication
router.use(auth);

// GET /api/wolfronix/key - Get current API key (masked)
// Query params: reveal=true to get full key
router.get('/key', getApiKey);

// POST /api/wolfronix/key - Generate or regenerate API key
router.post('/key', generateApiKey);

// DELETE /api/wolfronix/key - Revoke API key
router.delete('/key', revokeApiKey);

// GET /api/wolfronix/usage - Get usage statistics
router.get('/usage', getUsage);

export default router;
