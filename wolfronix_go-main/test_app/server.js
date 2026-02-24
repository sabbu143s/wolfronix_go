/**
 * Wolfronix Test App — Server with Chat Relay
 * Serves static files + provides a simple in-memory message relay for E2E chat.
 *
 * Usage:  node server.js
 * Then:   http://localhost:3000
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 3000;
const DIR = __dirname;

const MIME = {
    '.html': 'text/html',
    '.css': 'text/css',
    '.js': 'application/javascript',
    '.json': 'application/json',
    '.png': 'image/png',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
};

// ─── In-Memory Message Store ───
// { recipientUserId: [ { from, packet, timestamp }, ... ] }
const messageStore = {};

function parseBody(req) {
    return new Promise((resolve, reject) => {
        let body = '';
        const MAX_SIZE = 10 * 1024 * 1024; // 10MB limit for E2E media
        req.on('data', chunk => {
            body += chunk;
            if (body.length > MAX_SIZE) {
                req.destroy();
                reject(new Error('Body too large'));
            }
        });
        req.on('end', () => {
            try { resolve(JSON.parse(body)); }
            catch (e) { reject(e); }
        });
    });
}

const server = http.createServer(async (req, res) => {
    // CORS headers for cross-origin requests
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    const url = new URL(req.url, `http://localhost:${PORT}`);

    // ─── POST /api/chat/send — Send an encrypted message ───
    if (req.method === 'POST' && url.pathname === '/api/chat/send') {
        try {
            const { to, from, packet, isMedia, mediaInfo } = await parseBody(req);
            if (!to || !from || !packet) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Missing to, from, or packet' }));
                return;
            }
            if (!messageStore[to]) messageStore[to] = [];
            messageStore[to].push({ from, packet, isMedia: !!isMedia, mediaInfo: mediaInfo || null, timestamp: Date.now() });
            const label = isMedia ? '📎 Media' : '💬 Text';
            console.log(`  ${label}: ${from} → ${to} (${packet.length} chars)`);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, delivered: true }));
        } catch (e) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Invalid JSON' }));
        }
        return;
    }

    // ─── GET /api/chat/messages?userId=xxx — Poll for new messages ───
    if (req.method === 'GET' && url.pathname === '/api/chat/messages') {
        const userId = url.searchParams.get('userId');
        if (!userId) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Missing userId param' }));
            return;
        }
        const messages = messageStore[userId] || [];
        // Drain the queue (deliver and remove)
        messageStore[userId] = [];
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ messages }));
        return;
    }

    // ─── Static files ───
    let filePath = path.join(DIR, url.pathname === '/' ? 'index.html' : url.pathname);
    const ext = path.extname(filePath);
    const contentType = MIME[ext] || 'application/octet-stream';

    fs.readFile(filePath, (err, data) => {
        if (err) {
            res.writeHead(404);
            res.end('Not found');
            return;
        }
        res.writeHead(200, { 'Content-Type': contentType });
        res.end(data);
    });
});

server.listen(PORT, () => {
    console.log(`\n  🚀 Wolfronix Secure Vault running at:\n`);
    console.log(`     http://localhost:${PORT}\n`);
    console.log(`  Features:`);
    console.log(`  • Static file server`);
    console.log(`  • Chat relay (POST /api/chat/send, GET /api/chat/messages)`);
    console.log(`\n  Open in two browser tabs to test E2E chat!\n`);
});
