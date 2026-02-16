/**
 * Simple static file server for Wolfronix Test App.
 * Serves index.html on port 3000.
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

const server = http.createServer((req, res) => {
    let filePath = path.join(DIR, req.url === '/' ? 'index.html' : req.url);
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
    console.log(`\n  🚀 Wolfronix Test App running at:\n`);
    console.log(`     http://localhost:${PORT}\n`);
    console.log(`  Steps:`);
    console.log(`  1. Enter your server URL (e.g. https://49.206.202.13:9443)`);
    console.log(`  2. Enter Client ID + Wolfronix Key`);
    console.log(`  3. Click Connect → Register → Encrypt/Decrypt\n`);
});
