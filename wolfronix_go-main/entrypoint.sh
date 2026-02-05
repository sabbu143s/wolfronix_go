#!/bin/sh

echo "⚡ Wolfronix Container Starting..."

# 1. Check for SSL Certificates
if [ ! -f "server.crt" ] || [ ! -f "server.key" ]; then
    echo "🔒 No SSL Certs found. Generating Self-Signed Certs..."
    openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 3650 -nodes -subj "/C=US/ST=Secure/L=Wolfronix/O=Security/CN=localhost"
    echo "✅ Certs Generated!"
else
    echo "✅ SSL Certs found."
fi

# 2. Run the Engine
./wolfronix-engine
