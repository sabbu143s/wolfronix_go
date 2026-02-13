# --- Stage 1: Builder ---
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy dependency files first (Caching layer)
COPY go.mod go.sum ./
RUN go mod download

# Copy Source Code
COPY . .

# Build the Binary (CGO disabled - pure Go, no SQLite dependency)
# Uses ./cmd/api/ to include all Go files (main.go + messaging.go)
RUN CGO_ENABLED=0 GOOS=linux go build -o wolfronix-engine ./cmd/api/

# --- Stage 2: Runtime ---
FROM alpine:latest

WORKDIR /root/

# Install OpenSSL (To auto-generate certs on startup)
RUN apk add --no-cache openssl ca-certificates

# Copy Binary from Stage 1
COPY --from=builder /app/wolfronix-engine .

# Create a folder for persistent data
RUN mkdir -p /root/data

# Expose the HTTPS Port
EXPOSE 5001

# Copy the startup script (We will create this next)
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

# Run the startup script
CMD ["./entrypoint.sh"]
