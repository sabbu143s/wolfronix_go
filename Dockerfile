# --- Stage 1: Builder ---
FROM golang:1.21-alpine AS builder

# Install C-compiler (Required for SQLite)
RUN apk add --no-cache gcc musl-dev

WORKDIR /app

# Copy dependency files first (Caching layer)
COPY go.mod go.sum ./
RUN go mod download

# Copy Source Code
COPY . .

# Build the Binary (CGO enabled for SQLite)
RUN CGO_ENABLED=1 GOOS=linux go build -o wolfronix-engine cmd/api/main.go

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
