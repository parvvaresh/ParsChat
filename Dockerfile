# Stage 1: Build
FROM golang:1.21 AS builder
WORKDIR /app

RUN apt-get update && apt-get install -y gcc sqlite3 libsqlite3-dev

# Copy go.mod and go.sum for dependency caching
COPY go.mod go.sum ./
RUN go mod download

# Copy all source files
COPY . .

# Build server binary
RUN CGO_ENABLED=1 go build -o chat-server ./cmd/server

# Stage 2: Runtime
FROM debian:bullseye-slim
WORKDIR /app

RUN apt-get update && apt-get install -y ca-certificates sqlite3 && rm -rf /var/lib/apt/lists/*

# Copy binaries from builder
COPY --from=builder /app/chat-server .
COPY --from=builder /app/public ./public

RUN mkdir -p uploads

# Expose server port
EXPOSE 8080

# Default command (can override in Compose)
CMD ["./chat-server"]
