FROM golang:1.21 AS builder
WORKDIR /app

RUN apt-get update && apt-get install -y gcc sqlite3 libsqlite3-dev

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 go build -o chat-server ./cmd/server

FROM debian:bullseye-slim
WORKDIR /app

RUN apt-get update && apt-get install -y ca-certificates sqlite3 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/chat-server .
COPY --from=builder /app/public ./public

RUN mkdir -p uploads

EXPOSE 8080

CMD ["./chat-server"]