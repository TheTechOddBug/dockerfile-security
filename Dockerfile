# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY cmd/ cmd/
COPY internal/ internal/

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o dockerfile-sec ./cmd/dockerfile-sec/

# Final stage
FROM scratch

COPY --from=builder /app/dockerfile-sec /dockerfile-sec

ENTRYPOINT ["/dockerfile-sec"]
