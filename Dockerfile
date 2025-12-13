# Build stage
FROM golang:1.21-alpine AS builder

# Install git for version information
RUN apk add --no-cache git

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=$(git describe --tags --always --dirty 2>/dev/null || echo 'docker')" \
    -o flatten \
    ./cmd/flatten

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests if needed
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Create a non-root user
RUN adduser -D -s /bin/sh flattenuser

# Create a writable workdir for the non-root user
RUN mkdir -p /workspace && chown -R flattenuser:flattenuser /workspace

# Copy the binary from builder into a location accessible to the non-root user
COPY --from=builder /app/flatten /usr/local/bin/flatten
RUN chmod +x /usr/local/bin/flatten
USER flattenuser

WORKDIR /workspace

# Set the binary as entrypoint
ENTRYPOINT ["/usr/local/bin/flatten"]
CMD ["--help"]
