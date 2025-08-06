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

# Copy the binary from builder
COPY --from=builder /app/flatten .

# Make it executable
RUN chmod +x ./flatten

# Create a non-root user
RUN adduser -D -s /bin/sh flattenuser
USER flattenuser

WORKDIR /workspace

# Set the binary as entrypoint
ENTRYPOINT ["/root/flatten"]
CMD ["--help"]
