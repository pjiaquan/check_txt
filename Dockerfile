# Build stage
FROM rust:latest as builder

WORKDIR /usr/src/app

# Install build dependencies
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy the source code
COPY . .

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /usr/local/bin

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y libssl3 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user for security
RUN useradd --create-home --shell /bin/bash app

# Copy the binary from builder
COPY --from=builder /usr/src/app/target/release/check_txt .

# Create necessary directories with proper permissions
RUN mkdir -p /app/temp /app/static && \
    chown -R app:app /app && \
    chmod -R 755 /app

# Set working directory
WORKDIR /app

# Switch to non-root user
USER app

# Expose the port the app runs on
EXPOSE 8090

# Run the binary with web server
CMD ["/usr/local/bin/check_txt", "--web"] 