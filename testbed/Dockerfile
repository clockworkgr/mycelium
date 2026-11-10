## Multi-stage build for mycelium-node testbed container

# Stage 1: Build
FROM rust:1.82-bookworm AS builder

WORKDIR /build
COPY . .

RUN cargo build --release --bin mycelium-node

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    iproute2 \
    iputils-ping \
    iptables \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/mycelium-node /usr/local/bin/mycelium-node

RUN mkdir -p /data/mycelium

# Read by mycelium-node at startup (CLI flags take precedence).
ENV MYCELIUM_DATA_DIR=/data/mycelium
ENV MYCELIUM_DISPLAY_NAME=testbed-node
ENV RUST_LOG=info

ENTRYPOINT ["/usr/local/bin/mycelium-node"]
