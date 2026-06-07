# ── Stage 1: Build ──────────────────────────────────────────────────────────
FROM rust:1.88-bookworm AS builder
 
# Фикс "invalid signature" — отключаем проверку GPG и даты
RUN echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-check \
 && echo 'Acquire::AllowInsecureRepositories "true";' >> /etc/apt/apt.conf.d/99no-check \
 && echo 'APT::Get::AllowUnauthenticated "true";' >> /etc/apt/apt.conf.d/99no-check
 
RUN apt-get update -o Acquire::ForceIPv4=true && apt-get install -y --no-install-recommends \
    libssl-dev \
    pkg-config \
    libclang-dev \
    && apt-get install -y --no-install-recommends libyara-dev 2>/dev/null || true \
    && rm -rf /var/lib/apt/lists/*
 
WORKDIR /build
COPY Cargo.toml ./
 
# Кешируем зависимости отдельным слоем
RUN mkdir src && echo 'fn main(){}' > src/main.rs
RUN cargo build --release 2>/dev/null; rm -rf src
 
COPY src ./src
RUN touch src/main.rs && cargo build --release
 
# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime
 
RUN echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-check \
 && echo 'Acquire::AllowInsecureRepositories "true";' >> /etc/apt/apt.conf.d/99no-check \
 && echo 'APT::Get::AllowUnauthenticated "true";' >> /etc/apt/apt.conf.d/99no-check
 
RUN apt-get update -o Acquire::ForceIPv4=true && apt-get install -y --no-install-recommends \
    clamav \
    clamav-daemon \
    clamav-freshclam \
    ca-certificates \
    libssl3 \
    curl \
    && apt-get install -y --no-install-recommends libyara10 2>/dev/null \
    || apt-get install -y --no-install-recommends libyara9 2>/dev/null || true \
    && rm -rf /var/lib/apt/lists/*
 
WORKDIR /app
 
COPY --from=builder /build/target/release/sandbox-analyzer /usr/local/bin/sandbox-analyzer
COPY yara-rules /app/yara-rules
COPY docker/clamd.conf /etc/clamav/clamd.conf
COPY docker/freshclam.conf /etc/clamav/freshclam.conf
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
 
RUN mkdir -p /var/run/clamav /var/log/clamav /var/lib/clamav \
    && chown -R clamav:clamav /var/run/clamav /var/log/clamav /var/lib/clamav
 
ENV RUST_LOG=info
ENV CLAMAV_SOCKET=/var/run/clamav/clamd.ctl
ENV YARA_RULES_DIR=/app/yara-rules
 
ENTRYPOINT ["/entrypoint.sh"]
CMD ["sandbox-analyzer", "--help"]
