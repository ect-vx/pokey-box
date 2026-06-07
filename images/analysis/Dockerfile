# ── Stage 1: Build ──────────────────────────────────────────────────────────
FROM rust:1.82-bookworm AS builder

# Системные зависимости для yara и openssl
RUN apt-get update && apt-get install -y \
    libssl-dev \
    pkg-config \
    libyara-dev \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./

# Кешируем зависимости
RUN mkdir src && echo 'fn main(){}' > src/main.rs
RUN cargo build --release 2>/dev/null || true
RUN rm -rf src

# Копируем исходники и собираем
COPY src ./src
RUN touch src/main.rs && cargo build --release

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    # ClamAV демон и базы
    clamav \
    clamav-daemon \
    clamav-freshclam \
    # YARA runtime
    libyara10 \
    # TLS
    ca-certificates \
    libssl3 \
    # Утилиты
    curl \
    && rm -rf /var/lib/apt/lists/*

# Создаём пользователя без root
RUN useradd -m -u 1000 -s /bin/bash analyzer

WORKDIR /app

# Бинарник
COPY --from=builder /build/target/release/sandbox-analyzer /usr/local/bin/sandbox-analyzer

# YARA правила
COPY yara-rules /app/yara-rules

# ClamAV конфиг
COPY docker/clamd.conf /etc/clamav/clamd.conf
COPY docker/freshclam.conf /etc/clamav/freshclam.conf

# Entrypoint скрипт (запускает clamav + приложение)
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Создаём директории
RUN mkdir -p /var/run/clamav /var/log/clamav /var/lib/clamav \
    && chown -R clamav:clamav /var/run/clamav /var/log/clamav /var/lib/clamav

ENV RUST_LOG=info
ENV CLAMAV_SOCKET=/var/run/clamav/clamd.ctl
ENV YARA_RULES_DIR=/app/yara-rules

ENTRYPOINT ["/entrypoint.sh"]
CMD ["sandbox-analyzer", "--help"]
