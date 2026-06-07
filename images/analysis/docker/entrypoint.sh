#!/bin/bash
set -e

echo "[entrypoint] Starting ClamAV daemon..."

# Обновляем базы если их нет
if [ ! -f /var/lib/clamav/main.cvd ] && [ ! -f /var/lib/clamav/main.cld ]; then
    echo "[entrypoint] Downloading ClamAV databases (first run)..."
    freshclam --quiet || echo "[entrypoint] freshclam failed, continuing anyway"
fi

# Запускаем clamd в фоне
clamd --config-file=/etc/clamav/clamd.conf &
CLAMD_PID=$!

# Ждём сокета
echo "[entrypoint] Waiting for clamd socket..."
for i in $(seq 1 30); do
    if [ -S /var/run/clamav/clamd.ctl ]; then
        echo "[entrypoint] clamd ready"
        break
    fi
    sleep 1
done

if [ ! -S /var/run/clamav/clamd.ctl ]; then
    echo "[entrypoint] WARNING: clamd socket not ready, ClamAV analysis will fail gracefully"
fi

# Запускаем основную команду
exec "$@"
