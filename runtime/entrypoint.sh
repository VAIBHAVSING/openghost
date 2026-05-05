#!/usr/bin/env bash
set -euo pipefail

ZAP_HOST="${ZAP_HOST:-127.0.0.1}"
ZAP_PORT="${ZAP_PORT:-8080}"
CHROMIUM_BIN="$(command -v chromium || command -v chromium-browser || true)"

if [[ -n "${CHROMIUM_BIN}" ]]; then
  "${CHROMIUM_BIN}" \
    --headless \
    --disable-gpu \
    --disable-dev-shm-usage \
    --no-sandbox \
    --remote-debugging-address=127.0.0.1 \
    --remote-debugging-port=9222 \
    about:blank >/tmp/chromium.log 2>&1 &
fi

zap.sh -daemon \
  -host "${ZAP_HOST}" \
  -port "${ZAP_PORT}" \
  -config api.disablekey=true \
  -config api.addrs.addr.name=127.0.0.1 \
  -config api.addrs.addr.regex=false >/tmp/zap.log 2>&1 &

for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:${ZAP_PORT}/JSON/core/view/version/" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

exec sleep infinity
