#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"
API_PORT="${API_PORT:-8000}"
WEB_PORT="${WEB_PORT:-8080}"
PYTHON="${PYTHON:-python3}"
if [ -f ".venv/bin/activate" ]; then
  source .venv/bin/activate
fi
"$PYTHON" -c "import fastapi, uvicorn, psutil, prometheus_client" 2>/dev/null || {
  echo "[SETUP] Installing missing Python deps..."
  "$PYTHON" -m pip install --quiet fastapi 'uvicorn[standard]' psutil pyyaml prometheus_client || true
}
cleanup() {
  echo ""
  echo "[SHUTDOWN] Stopping processes..."
  [ -n "${API_PID:-}" ] && kill "$API_PID" 2>/dev/null || true
  [ -n "${WEB_PID:-}" ] && kill "$WEB_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  echo "[SHUTDOWN] Done."
}
trap cleanup EXIT INT TERM
echo "═══════════════════════════════════════════════════════════"
echo "  ZENITH-SENTRY — Starting web stack"
echo "═══════════════════════════════════════════════════════════"
echo "  API  : http://localhost:${API_PORT}  (FastAPI)"
echo "  WEB  : http://localhost:${WEB_PORT}  (Command Center UI)"
echo "  DOCS : http://localhost:${API_PORT}/docs"
echo "═══════════════════════════════════════════════════════════"
echo "[API]  Launching FastAPI on :${API_PORT} ..."
"$PYTHON" -m uvicorn zenith.api.main:app \
  --host 0.0.0.0 --port "$API_PORT" --log-level warning &
API_PID=$!
for i in {1..20}; do
  if curl -fsS "http://localhost:${API_PORT}/health" >/dev/null 2>&1; then
    echo "[API]  Ready."
    break
  fi
  sleep 0.25
done
echo "[WEB]  Launching Command Center on :${WEB_PORT} ..."
"$PYTHON" web/server.py --http --port "$WEB_PORT" --api "http://localhost:${API_PORT}" &
WEB_PID=$!
echo ""
echo "  ► Open: http://localhost:${WEB_PORT}"
echo "  ► Press Ctrl+C to stop."
echo ""
wait
