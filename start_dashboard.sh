#!/usr/bin/env bash
# AdapTrap Dashboard Startup Script

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_EXEC="${SCRIPT_DIR}/venv/bin/python3"

echo "=========================================="
echo "AdapTrap Web Dashboard"
echo "=========================================="
echo ""
echo "Starting Flask server..."
echo "Dashboard will be available at:"
echo ""
echo "  http://127.0.0.1:5000"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""
echo "=========================================="
echo ""

# Free port 5000 if a stale background process is holding it
fuser -k 5000/tcp 2>/dev/null || true

cd "${SCRIPT_DIR}/dashboard"
exec "${PYTHON_EXEC}" app.py
