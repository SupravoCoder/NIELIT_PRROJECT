#!/usr/bin/env bash
# Start script for launching both FastAPI backend and Streamlit frontend.

set -e

# If running locally on Windows/Git Bash or Linux with a .venv present, activate it automatically
if [ -f ".venv/Scripts/activate" ]; then
    source .venv/Scripts/activate
elif [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
fi

echo "🚀 Starting FastAPI backend (Uvicorn)..."
uvicorn app.main:app --host 0.0.0.0 --port 8000 &

echo "⏳ Waiting for backend service to initialize..."
sleep 3

PORT="${PORT:-8501}"
echo "🌐 Starting Streamlit frontend on port ${PORT}..."
exec streamlit run app/frontend/app.py --server.port "${PORT}" --server.address 0.0.0.0

