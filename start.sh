#!/usr/bin/env bash
# Start script for launching the VulnSense AI application.
# The FastAPI backend is started automatically within the Streamlit process.

set -e

# If running locally on Windows/Git Bash or Linux with a .venv present, activate it automatically
if [ -f ".venv/Scripts/activate" ]; then
    source .venv/Scripts/activate
elif [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
fi

PORT="${PORT:-8501}"
echo "🌐 Starting VulnSense AI on port ${PORT}..."
exec streamlit run app/frontend/app.py --server.port "${PORT}" --server.address 0.0.0.0

