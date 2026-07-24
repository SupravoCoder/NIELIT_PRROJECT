# Multi-stage Dockerfile for VulnSense AI
FROM python:3.11-slim

# Install system dependencies including nmap and curl
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency definition
COPY requirements.txt .

# Install Python packages
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Expose ports for FastAPI (8000) and Streamlit (8501)
EXPOSE 8000 8501

# Default environment variables
ENV API_BASE_URL=http://127.0.0.1:8000/api/v1
ENV HOST=0.0.0.0

# Startup script launching both FastAPI and Streamlit
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port 8000 & streamlit run app/frontend/app.py --server.port 8501 --server.address 0.0.0.0"]
