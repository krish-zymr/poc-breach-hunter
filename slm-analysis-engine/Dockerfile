# AEGIS Analysis Engine Docker Image
# This image provides LLM-based intent classification and risk scoring services
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install dependencies for SLM support
# - curl: for Ollama installation and API calls
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy project files first (needed for package installation)
COPY pyproject.toml ./
COPY src/ ./src/
COPY README.md ./

# Copy Ollama startup script (needed before we install Ollama)
RUN mkdir -p /app/docker
COPY docker/start_ollama.sh /usr/local/bin/start_ollama.sh
RUN chmod +x /usr/local/bin/start_ollama.sh

# Install Ollama
# Try multiple download methods to ensure we get the binary
# If download fails, create a placeholder so the build doesn't fail
RUN (curl -L -f https://ollama.com/download/ollama-linux-amd64 -o /usr/local/bin/ollama 2>/dev/null || \
     curl -L -f https://github.com/ollama/ollama/releases/latest/download/ollama-linux-amd64 -o /usr/local/bin/ollama 2>/dev/null || \
     (echo "⚠️  Warning: Ollama download failed, will install at runtime" && echo "#!/bin/bash" > /usr/local/bin/ollama && echo "echo 'Ollama not installed. Run: curl -fsSL https://ollama.com/install.sh | sh'" >> /usr/local/bin/ollama)) && \
    chmod +x /usr/local/bin/ollama && \
    (file /usr/local/bin/ollama 2>/dev/null | grep -q "ELF" && /usr/local/bin/ollama --version >/dev/null 2>&1 || echo "⚠️  Warning: Ollama binary verification failed - will use Transformers backend only")

# Set up Ollama environment
ENV OLLAMA_HOST=0.0.0.0:11434
ENV OLLAMA_ORIGINS=*
ENV PATH="/usr/local/bin:${PATH}"

# Start Ollama and pull model during build
# This ensures the model is available when container runs (adds ~1.3GB to image)
RUN if [ -x /usr/local/bin/ollama ]; then \
        /usr/local/bin/ollama serve & \
        sleep 10 && \
        /usr/local/bin/ollama pull llama3.2:1b && \
        pkill -f "ollama serve" || true && \
        sleep 2; \
    else \
        echo "⚠️  Warning: Ollama not executable, model will be pulled at runtime"; \
    fi

# Install the analysis engine package
RUN pip install --no-cache-dir -e .

# Install SLM dependencies for intent classification (one-by-one for clearer failures)
# Requests (redundant but kept explicit)
RUN pip install --no-cache-dir requests>=2.31.0 || echo "⚠️  requests install failed"
# HuggingFace Hub (for snapshot download) - install BEFORE transformers
RUN pip install --no-cache-dir huggingface_hub>=0.20.0 || echo "⚠️  huggingface_hub install failed"
# Transformers
RUN pip install --no-cache-dir transformers>=4.30.0 || echo "⚠️  transformers install failed (SLM may not work)"
# Torch
RUN pip install --no-cache-dir torch>=2.0.0 || echo "⚠️  torch install failed (SLM may not work)"
# FastAPI and Uvicorn
RUN pip install --no-cache-dir fastapi>=0.104.0 uvicorn>=0.24.0 pydantic>=2.0.0 || echo "⚠️  FastAPI install failed"

# Copy model download script (needed before we download the model)
COPY docker/download_model.py /tmp/download_model.py

# Download Transformers model snapshot during build (deterministic, zero network at runtime)
# This ensures the model is fully downloaded and available locally
RUN mkdir -p /opt/models && \
    python3 /tmp/download_model.py || echo "⚠️  Warning: Model snapshot download failed, will download on first use"

# Set default environment variables
ENV PYTHONPATH=/app/src
ENV AEGIS_SLM_BACKEND=auto
ENV AEGIS_OLLAMA_MODEL=llama3.2:1b
ENV AEGIS_USE_SLM=1
ENV AEGIS_USE_ML=1

# Persistent cache for Transformers models (VERY IMPORTANT - prevents re-download on restart)
# Using HF_HOME (recommended) - TRANSFORMERS_CACHE is deprecated in v5
ENV HF_HOME=/opt/hf_cache
ENV HF_HUB_DISABLE_PROGRESS_BARS=1

# Create cache directory with proper permissions
RUN mkdir -p /opt/hf_cache && chmod 777 /opt/hf_cache

# Model configuration
ENV AEGIS_TRANSFORMERS_MODEL=distilbert-base-uncased
ENV AEGIS_MODELS_DIR=/opt/models

# API server configuration
ENV PORT=7000
ENV HOST=0.0.0.0

# Expose API port
EXPOSE 7000

# Default command: start the API server
CMD ["python3", "-m", "aegis_analysis_engine.server"]
