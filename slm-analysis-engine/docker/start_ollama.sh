#!/bin/bash
# Startup script to initialize Ollama service and ensure model is available

set -e

echo "🔧 Initializing Ollama for SLM support..."

# Ensure cache directory exists (for Transformers models)
if [ ! -d "/opt/hf_cache" ]; then
    mkdir -p /opt/hf_cache
    chmod 777 /opt/hf_cache
    echo "✅ Created /opt/hf_cache directory"
fi

# Check if Ollama binary exists and is valid
if [ ! -f "/usr/local/bin/ollama" ] || [ ! -x "/usr/local/bin/ollama" ]; then
    echo "⚠️  Ollama binary not found or not executable"
    echo "   Ollama will not be available. Using Transformers backend only."
    exit 0  # Don't fail the container, just skip Ollama
fi

# Verify Ollama binary is actually a binary (not HTML/text)
if file /usr/local/bin/ollama 2>/dev/null | grep -qE "(text|HTML|ASCII)"; then
    echo "❌ Ollama binary appears to be text/HTML, not a binary"
    echo "   Ollama will not be available. Using Transformers backend only."
    exit 0
fi

# Start Ollama service in background
echo "🚀 Starting Ollama service..."
/usr/local/bin/ollama serve &
OLLAMA_PID=$!

# Wait for Ollama to be ready
echo "⏳ Waiting for Ollama to start..."
for i in {1..10}; do
    if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
        echo "✅ Ollama is ready!"
        break
    fi
    sleep 1
done

# Check if model exists, if not pull it
echo "📦 Checking for model llama3.2:1b..."
if ! ollama list 2>/dev/null | grep -q "llama3.2:1b"; then
    echo "📥 Pulling model llama3.2:1b (this may take a few minutes)..."
    ollama pull llama3.2:1b
    echo "✅ Model downloaded"
else
    echo "✅ Model llama3.2:1b already available"
fi

echo "✅ Ollama is ready!"
echo "   Model: llama3.2:1b"
echo "   API: http://localhost:11434"
echo ""

# ---------------------------------------------------------------------------
# Verify Transformers model snapshot (downloaded during build)
# ---------------------------------------------------------------------------
TRANSFORMERS_MODEL="${AEGIS_TRANSFORMERS_MODEL:-distilbert-base-uncased}"
MODELS_DIR="${AEGIS_MODELS_DIR:-/opt/models}"
LOCAL_MODEL_DIR="${MODELS_DIR}/${TRANSFORMERS_MODEL//\//_}"

if [ -f "${LOCAL_MODEL_DIR}/config.json" ]; then
  echo "✅ Transformers model ready (pre-downloaded during build)"
  echo "   Runtime: Offline mode (zero network activity)"
else
  echo "📥 Transformers model: Will download on first classification"
  echo "   (Model will be cached for future use)"
fi
echo ""

# Keep Ollama running in background
# Don't wait - let it run in background
disown $OLLAMA_PID 2>/dev/null || true

