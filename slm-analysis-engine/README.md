# AEGIS Analysis Engine

AEGIS Analysis Engine provides LLM-based intent classification and risk scoring services for AEGIS Runtime. It can be deployed as a standalone service that multiple AEGIS Runtime instances can connect to.

## Features

- **SLM-based Intent Classification**: Uses Small Language Models (Ollama or Transformers) for sophisticated intent detection
- **ML-based Classification**: Offline ML-based classification using embeddings
- **Risk Scoring**: Comprehensive risk assessment based on action types, intents, and context
- **REST API**: HTTP API for integration with AEGIS Runtime instances
- **Docker Support**: Pre-configured Docker image with all LLM dependencies

## Quick Start

### Using Docker

```bash
# Build the image
docker build -t aegis-analysis-engine:latest .

# Run the service
docker run -d \
  -p 8000:8000 \
  -e AEGIS_SLM_BACKEND=auto \
  -e AEGIS_OLLAMA_MODEL=llama3.2:1b \
  aegis-analysis-engine:latest
```

### Using Docker Compose

See the main `docker-compose.yml` in the parent directory for an integrated setup with AEGIS Runtime.

### API Usage

The service exposes a REST API at `http://localhost:8000`:

```bash
# Classify an event
curl -X POST http://localhost:8000/api/v1/classify \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "file_open",
    "arguments": {
      "file": "/etc/passwd",
      "mode": "r"
    }
  }'
```

## Configuration

### Environment Variables

- `AEGIS_SLM_BACKEND`: Backend to use (`auto`, `ollama`, `transformers`, `simple`)
- `AEGIS_OLLAMA_MODEL`: Ollama model name (default: `llama3.2:1b`)
- `AEGIS_TRANSFORMERS_MODEL`: Transformers model name (default: `distilbert-base-uncased`)
- `AEGIS_MODELS_DIR`: Directory for model snapshots (default: `/opt/models`)
- `HF_HOME`: HuggingFace cache directory (default: `/opt/hf_cache`)
- `PORT`: API server port (default: `8000`)

## Architecture

The Analysis Engine is designed to be:
- **Stateless**: Each request is independent
- **Scalable**: Can handle multiple concurrent requests
- **Resilient**: Falls back gracefully if LLM backends are unavailable
- **Fast**: Uses caching and optimized inference

## Integration with AEGIS Runtime

AEGIS Runtime instances can connect to the Analysis Engine by setting:
- `AEGIS_ANALYSIS_ENGINE_URL`: URL of the analysis engine service (e.g., `http://analysis-engine:8000`)

If not configured, AEGIS Runtime will use rule-based classification only.

