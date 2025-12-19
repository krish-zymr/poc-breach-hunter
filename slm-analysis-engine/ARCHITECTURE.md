# AEGIS Analysis Engine Architecture

## Overview

The AEGIS Analysis Engine is a separate service that provides LLM-based intent classification and risk scoring for AEGIS Runtime instances. This separation allows:

1. **Scalability**: Multiple AEGIS Runtime instances can share a single Analysis Engine
2. **Resource Efficiency**: LLM dependencies are isolated to a single service
3. **Flexibility**: Analysis Engine can be deployed independently or disabled entirely

## Architecture

```
┌─────────────────┐         HTTP API         ┌──────────────────────┐
│  AEGIS Runtime  │ ────────────────────────> │ Analysis Engine      │
│  (Interception) │                           │ (LLM Classification) │
└─────────────────┘                           └──────────────────────┘
                                                       │
                                                       ├─ Ollama
                                                       ├─ Transformers
                                                       └─ ML Models
```

## Components

### Analysis Engine Service

- **Location**: `aegis-analysis-engine/`
- **Purpose**: Provides LLM-based intent classification and risk scoring
- **API**: REST API on port 8000
- **Backends**:
  - Ollama (preferred)
  - Transformers (fallback)
  - ML-based (offline embeddings)

### AEGIS Runtime

- **Location**: `aegis-runtime/`
- **Purpose**: Intercepts Python operations and enforces policies
- **Integration**: Optional connection to Analysis Engine via HTTP client
- **Fallback**: Rule-based classification if Analysis Engine unavailable

## Integration

### Configuration

AEGIS Runtime connects to Analysis Engine via environment variable:

```bash
AEGIS_ANALYSIS_ENGINE_URL=http://analysis-engine:8000
```

If not set, AEGIS Runtime will use rule-based classification only.

### Request Flow

1. AEGIS Runtime intercepts an event (file access, network, subprocess, etc.)
2. Rule-based classification runs first (fast, local)
3. If rule doesn't match or risk is low, query Analysis Engine
4. Analysis Engine uses LLM to classify intent and assess risk
5. Results are combined and cached

## Deployment

### Docker Compose

The `docker-compose.yml` in `aegis-runtime/` includes both services:

```yaml
services:
  analysis-engine:
    # LLM service on port 8000
    
  aegis-runtime:
    # Runtime service
    environment:
      - AEGIS_ANALYSIS_ENGINE_URL=http://analysis-engine:8000
    depends_on:
      - analysis-engine
```

### Standalone Deployment

You can deploy Analysis Engine independently:

```bash
cd aegis-analysis-engine
docker build -t aegis-analysis-engine:latest .
docker run -p 8000:8000 aegis-analysis-engine:latest
```

Then configure AEGIS Runtime to connect to it.

## API Reference

### POST /api/v1/classify

Classify an event and return intent/risk assessment.

**Request:**
```json
{
  "event_type": "file_open",
  "arguments": {
    "file": "/etc/passwd",
    "mode": "r"
  },
  "agent_info": {
    "agent_id": "agent-123"
  }
}
```

**Response:**
```json
{
  "action_type": "file_read",
  "intent": "enumeration",
  "risk": "high",
  "confidence": 0.85,
  "explanation": "SLM (ollama): Reading system file...",
  "classification_backend": "ollama",
  "classification_duration_ms": 150
}
```

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "ml_available": true,
  "slm_available": true
}
```

## Migration Notes

### From Embedded LLM to Analysis Engine

1. **Old Setup**: LLM dependencies in `aegis-runtime` Dockerfile
2. **New Setup**: LLM dependencies in `aegis-analysis-engine` Dockerfile
3. **Runtime Changes**: 
   - Removed: Ollama, Transformers, Torch dependencies
   - Added: Analysis Engine HTTP client
   - Behavior: Falls back to rule-based if Analysis Engine unavailable

### Backward Compatibility

- AEGIS Runtime still supports local SLM/ML if Analysis Engine is not configured
- Rule-based classification always available
- No breaking changes to existing APIs

## Performance Considerations

- **Caching**: Both services cache classification results
- **Latency**: HTTP requests add ~10-50ms overhead
- **Throughput**: Analysis Engine can handle multiple concurrent requests
- **Resource Usage**: LLM models loaded once in Analysis Engine, shared across requests

## Security Considerations

- Analysis Engine should be deployed in a trusted network
- Consider authentication/authorization for production deployments
- Network traffic between Runtime and Engine should be encrypted (HTTPS) in production

