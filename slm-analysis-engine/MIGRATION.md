# Migration Guide: Embedded LLM to Analysis Engine

This guide explains how to migrate from the embedded LLM setup to the new Analysis Engine architecture.

## What Changed

### Before (Embedded LLM)

- LLM dependencies (Ollama, Transformers, Torch) were in `aegis-runtime`
- Each runtime instance loaded its own LLM models
- Models were downloaded during Docker build

### After (Analysis Engine)

- LLM dependencies moved to `aegis-analysis-engine`
- Single Analysis Engine service serves multiple runtime instances
- Runtime instances connect via HTTP API

## Migration Steps

### 1. Build Analysis Engine

```bash
cd aegis-analysis-engine
docker build -t aegis-analysis-engine:latest .
```

### 2. Update Runtime Configuration

Set the Analysis Engine URL in your runtime environment:

```bash
export AEGIS_ANALYSIS_ENGINE_URL=http://analysis-engine:8000
```

Or in `docker-compose.yml`:

```yaml
environment:
  - AEGIS_ANALYSIS_ENGINE_URL=http://analysis-engine:8000
```

### 3. Deploy Both Services

Use the updated `docker-compose.yml` in `aegis-runtime/`:

```bash
cd aegis-runtime
docker-compose up -d
```

This will start both:
- `analysis-engine` (port 8000)
- `aegis-runtime` (connected to analysis-engine)

### 4. Verify Integration

Check that Runtime can connect to Analysis Engine:

```bash
# Check Analysis Engine health
curl http://localhost:8000/health

# Test classification
curl -X POST http://localhost:8000/api/v1/classify \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "file_open",
    "arguments": {"file": "/etc/passwd", "mode": "r"}
  }'
```

## Rollback

If you need to rollback to embedded LLM:

1. Set `AEGIS_USE_SLM=1` in runtime environment
2. Ensure LLM dependencies are installed in runtime image
3. Remove `AEGIS_ANALYSIS_ENGINE_URL` environment variable

Note: The embedded LLM code is still available but deprecated.

## Benefits

1. **Smaller Runtime Images**: ~2GB smaller (no LLM dependencies)
2. **Faster Builds**: Runtime builds in ~2 minutes vs ~10 minutes
3. **Shared Resources**: One Analysis Engine serves multiple runtimes
4. **Easier Updates**: Update Analysis Engine independently
5. **Better Scalability**: Scale Analysis Engine separately from Runtime

## Troubleshooting

### Runtime can't connect to Analysis Engine

- Check `AEGIS_ANALYSIS_ENGINE_URL` is set correctly
- Verify Analysis Engine is running: `curl http://analysis-engine:8000/health`
- Check network connectivity between containers

### Analysis Engine not starting

- Check logs: `docker logs aegis-analysis-engine`
- Verify Ollama/Transformers dependencies are installed
- Check model download completed during build

### Classification falling back to rules

- Check Analysis Engine health endpoint
- Verify `AEGIS_ANALYSIS_ENGINE_URL` is accessible from runtime
- Check runtime logs for connection errors

