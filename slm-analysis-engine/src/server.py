"""FastAPI server for Breach Hunter Analysis Engine."""
from __future__ import annotations

import os
import sys
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from classifier import AnalysisEngine
from intent_types import normalize_event
from logger import LOGGER

app = FastAPI(
    title="Breach Hunter Analysis Engine",
    description="LLM-based intent classification and risk scoring service",
    version="0.1.0",
)


class ClassifyRequest(BaseModel):
    """Request model for classification."""

    event_type: str
    arguments: Dict[str, Any]
    agent_info: Optional[Dict[str, Any]] = None


class ClassifyResponse(BaseModel):
    """Response model for classification."""

    action_type: str
    intent: str
    risk: str
    confidence: float
    explanation: str
    rule_matched: Optional[str] = None
    ml_confidence: Optional[float] = None
    classification_backend: Optional[str] = None
    classification_duration_ms: Optional[int] = None


# Global classifier instance
_engine: Optional[AnalysisEngine] = None


def get_engine() -> AnalysisEngine:
    """Get or create the analysis engine instance."""
    global _engine
    if _engine is None:
        use_slm = os.getenv("BREACH_HUNTER_USE_SLM", "1").lower() in ("1", "true", "yes", "on")
        use_ml = os.getenv("BREACH_HUNTER_USE_ML", "1").lower() in ("1", "true", "yes", "on")
        _engine = AnalysisEngine(use_ml=use_ml, use_slm=use_slm)
        LOGGER.info("Analysis Engine initialized (ML: %s, SLM: %s)", use_ml, use_slm)
    return _engine


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "Breach Hunter Analysis Engine",
        "version": "0.1.0",
        "status": "running",
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    try:
        engine = get_engine()
        return {
            "status": "healthy",
            "ml_available": engine.ml_model is not None,
            "slm_available": engine.slm_model is not None,
        }
    except Exception as e:
        LOGGER.error("Health check failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")


@app.post("/api/v1/classify", response_model=ClassifyResponse)
async def classify(request: ClassifyRequest):
    """Classify an event and return intent and risk assessment."""
    try:
        engine = get_engine()
        result = engine.classify_event(
            event_type=request.event_type,
            arguments=request.arguments,
            agent_info=request.agent_info,
        )

        # Convert enums to strings for JSON serialization
        return ClassifyResponse(
            action_type=result["action_type"].value if hasattr(result["action_type"], "value") else str(result["action_type"]),
            intent=result["intent"].value if hasattr(result["intent"], "value") else str(result["intent"]),
            risk=result["risk"].value if hasattr(result["risk"], "value") else str(result["risk"]),
            confidence=result["confidence"],
            explanation=result["explanation"],
            rule_matched=result.get("rule_matched"),
            ml_confidence=result.get("ml_confidence"),
            classification_backend=result.get("classification_backend"),
            classification_duration_ms=result.get("classification_duration_ms"),
        )
    except Exception as e:
        LOGGER.error("Classification failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Classification failed: {str(e)}")


def main():
    """Main entry point for the server."""
    import uvicorn

    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "0.0.0.0")

    LOGGER.info("Starting Breach Hunter Analysis Engine on %s:%d", host, port)
    uvicorn.run("server:app", host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()

