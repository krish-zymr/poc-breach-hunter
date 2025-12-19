"""Main classifier for Analysis Engine combining ML and SLM approaches."""
from __future__ import annotations

import os
from typing import Any, Dict, Optional

from intent_types import EventDict, IntentResult, normalize_event, RiskLevel
from logger import LOGGER
from ml_based import MLIntentModel
from risk_scorer import RiskScorer

    # Try to import SLM classifier (optional)
try:
    from slm_based import SLMIntentClassifier
    SLM_AVAILABLE = True
except ImportError:
    SLM_AVAILABLE = False
    SLMIntentClassifier = None


class AnalysisEngine:
    """Analysis Engine combining ML and SLM-based classification.

    This engine provides intent classification and risk scoring using:
    1. ML-based classifier (offline embeddings)
    2. SLM-based classifier (Ollama/Transformers)
    """

    def __init__(
        self,
        use_ml: bool = True,
        use_slm: bool = False,
    ):
        """Initialize the analysis engine.

        Args:
            use_ml: Whether to use ML-based classifier. Defaults to True.
            use_slm: Whether to use SLM-based classifier (if available). Defaults to False.
        """
        self.ml_model: Optional[MLIntentModel] = None
        self.slm_model: Optional[SLMIntentClassifier] = None

        # Initialize SLM if requested and available
        if use_slm and SLM_AVAILABLE and SLMIntentClassifier:
            try:
                slm_backend = os.getenv("BREACH_HUNTER_SLM_BACKEND", "auto")
                # Warmup enabled by default (recommended for production)
                warmup_enabled = os.getenv("BREACH_HUNTER_SLM_WARMUP", "1").lower() in ('1', 'true', 'yes', 'on')
                self.slm_model = SLMIntentClassifier(backend=slm_backend, warmup=warmup_enabled)
                self.ml_model = None  # SLM replaces ML
                LOGGER.info("Analysis Engine initialized with SLM (backend: %s, warmup: %s)", slm_backend, warmup_enabled)
            except Exception as e:
                LOGGER.warning("Failed to initialize SLM, falling back to ML: %s", e)
                self.slm_model = None
                self.ml_model = MLIntentModel() if use_ml else None
        else:
            self.slm_model = None
            self.ml_model = MLIntentModel() if use_ml else None

        LOGGER.info("Analysis Engine initialized (ML: %s, SLM: %s)", use_ml, use_slm and SLM_AVAILABLE)

    def classify_event(
        self,
        event_type: str,
        arguments: Dict[str, Any],
        agent_info: Optional[Dict[str, Any]] = None,
    ) -> IntentResult:
        """Classify an event and return intent and risk assessment.

        Args:
            event_type: Type of event (e.g., "file_open", "subprocess_popen").
            arguments: Event arguments dictionary.
            agent_info: Optional agent information (for future use).

        Returns:
            IntentResult dictionary with classification results.
        """
        # Normalize event
        event = normalize_event(event_type, arguments)

        # Use SLM if available, otherwise ML
        if self.slm_model:
            result = self.slm_model.classify(event)
        elif self.ml_model:
            result = self.ml_model.classify(event)
        else:
            # Fallback: simple risk assessment
            from intent_types import ActionType, IntentType, RiskLevel

            # Infer action type
            action_type = ActionType.UNKNOWN
            if "file" in event_type.lower():
                if "write" in event_type.lower() or arguments.get("mode", "").startswith("w"):
                    action_type = ActionType.FILE_WRITE
                else:
                    action_type = ActionType.FILE_READ
            elif "subprocess" in event_type.lower() or "process" in event_type.lower():
                action_type = ActionType.SUBPROCESS_EXEC
            elif "network" in event_type.lower() or "socket" in event_type.lower():
                action_type = ActionType.NETWORK_CONNECT

            intent = IntentType.UNKNOWN
            risk_score = RiskScorer.compute_combined_risk(action_type, intent, event, 0.5)
            risk_level = RiskScorer.risk_level_from_score(risk_score)
            
            # CRITICAL OVERRIDE: Writing to critical file paths is ALWAYS CRITICAL
            if RiskScorer.is_critical_file_write(action_type, event):
                risk_level = RiskLevel.CRITICAL
                explanation = "Fallback classification (no ML/SLM available) | OVERRIDE: Critical file write detected -> CRITICAL risk"
            else:
                explanation = "Fallback classification (no ML/SLM available)"

            result = IntentResult(
                action_type=action_type,
                intent=intent,
                risk=risk_level,
                confidence=0.5,
                explanation=explanation,
                rule_matched=None,
                ml_confidence=0.5,
            )

        return result

