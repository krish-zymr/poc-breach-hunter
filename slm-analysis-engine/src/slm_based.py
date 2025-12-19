"""SLM-based intent classifier using small language models for intent and risk detection."""
from __future__ import annotations

import json
import time
import torch
import torch.nn.functional as F
import os
from typing import Dict, Optional

from logger import LOGGER
from intent_types import ActionType, EventDict, IntentResult, IntentType, RiskLevel
from risk_scorer import RiskScorer


class SLMIntentClassifier:
    """SLM-based intent classifier using small language models.
    
    Supports multiple backends:
    - Ollama (if available)
    - Transformers library with small models
    - Fallback to simple ML model
    """

    def __init__(self, backend: str = "auto", warmup: bool = True):
        """Initialize the SLM classifier.
        
        Args:
            backend: Backend to use ("ollama", "transformers", "auto", or "simple").
                "auto" tries ollama first, then transformers, then falls back to simple.
            warmup: Whether to perform warm-up inference after initialization. Defaults to True.
        """
        self.backend = backend
        self.ollama_client = None
        self.transformer_model = None
        self.transformer_tokenizer = None
        self._initialize_backend()
        
        # Perform warm-up inference if requested (recommended for production)
        if warmup:
            self._warmup()

    def _initialize_backend(self) -> None:
        """Initialize the selected backend."""
        if self.backend == "auto":
            # Try Ollama first
            if self._try_ollama():
                self.backend = "ollama"
                LOGGER.info("SLM backend: Ollama")
                return
            
            # Try Transformers
            if self._try_transformers():
                self.backend = "transformers"
                LOGGER.info("SLM backend: Transformers")
                return
            
            # Fallback to simple
            self.backend = "simple"
            LOGGER.info("SLM backend: Simple (fallback)")
        
        elif self.backend == "ollama":
            if not self._try_ollama():
                raise RuntimeError("Ollama backend requested but not available")
        
        elif self.backend == "transformers":
            if not self._try_transformers():
                raise RuntimeError("Transformers backend requested but not available")

    def _try_ollama(self) -> bool:
        """Try to initialize Ollama client.
        
        Returns:
            True if Ollama is available, False otherwise.
        """
        try:
            import requests
            
            # Check if Ollama is running (try a few times with delays)
            for attempt in range(3):
                try:
                    response = requests.get("http://localhost:11434/api/tags", timeout=3)
                    if response.status_code == 200:
                        self.ollama_client = requests
                        LOGGER.info("Ollama is available and running")
                        return True
                except Exception:
                    # Ollama might not be started yet, try to start it
                    if attempt == 0:
                        try:
                            import subprocess
                            # Try to start Ollama in background
                            subprocess.Popen(["ollama", "serve"], 
                                           stdout=subprocess.DEVNULL, 
                                           stderr=subprocess.DEVNULL)
                            import time
                            time.sleep(3)  # Wait for Ollama to start
                        except Exception:
                            pass
                    elif attempt < 2:
                        import time
                        time.sleep(2)  # Wait a bit more
            
            LOGGER.debug("Ollama not available after retries")
            return False
        except ImportError:
            return False

    def _warmup(self) -> None:
        """Perform warm-up inference to ensure model is loaded and ready.
        
        This runs a simple classification on a benign event to:
        - Load tokenizer and model into memory
        - Warm up GPU/CPU caches
        - Verify everything works before first real classification
        """
        try:
            # Create a simple benign event for warm-up
            warmup_event: EventDict = {
                "event_type": "file_open",
                "file": "/tmp/test.txt",
                "mode": "r",
            }
            
            LOGGER.debug("Warming up SLM with test inference...")
            start_time = time.perf_counter()
            
            # Perform a simple classification (this will load model if not already loaded)
            result = self.classify(warmup_event)
            
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            intent_str = result.get("intent", "unknown")
            if hasattr(intent_str, "value"):
                intent_str = intent_str.value
            LOGGER.info("SLM warm-up complete (duration=%dms, intent=%s)", 
                       duration_ms, intent_str)
        except Exception as e:
            LOGGER.warning("SLM warm-up failed (non-critical): %s", e)
            # Don't fail initialization if warm-up fails

    def _get_model_path(self) -> Optional[str]:
        """Get local model path if snapshot exists, otherwise None.
        
        Returns:
            Local model directory path if snapshot exists, None otherwise.
        """
        try:
            model_name = os.getenv("BREACH_HUNTER_TRANSFORMERS_MODEL", "distilbert-base-uncased")
            models_dir = os.getenv("BREACH_HUNTER_MODELS_DIR", "/opt/models")
            # Convert model name to directory name (e.g., "distilbert-base-uncased" -> "distilbert-base-uncased")
            local_model_dir = os.path.join(models_dir, model_name.replace("/", "_"))
            
            # Check if snapshot exists (look for config.json as indicator)
            config_path = os.path.join(local_model_dir, "config.json")
            if os.path.exists(config_path):
                LOGGER.info(f"Using local model snapshot: {local_model_dir}")
                return local_model_dir
            else:
                LOGGER.debug(f"Local model snapshot not found at {local_model_dir}, will download on first use")
                return None
        except Exception as e:
            LOGGER.debug(f"Error checking for local model snapshot: {e}")
            return None
    
    def _try_transformers(self) -> bool:
        """Try to initialize Transformers library.
        
        Returns:
            True if Transformers is available, False otherwise.
        """
        try:
            from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
            
            # Use a small, fast model for classification
            model_name = os.getenv("BREACH_HUNTER_TRANSFORMERS_MODEL", os.getenv("BREACH_HUNTER_SLM_MODEL", "distilbert-base-uncased"))
            
            # Try to use local snapshot first (zero network activity)
            local_model_path = self._get_model_path()
            if local_model_path:
                # Use local snapshot with local_files_only=True (deterministic, no network)
                LOGGER.info(f"Loading model from local snapshot: {local_model_path}")
                try:
                    self.transformer_tokenizer = AutoTokenizer.from_pretrained(
                        local_model_path,
                        local_files_only=True
                    )
                    self.transformer_model = AutoModelForSequenceClassification.from_pretrained(
                        local_model_path,
                        local_files_only=True,
                        num_labels=len(IntentType),
                    )
                    return True
                except Exception as e:
                    LOGGER.warning(f"Failed to load from local snapshot: {e}, falling back to Hub download")
                    # Fall through to Hub download
            
            # Fallback to downloading from HuggingFace Hub
            LOGGER.info(f"Loading model from HuggingFace Hub: {model_name}")
            try:
                self.transformer_tokenizer = AutoTokenizer.from_pretrained(model_name)
                self.transformer_model = AutoModelForSequenceClassification.from_pretrained(
                    model_name,
                    num_labels=len(IntentType),
                )
                return True
            except Exception as e:
                LOGGER.warning("Failed to load transformer model: %s", e)
                return False
        except ImportError:
            return False

    def _event_to_prompt(self, event: EventDict) -> str:
        """Convert event to a prompt for the SLM using Sentinel Risk rules.
        
        Args:
            event: Normalized event dictionary.
            
        Returns:
            Prompt string for the SLM.
        """
        parts = []
        event_id = "event_001"  # Single event ID for this analysis
        
        event_type = event.get("event_type", "unknown")
        parts.append(f"Event ID: {event_id}")
        parts.append(f"Event type: {event_type}")
        
        if event.get("file"):
            parts.append(f"File: {event.get('file')}")
            if event.get("mode"):
                parts.append(f"Mode: {event.get('mode')}")
        
        if event.get("argv"):
            parts.append(f"Command: {' '.join(event.get('argv', []))}")
        elif event.get("cmd"):
            parts.append(f"Command: {event.get('cmd', '')}")
        
        if event.get("host"):
            parts.append(f"Host: {event.get('host')}")
            if event.get("port"):
                parts.append(f"Port: {event.get('port')}")
        
        prompt = f"""Analyze this security event and classify its risk according to Sentinel Risk rules.

Rules:
- Output STRICT JSON only.
- Every finding MUST reference valid event_id values from the input.
- If any event includes DESTRUCTIVE_ACTION or PROMPT_INJECTION, overall risk_level cannot be LOW.
- Base confidence on strength of evidence and sequence consistency.

Event details:
{chr(10).join(parts)}

Risk categories to consider:
- DESTRUCTIVE_ACTION: Attempts to delete, modify, or corrupt system files or data
- PROMPT_INJECTION: Attempts to inject malicious prompts or commands
- DATA_EXFILTRATION: Attempts to exfiltrate sensitive data
- PRIVILEGE_ESCALATION: Attempts to gain elevated privileges
- RECONNAISSANCE: Information gathering activities
- SUSPICIOUS_AUTOMATION: Automated or scripted suspicious behavior
- POLICY_EVASION: Attempts to evade security policies

Return JSON using this schema (STRICT JSON only):
{{
  "risk_score": <number between 0.0 and 1.0>,
  "risk_level": "SAFE"|"LOW"|"MEDIUM"|"HIGH"|"CRITICAL",
  "primary_risk_categories": [<array of risk category strings>],
  "findings": [
    {{
      "category": "<risk_category>",
      "severity": "SAFE"|"LOW"|"MEDIUM"|"HIGH"|"CRITICAL",
      "evidence_event_ids": ["{event_id}"],
      "reason": "<explanation of why this category applies>"
    }}
  ],
  "explanation": "<overall explanation of the risk assessment>",
  "recommended_next_actions": [<array of recommended action strings>],
  "uncertainties": [<array of uncertainty strings, if any>],
  "confidence": <number between 0.0 and 1.0>
}}"""
        
        return prompt

    def _classify_with_ollama(self, prompt: str, event: EventDict) -> Optional[Dict]:
        """Classify using Ollama.
        
        Args:
            prompt: Prompt string.
            event: Event dictionary (for context, though not directly used).
            
        Returns:
            Classification result dictionary or None if failed.
        """
        try:
            model = os.getenv("BREACH_HUNTER_OLLAMA_MODEL", "llama3.2:1b")  # Small model
            
            response = self.ollama_client.post(
                "http://localhost:11434/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                    # Optimized for JSON output
                    "options": {
                        "temperature": 0.1,  # Low temperature for consistent JSON
                        "num_predict": 512,  # Allow enough tokens for full JSON response
                        "top_p": 0.9,
                        "stop": []  # Don't stop early, need full JSON
                    }
                },
                timeout=30  # Increased timeout for more complex analysis
            )
            
            if response.status_code == 200:
                result = response.json()
                response_text = result.get("response", "")
                
                # Try to extract JSON from response
                try:
                    # Find JSON in response
                    start = response_text.find("{")
                    end = response_text.rfind("}") + 1
                    if start >= 0 and end > start:
                        json_str = response_text[start:end]
                        return json.loads(json_str)
                except Exception:
                    pass
                
                # Fallback: try to parse text response
                return self._parse_text_response(response_text)
            
            return None
        except Exception as e:
            LOGGER.warning("Ollama classification failed: %s", e)
            return None

    def _classify_with_transformers(self, prompt: str, event: EventDict) -> Optional[Dict]:
        """Classify using Transformers with logits (micro-inference style)."""
        try:
            inputs = self.transformer_tokenizer(
                prompt,
                return_tensors="pt",
                truncation=True,
                max_length=256,
                padding=True,
            )
            with torch.no_grad():
                outputs = self.transformer_model(**inputs)
                logits = outputs.logits  # [batch, num_labels]
                probs = F.softmax(logits, dim=-1)
                top_id = int(torch.argmax(probs, dim=-1))
                top_prob = float(probs[0, top_id])
                label = self.transformer_model.config.id2label.get(top_id, "unknown").lower()

            # Map model label to intent
            label_to_intent = {
                "benign": IntentType.BENIGN,
                "safe": IntentType.BENIGN,
                "neutral": IntentType.BENIGN,
                "malicious": IntentType.ATTACK_PREP,
                "attack": IntentType.ATTACK_PREP,
                "exfiltration": IntentType.DATA_EXFILTRATION,
                "data_exfiltration": IntentType.DATA_EXFILTRATION,
                "recon": IntentType.ENUMERATION,
                "enumeration": IntentType.ENUMERATION,
                "exploration": IntentType.EXPLORATION,
                "rce": IntentType.REMOTE_COMMAND_EXECUTION,
                "remote_command_execution": IntentType.REMOTE_COMMAND_EXECUTION,
                "privilege_escalation": IntentType.PRIVILEGE_ESCALATION,
            }

            intent = label_to_intent.get(label, IntentType.UNKNOWN)

            # Risk level derived from intent
            # DATA_EXFILTRATION and RECONNAISSANCE (ENUMERATION) are enforced as MEDIUM
            risk_map = {
                IntentType.BENIGN: RiskLevel.SAFE,
                IntentType.EXPLORATION: RiskLevel.LOW,
                IntentType.ENUMERATION: RiskLevel.MEDIUM,  # Maps to RECONNAISSANCE
                IntentType.DATA_EXFILTRATION: RiskLevel.MEDIUM,  # Enforced as MEDIUM
                IntentType.REMOTE_COMMAND_EXECUTION: RiskLevel.CRITICAL,
                IntentType.PRIVILEGE_ESCALATION: RiskLevel.CRITICAL,
                IntentType.ATTACK_PREP: RiskLevel.HIGH,
                IntentType.UNKNOWN: RiskLevel.MEDIUM,
            }
            risk_level = risk_map.get(intent, RiskLevel.MEDIUM)

            # Map intent to Sentinel Risk categories
            intent_to_categories = {
                IntentType.DATA_EXFILTRATION: ["DATA_EXFILTRATION"],
                IntentType.PRIVILEGE_ESCALATION: ["PRIVILEGE_ESCALATION"],
                IntentType.REMOTE_COMMAND_EXECUTION: ["DATA_EXFILTRATION", "SUSPICIOUS_AUTOMATION"],
                IntentType.ATTACK_PREP: ["DESTRUCTIVE_ACTION", "SUSPICIOUS_AUTOMATION"],
                IntentType.ENUMERATION: ["RECONNAISSANCE"],
                IntentType.EXPLORATION: ["RECONNAISSANCE", "SUSPICIOUS_AUTOMATION"],
                IntentType.BENIGN: [],
                IntentType.UNKNOWN: ["SUSPICIOUS_AUTOMATION"],
            }
            primary_categories = intent_to_categories.get(intent, ["SUSPICIOUS_AUTOMATION"])

            # Calculate risk score (0-100 scale)
            # Ensure DATA_EXFILTRATION and RECONNAISSANCE get MEDIUM risk score (60)
            risk_score_map = {
                RiskLevel.SAFE: 10,
                RiskLevel.LOW: 30,
                RiskLevel.MEDIUM: 60,
                RiskLevel.HIGH: 80,
                RiskLevel.CRITICAL: 95,
            }
            # Override: If intent is DATA_EXFILTRATION or category is RECONNAISSANCE, force MEDIUM
            if intent == IntentType.DATA_EXFILTRATION or "RECONNAISSANCE" in primary_categories:
                risk_level = RiskLevel.MEDIUM
                risk_score = 60
            else:
                risk_score = risk_score_map.get(risk_level, 50)

            # Build findings
            findings = []
            if primary_categories:
                for category in primary_categories:
                    findings.append({
                        "category": category,
                        "severity": risk_level.value.upper(),
                        "evidence_event_ids": ["event_001"],
                        "reason": self._generate_finding_reason(intent, category, event)
                    })

            # Generate comprehensive explanation
            explanation = self._generate_sentinel_explanation(intent, risk_level, primary_categories, event, top_prob)
            
            # Generate recommended actions
            recommended_actions = self._generate_recommended_actions(intent, risk_level, primary_categories)
            
            # Generate uncertainties
            uncertainties = self._generate_uncertainties(intent, top_prob)

            # Return in Sentinel Risk schema format
            return {
                "risk_score": risk_score,
                "risk_level": risk_level.value.upper(),
                "primary_risk_categories": primary_categories,
                "findings": findings,
                "explanation": explanation,
                "recommended_next_actions": recommended_actions,
                "uncertainties": uncertainties,
                "confidence": top_prob,
                # Also include legacy fields for compatibility
                "intent": intent.value,
            }
        except Exception as e:
            LOGGER.warning("Transformers classification failed: %s", e)
            return None

    def _parse_sentinel_response(self, response_data: Dict) -> Dict:
        """Parse Sentinel Risk schema response into our internal format.
        
        Args:
            response_data: Parsed JSON response from SLM.
            
        Returns:
            Parsed classification dictionary in our format.
        """
        # Map Sentinel risk categories to IntentType
        category_to_intent = {
            "DESTRUCTIVE_ACTION": IntentType.ATTACK_PREP,
            "PROMPT_INJECTION": IntentType.ATTACK_PREP,
            "DATA_EXFILTRATION": IntentType.DATA_EXFILTRATION,
            "PRIVILEGE_ESCALATION": IntentType.PRIVILEGE_ESCALATION,
            "RECONNAISSANCE": IntentType.ENUMERATION,
            "SUSPICIOUS_AUTOMATION": IntentType.EXPLORATION,
            "POLICY_EVASION": IntentType.ATTACK_PREP,
        }
        
        # Determine intent from primary risk categories
        primary_categories = response_data.get("primary_risk_categories", [])
        intent = IntentType.UNKNOWN
        
        # Priority order: most severe first
        priority_order = [
            "PRIVILEGE_ESCALATION",
            "DESTRUCTIVE_ACTION",
            "PROMPT_INJECTION",
            "DATA_EXFILTRATION",
            "REMOTE_COMMAND_EXECUTION",
            "ATTACK_PREP",
            "RECONNAISSANCE",
            "SUSPICIOUS_AUTOMATION",
            "POLICY_EVASION",
        ]
        
        for category in priority_order:
            if category in primary_categories:
                intent = category_to_intent.get(category, IntentType.UNKNOWN)
                if intent != IntentType.UNKNOWN:
                    break
        
        # If no match, check findings
        if intent == IntentType.UNKNOWN:
            findings = response_data.get("findings", [])
            for finding in findings:
                category = finding.get("category", "")
                if category in category_to_intent:
                    intent = category_to_intent[category]
                    break
        
        # Extract risk level (map SAFE to our enum)
        risk_level_str = response_data.get("risk_level", "LOW").upper()
        try:
            if risk_level_str == "SAFE":
                risk_level = RiskLevel.SAFE
            else:
                risk_level = RiskLevel(risk_level_str.lower())
        except ValueError:
            risk_level = RiskLevel.LOW
        
        # Enforce MEDIUM risk for DATA_EXFILTRATION and RECONNAISSANCE
        if "DATA_EXFILTRATION" in primary_categories or "RECONNAISSANCE" in primary_categories:
            risk_level = RiskLevel.MEDIUM
        
        # Apply rule: DESTRUCTIVE_ACTION or PROMPT_INJECTION cannot be LOW
        if risk_level == RiskLevel.LOW or risk_level == RiskLevel.SAFE:
            if any(cat in primary_categories for cat in ["DESTRUCTIVE_ACTION", "PROMPT_INJECTION"]):
                risk_level = RiskLevel.MEDIUM  # Minimum for destructive actions
        
        # Get confidence
        confidence = response_data.get("confidence", 0.5)
        if not isinstance(confidence, (int, float)):
            confidence = 0.5
        confidence = max(0.0, min(1.0, float(confidence)))
        
        # Build explanation from findings and overall explanation
        explanation_parts = []
        findings = response_data.get("findings", [])
        if findings:
            for finding in findings[:3]:  # Limit to first 3 findings
                category = finding.get("category", "")
                reason = finding.get("reason", "")
                if reason:
                    explanation_parts.append(f"{category}: {reason}")
        
        overall_explanation = response_data.get("explanation", "")
        if overall_explanation:
            explanation_parts.insert(0, overall_explanation)
        
        explanation = " | ".join(explanation_parts) if explanation_parts else "Sentinel Risk analysis"
        
        return {
            "intent": intent.value,
            "risk_level": risk_level.value,
            "confidence": confidence,
            "explanation": explanation,
            "risk_score": response_data.get("risk_score"),
            "primary_risk_categories": primary_categories,
            "findings": findings,
        }
    
    def _generate_finding_reason(self, intent: IntentType, category: str, event: EventDict) -> str:
        """Generate a reason for a finding based on intent and event."""
        file_path = event.get("file", "")
        command = " ".join(event.get("argv", [])) if event.get("argv") else event.get("cmd", "")
        host = event.get("host", "")
        
        reason_templates = {
            "DATA_EXFILTRATION": f"Network activity detected to external host {host}" if host else "Data transmission to external destination detected",
            "PRIVILEGE_ESCALATION": f"Privilege escalation attempt detected via {command}" if command else "Privilege escalation attempt detected",
            "DESTRUCTIVE_ACTION": f"Write operation to system file {file_path}" if file_path else "Destructive file operation detected",
            "RECONNAISSANCE": f"Information gathering activity: {command}" if command else "Reconnaissance activity detected",
            "SUSPICIOUS_AUTOMATION": f"Automated suspicious behavior detected: {command}" if command else "Suspicious automated activity detected",
            "PROMPT_INJECTION": "Potential prompt injection attempt detected",
            "POLICY_EVASION": "Attempt to evade security policies detected",
        }
        
        return reason_templates.get(category, f"{category} activity detected based on {intent.value} intent")

    def _generate_sentinel_explanation(self, intent: IntentType, risk_level: RiskLevel, 
                                      categories: list, event: EventDict, confidence: float) -> str:
        """Generate comprehensive explanation in Sentinel Risk format."""
        file_path = event.get("file", "")
        command = " ".join(event.get("argv", [])) if event.get("argv") else event.get("cmd", "")
        host = event.get("host", "")
        
        parts = []
        
        # Describe the action
        if file_path:
            mode = event.get("mode", "")
            if mode and "w" in mode:
                parts.append(f"Write operation to file: {file_path}")
            else:
                parts.append(f"Read operation on file: {file_path}")
        elif command:
            parts.append(f"Command execution: {command}")
        elif host:
            parts.append(f"Network connection to: {host}")
        
        # Describe the risk
        if categories:
            parts.append(f"Risk categories identified: {', '.join(categories)}")
        
        # Describe intent
        intent_descriptions = {
            IntentType.DATA_EXFILTRATION: "This activity indicates potential data exfiltration, where sensitive information may be transmitted to unauthorized destinations.",
            IntentType.PRIVILEGE_ESCALATION: "This activity suggests an attempt to gain elevated privileges, which could lead to unauthorized system access.",
            IntentType.REMOTE_COMMAND_EXECUTION: "This activity involves remote command execution, which poses significant security risks if unauthorized.",
            IntentType.ATTACK_PREP: "This activity appears to be preparation for an attack, involving potentially destructive operations.",
            IntentType.ENUMERATION: "This activity involves information gathering, which may be part of reconnaissance for potential attacks.",
            IntentType.EXPLORATION: "This activity involves system exploration, which may be benign but requires monitoring.",
            IntentType.BENIGN: "This activity appears to be normal system operation with low security risk.",
            IntentType.UNKNOWN: "The intent of this activity is unclear and requires further investigation.",
        }
        
        intent_desc = intent_descriptions.get(intent, "")
        if intent_desc:
            parts.append(intent_desc)
        
        # Add context about risk level
        risk_context = {
            RiskLevel.CRITICAL: "The risk level is CRITICAL, requiring immediate attention and response.",
            RiskLevel.HIGH: "The risk level is HIGH, indicating significant security concerns.",
            RiskLevel.MEDIUM: "The risk level is MEDIUM, suggesting moderate security concerns that should be monitored.",
            RiskLevel.LOW: "The risk level is LOW, indicating minimal security concerns.",
            RiskLevel.SAFE: "The risk level is SAFE, indicating normal operation.",
        }
        
        parts.append(risk_context.get(risk_level, ""))
        
        return " ".join(parts)

    def _generate_recommended_actions(self, intent: IntentType, risk_level: RiskLevel, 
                                      categories: list) -> list:
        """Generate recommended next actions based on intent and risk level."""
        actions = []
        
        if RiskLevel.CRITICAL in [risk_level] or "PRIVILEGE_ESCALATION" in categories:
            actions.append("Immediately investigate and block the source of this activity.")
            actions.append("Review system logs for related suspicious activities.")
            actions.append("Check for unauthorized privilege changes or access.")
        
        if "DATA_EXFILTRATION" in categories:
            actions.append("Verify the authorization and necessity of data transmission.")
            actions.append("Check for proper encryption and security measures during data transmission.")
            actions.append("Audit logs for any unusual patterns in data transfer.")
        
        if "DESTRUCTIVE_ACTION" in categories:
            actions.append("Verify the integrity of affected system files.")
            actions.append("Check for unauthorized modifications to critical system files.")
            actions.append("Review backup and recovery procedures.")
        
        if "RECONNAISSANCE" in categories or IntentType.ENUMERATION == intent:
            actions.append("Monitor for follow-up activities that may indicate attack progression.")
            actions.append("Review access controls and ensure proper authentication.")
        
        if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            actions.append("Consider isolating the affected system or process.")
            actions.append("Notify security team for further investigation.")
        
        if not actions:
            actions.append("Continue monitoring this activity for any escalation.")
            actions.append("Review security policies to ensure proper controls are in place.")
        
        return actions

    def _generate_uncertainties(self, intent: IntentType, confidence: float) -> list:
        """Generate uncertainty statements based on confidence and intent."""
        uncertainties = []
        
        if confidence < 0.6:
            uncertainties.append("The classification confidence is moderate, and there may be legitimate reasons for this activity.")
        
        if intent == IntentType.UNKNOWN:
            uncertainties.append("The intent of this activity is unclear and requires additional context.")
        
        if confidence < 0.5:
            uncertainties.append("The evidence for this classification is limited, and further investigation may be needed.")
        
        return uncertainties

    def _parse_text_response(self, text: str) -> Dict:
        """Parse text response from SLM into structured format (fallback).
        
        Args:
            text: Text response from SLM.
            
        Returns:
            Parsed classification dictionary.
        """
        text_lower = text.lower()
        
        # Extract intent
        intent = IntentType.UNKNOWN
        for intent_type in IntentType:
            if intent_type.value.lower() in text_lower:
                intent = intent_type
                break
        
        # Extract risk level
        risk_level = RiskLevel.LOW
        if "critical" in text_lower:
            risk_level = RiskLevel.CRITICAL
        elif "high" in text_lower:
            risk_level = RiskLevel.HIGH
        elif "medium" in text_lower:
            risk_level = RiskLevel.MEDIUM
        elif "safe" in text_lower:
            risk_level = RiskLevel.SAFE
        
        # Extract confidence (look for numbers)
        confidence = 0.5
        try:
            import re
            numbers = re.findall(r'\d+\.?\d*', text)
            if numbers:
                conf = float(numbers[0])
                if 0 <= conf <= 1:
                    confidence = conf
                elif 0 <= conf <= 100:
                    confidence = conf / 100.0
        except Exception:
            pass
        
        return {
            "intent": intent.value,
            "risk_level": risk_level.value,
            "confidence": confidence,
            "explanation": text[:200]  # First 200 chars
        }

    def classify(self, event: EventDict) -> IntentResult:
        """Classify an event using SLM.
        
        Args:
            event: Normalized event dictionary.
            
        Returns:
            IntentResult dictionary with SLM predictions.
        """
        prompt = self._event_to_prompt(event)
        start_time = time.perf_counter()
        backend_used: Optional[str] = None
        
        # Classify based on backend
        slm_result = None
        if self.backend == "ollama" and self.ollama_client:
            slm_result = self._classify_with_ollama(prompt, event)
            backend_used = "ollama"
        elif self.backend == "transformers" and self.transformer_model:
            slm_result = self._classify_with_transformers(prompt, event)
            backend_used = "transformers"
        elif self.backend == "auto":
            # Try Ollama first (better results), then Transformers
            if self.ollama_client:
                slm_result = self._classify_with_ollama(prompt, event)
                if slm_result:
                    LOGGER.debug("SLM classification using Ollama")
                    backend_used = "ollama"
            if not slm_result and self.transformer_model:
                slm_result = self._classify_with_transformers(prompt, event)
                if slm_result:
                    LOGGER.debug("SLM classification using Transformers")
                    backend_used = "transformers"
        
        # If SLM classification failed, fall back to rule-based
        if not slm_result:
            LOGGER.debug("SLM classification failed, using fallback")
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            fallback_result = self._fallback_classification(event)
            fallback_result["explanation"] = f"{fallback_result.get('explanation', 'Fallback classification')} | backend=fallback | duration_ms={duration_ms}ms"
            fallback_result["classification_backend"] = "fallback"
            fallback_result["classification_duration_ms"] = duration_ms
            return fallback_result
        
        duration_ms = int((time.perf_counter() - start_time) * 1000)
        backend_label = backend_used or self.backend or "unknown"
        # Simple console log for timing
        LOGGER.info("SLM classify backend=%s duration=%dms", backend_label, duration_ms)
        
        # Check if result is in Sentinel Risk schema format
        if "risk_score" in slm_result and "primary_risk_categories" in slm_result:
            # Already in Sentinel Risk format, parse it
            parsed = self._parse_sentinel_response(slm_result)
            intent_str = parsed.get("intent", "UNKNOWN")
            risk_str = parsed.get("risk_level", "low")
            confidence = float(parsed.get("confidence", 0.5))
            explanation = parsed.get("explanation", "SLM classification")
            # Preserve Sentinel Risk metadata
            sentinel_metadata = {
                "risk_score": parsed.get("risk_score"),
                "primary_risk_categories": parsed.get("primary_risk_categories", []),
                "findings": parsed.get("findings", []),
                "recommended_next_actions": parsed.get("recommended_next_actions", []),
                "uncertainties": parsed.get("uncertainties", []),
            }
        else:
            # Legacy format
            intent_str = slm_result.get("intent", "UNKNOWN")
            risk_str = slm_result.get("risk_level", "low")
            confidence = float(slm_result.get("confidence", 0.5))
            explanation = slm_result.get("explanation", "SLM classification")
            sentinel_metadata = {}
        
        slm_result["classification_backend"] = backend_label
        slm_result["classification_duration_ms"] = duration_ms
        
        # Map to enums
        try:
            intent = IntentType(intent_str.upper())
        except ValueError:
            intent = IntentType.UNKNOWN
        
        try:
            # Map common variations to RiskLevel enum
            risk_str_lower = risk_str.lower()
            if risk_str_lower in ["safe", "s"]:
                risk_level = RiskLevel.SAFE
            elif risk_str_lower in ["low", "l"]:
                risk_level = RiskLevel.LOW
            elif risk_str_lower in ["medium", "med", "m"]:
                risk_level = RiskLevel.MEDIUM
            elif risk_str_lower in ["high", "h"]:
                risk_level = RiskLevel.HIGH
            elif risk_str_lower in ["critical", "crit", "c"]:
                risk_level = RiskLevel.CRITICAL
            else:
                risk_level = RiskLevel(risk_str_lower)
        except ValueError:
            # Map risk level from score if enum conversion fails
            risk_score = RiskScorer.score_intent(intent)
            risk_level = RiskScorer.risk_level_from_score(risk_score)
        
        # Determine action type from event
        action_type = self._infer_action_type(event)
        
        # Compute final risk score
        risk_score = RiskScorer.compute_combined_risk(action_type, intent, event, confidence)
        final_risk_level = RiskScorer.risk_level_from_score(risk_score)
        
        # Enforce MEDIUM risk for DATA_EXFILTRATION and RECONNAISSANCE (ENUMERATION)
        # This ensures these categories always trigger LLM evaluation
        if intent == IntentType.DATA_EXFILTRATION or intent == IntentType.ENUMERATION:
            final_risk_level = RiskLevel.MEDIUM
        
        # CRITICAL OVERRIDE: Writing to critical file paths is ALWAYS CRITICAL
        # This overrides any SLM classification to ensure security
        override_applied = False
        if RiskScorer.is_critical_file_write(action_type, event):
            final_risk_level = RiskLevel.CRITICAL
            override_applied = True
            # Update explanation to note the override, but preserve Sentinel format
            if sentinel_metadata:
                # Add override to explanation while preserving structure
                explanation = f"{explanation} [OVERRIDE: Critical file write detected -> CRITICAL risk]"
                # Update risk_score and findings
                sentinel_metadata["risk_score"] = 95
                # Add override finding
                if "findings" in sentinel_metadata:
                    sentinel_metadata["findings"].append({
                        "category": "DESTRUCTIVE_ACTION",
                        "severity": "CRITICAL",
                        "evidence_event_ids": ["event_001"],
                        "reason": "Write operation to critical system file path detected - security override applied"
                    })
            else:
                explanation = f"{explanation} | OVERRIDE: Critical file write detected -> CRITICAL risk"
        
        # Build final explanation preserving Sentinel Risk format
        if sentinel_metadata and sentinel_metadata.get("findings"):
            # Format as comprehensive Sentinel Risk explanation
            explanation_parts = [explanation]
            
            # Add findings details
            findings = sentinel_metadata.get("findings", [])
            if findings:
                findings_text = " | ".join([
                    f"Finding: {f.get('category', '')} ({f.get('severity', '')}) - {f.get('reason', '')}"
                    for f in findings[:3]  # Limit to first 3 findings
                ])
                if findings_text:
                    explanation_parts.append(f"Findings: {findings_text}")
            
            # Add recommended actions
            recommended = sentinel_metadata.get("recommended_next_actions", [])
            if recommended:
                actions_text = "; ".join(recommended[:3])  # Limit to first 3
                if actions_text:
                    explanation_parts.append(f"Recommended actions: {actions_text}")
            
            # Add uncertainties if any
            uncertainties = sentinel_metadata.get("uncertainties", [])
            if uncertainties:
                uncertainties_text = "; ".join(uncertainties[:2])  # Limit to first 2
                if uncertainties_text:
                    explanation_parts.append(f"Uncertainties: {uncertainties_text}")
            
            enriched_explanation = " | ".join(explanation_parts)
        else:
            # Legacy format - add backend info
            enriched_explanation = f"SLM ({backend_label}): {explanation}"
        
        # Add timing info
        enriched_explanation = f"{enriched_explanation} | duration_ms={duration_ms}ms"

        return IntentResult(
            action_type=action_type,
            intent=intent,
            risk=final_risk_level,
            confidence=confidence,
            explanation=enriched_explanation,
            rule_matched=None,
            ml_confidence=confidence,
            classification_backend=backend_label,
            classification_duration_ms=duration_ms,
        )

    def _infer_action_type(self, event: EventDict) -> ActionType:
        """Infer action type from event.
        
        Args:
            event: Normalized event dictionary.
            
        Returns:
            ActionType enum.
        """
        event_type = event.get("event_type", "")
        mode = event.get("mode", "")
        
        if "file" in event_type.lower():
            # Check mode for write operations (w, a, +, or explicit "write" command)
            if (mode.startswith("w") or mode.startswith("a") or "+" in mode or 
                "write" in mode.lower() or "write" in event_type.lower()):
                return ActionType.FILE_WRITE
            return ActionType.FILE_READ
        elif "subprocess" in event_type.lower() or "process" in event_type.lower():
            return ActionType.SUBPROCESS_EXEC
        elif "network" in event_type.lower() or "socket" in event_type.lower():
            return ActionType.NETWORK_CONNECT
        elif "privilege" in event_type.lower() or "sudo" in str(event.get("argv", [])).lower():
            return ActionType.PRIVILEGE_ESCALATION
        
        return ActionType.UNKNOWN

    def _fallback_classification(self, event: EventDict) -> IntentResult:
        """Fallback classification using simple heuristics.
        
        Args:
            event: Normalized event dictionary.
            
        Returns:
            IntentResult dictionary.
        """
        action_type = self._infer_action_type(event)
        intent = IntentType.UNKNOWN
        
        # Simple heuristics
        if action_type == ActionType.FILE_READ:
            file_path = event.get("file", "")
            if any(risk in file_path for risk in ["/etc/", "/root/", "/proc/"]):
                intent = IntentType.ENUMERATION
            else:
                intent = IntentType.BENIGN
        elif action_type == ActionType.FILE_WRITE:
            file_path = event.get("file", "")
            if any(risk in file_path for risk in ["/etc/", "/root/", "/proc/", "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/"]):
                intent = IntentType.ATTACK_PREP
            else:
                intent = IntentType.EXPLORATION
        elif action_type == ActionType.NETWORK_CONNECT:
            host = event.get("host", "")
            if host and host not in ("127.0.0.1", "localhost"):
                intent = IntentType.DATA_EXFILTRATION
            else:
                intent = IntentType.BENIGN
        elif action_type == ActionType.SUBPROCESS_EXEC:
            cmd = " ".join(event.get("argv", []))
            if any(risk in cmd.lower() for risk in ["wget", "curl", "nc", "netcat"]):
                intent = IntentType.REMOTE_COMMAND_EXECUTION
            elif "sudo" in cmd.lower() or "su" in cmd.lower():
                intent = IntentType.PRIVILEGE_ESCALATION
            else:
                intent = IntentType.EXPLORATION
        
        risk_score = RiskScorer.compute_combined_risk(action_type, intent, event, 0.5)
        risk_level = RiskScorer.risk_level_from_score(risk_score)
        
        # CRITICAL OVERRIDE: Writing to critical file paths is ALWAYS CRITICAL
        if RiskScorer.is_critical_file_write(action_type, event):
            risk_level = RiskLevel.CRITICAL
            explanation = "Fallback classification (SLM unavailable) | OVERRIDE: Critical file write detected -> CRITICAL risk"
        else:
            explanation = "Fallback classification (SLM unavailable)"
        
        return IntentResult(
            action_type=action_type,
            intent=intent,
            risk=risk_level,
            confidence=0.5,
            explanation=explanation,
            rule_matched=None,
            ml_confidence=0.5,
        )

