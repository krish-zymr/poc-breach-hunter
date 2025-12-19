"""ML-based intent classifier using offline embeddings."""
from __future__ import annotations

import math
from typing import Dict, List, Tuple

from intent_types import ActionType, EventDict, IntentResult, IntentType, RiskLevel
from risk_scorer import RiskScorer


class SimpleEmbedding:
    """Simple offline embedding using TF-IDF-like term weighting."""

    def __init__(self, vocabulary: Dict[str, int]):
        """Initialize with vocabulary.

        Args:
            vocabulary: Dictionary mapping terms to indices.
        """
        self.vocabulary = vocabulary
        self.vocab_size = len(vocabulary)

    def embed(self, text: str) -> List[float]:
        """Create a simple embedding vector from text.

        Uses term frequency weighting with inverse document frequency approximation.

        Args:
            text: Input text to embed.

        Returns:
            Embedding vector of length vocab_size.
        """
        text_lower = text.lower()
        words = text_lower.split()
        vector = [0.0] * self.vocab_size

        # Simple term frequency
        word_counts: Dict[str, int] = {}
        for word in words:
            word_counts[word] = word_counts.get(word, 0) + 1

        # Weight by position in vocabulary (simulating IDF)
        for word, count in word_counts.items():
            if word in self.vocabulary:
                idx = self.vocabulary[word]
                # Simple weighting: count * (1 / position_in_vocab)
                weight = count * (1.0 / (self.vocabulary[word] + 1))
                vector[idx] = weight

        # Normalize
        norm = math.sqrt(sum(x * x for x in vector))
        if norm > 0:
            vector = [x / norm for x in vector]

        return vector


class MLIntentModel:
    """Offline ML-based intent classifier using embeddings."""

    def __init__(self):
        """Initialize the ML model with synthetic training examples."""
        # Build vocabulary from training examples
        self.vocabulary: Dict[str, int] = {}
        self._build_vocabulary()

        # Initialize embedding model
        self.embedding = SimpleEmbedding(self.vocabulary)

        # Training examples: (event_description, intent, action_type)
        self.training_examples: List[Tuple[str, IntentType, ActionType]] = self._create_training_examples()

        # Pre-compute embeddings for training examples
        self.example_embeddings: List[Tuple[List[float], IntentType, ActionType]] = []
        for desc, intent, action_type in self.training_examples:
            emb = self.embedding.embed(desc)
            self.example_embeddings.append((emb, intent, action_type))

    def _build_vocabulary(self) -> None:
        """Build vocabulary from security-relevant terms."""
        terms = [
            # File operations
            "read",
            "write",
            "open",
            "file",
            "directory",
            "path",
            "system",
            "etc",
            "shadow",
            "passwd",
            "sudoers",
            "root",
            "tmp",
            "temp",
            # Network operations
            "network",
            "socket",
            "connect",
            "host",
            "port",
            "http",
            "https",
            "external",
            "localhost",
            "ip",
            # Subprocess operations
            "subprocess",
            "execute",
            "command",
            "shell",
            "bash",
            "sh",
            "wget",
            "curl",
            "nc",
            "netcat",
            "ssh",
            "scp",
            # Security terms
            "sudo",
            "su",
            "privilege",
            "escalation",
            "permission",
            "access",
            "denied",
            "allowed",
            # Intent terms
            "benign",
            "malicious",
            "attack",
            "exploit",
            "exfiltration",
            "enumeration",
            "reconnaissance",
        ]

        for idx, term in enumerate(terms):
            self.vocabulary[term] = idx

    def _create_training_examples(self) -> List[Tuple[str, IntentType, ActionType]]:
        """Create synthetic training examples.

        Returns:
            List of (description, intent, action_type) tuples.
        """
        examples = [
            # Benign file reads
            ("read file from tmp directory", IntentType.BENIGN, ActionType.FILE_READ),
            ("open file for reading user data", IntentType.BENIGN, ActionType.FILE_READ),
            ("read configuration file", IntentType.BENIGN, ActionType.FILE_READ),
            # Suspicious file reads
            ("read system file etc shadow", IntentType.ENUMERATION, ActionType.FILE_READ),
            ("open etc passwd file", IntentType.ENUMERATION, ActionType.FILE_READ),
            ("read root directory files", IntentType.ENUMERATION, ActionType.FILE_READ),
            # Benign file writes
            ("write file to tmp directory", IntentType.BENIGN, ActionType.FILE_WRITE),
            ("create temporary file", IntentType.BENIGN, ActionType.FILE_WRITE),
            # Suspicious file writes
            ("write to system path etc", IntentType.PRIVILEGE_ESCALATION, ActionType.FILE_WRITE),
            ("modify system file", IntentType.PRIVILEGE_ESCALATION, ActionType.FILE_WRITE),
            # Network operations
            ("connect to localhost", IntentType.BENIGN, ActionType.NETWORK_CONNECT),
            ("socket connection to 127.0.0.1", IntentType.BENIGN, ActionType.NETWORK_CONNECT),
            ("connect to external host http", IntentType.DATA_EXFILTRATION, ActionType.NETWORK_CONNECT),
            ("network connection to remote ip", IntentType.DATA_EXFILTRATION, ActionType.NETWORK_CONNECT),
            # Subprocess operations
            ("execute command echo", IntentType.BENIGN, ActionType.SUBPROCESS_EXEC),
            ("run subprocess ls", IntentType.EXPLORATION, ActionType.SUBPROCESS_EXEC),
            ("execute wget command", IntentType.REMOTE_COMMAND_EXECUTION, ActionType.SUBPROCESS_EXEC),
            ("run curl subprocess", IntentType.REMOTE_COMMAND_EXECUTION, ActionType.SUBPROCESS_EXEC),
            ("execute sudo command", IntentType.PRIVILEGE_ESCALATION, ActionType.PRIVILEGE_ESCALATION),
            ("run su subprocess", IntentType.PRIVILEGE_ESCALATION, ActionType.PRIVILEGE_ESCALATION),
        ]

        return examples

    def _cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        """Compute cosine similarity between two vectors.

        Args:
            vec1: First vector.
            vec2: Second vector.

        Returns:
            Cosine similarity score between -1.0 and 1.0.
        """
        if len(vec1) != len(vec2):
            return 0.0

        dot_product = sum(a * b for a, b in zip(vec1, vec2))
        norm1 = math.sqrt(sum(a * a for a in vec1))
        norm2 = math.sqrt(sum(a * a for a in vec2))

        if norm1 == 0.0 or norm2 == 0.0:
            return 0.0

        return dot_product / (norm1 * norm2)

    def _event_to_description(self, event: EventDict) -> str:
        """Convert event dictionary to text description.

        Args:
            event: Normalized event dictionary.

        Returns:
            Text description of the event.
        """
        parts = []

        event_type = event.get("event_type", "")
        parts.append(event_type)

        if event.get("file"):
            parts.append(f"file {event.get('file')}")
            if event.get("mode"):
                parts.append(f"mode {event.get('mode')}")

        if event.get("argv"):
            parts.append(" ".join(event.get("argv", [])))
        elif event.get("cmd"):
            parts.append(event.get("cmd", ""))

        if event.get("host"):
            parts.append(f"host {event.get('host')}")
            if event.get("port"):
                parts.append(f"port {event.get('port')}")

        return " ".join(parts)

    def classify(self, event: EventDict) -> IntentResult:
        """Classify an event using ML-based matching.

        Args:
            event: Normalized event dictionary.

        Returns:
            IntentResult dictionary with ML predictions.
        """
        # Convert event to description
        description = self._event_to_description(event)

        # Embed the description
        event_embedding = self.embedding.embed(description)

        # Find closest training example
        best_similarity = -1.0
        best_intent = IntentType.UNKNOWN
        best_action_type = ActionType.UNKNOWN

        for emb, intent, action_type in self.example_embeddings:
            similarity = self._cosine_similarity(event_embedding, emb)
            if similarity > best_similarity:
                best_similarity = similarity
                best_intent = intent
                best_action_type = action_type

        # Convert similarity to confidence (normalize to 0-1)
        confidence = max(0.0, min(1.0, (best_similarity + 1.0) / 2.0))

        # If similarity is too low, fall back to unknown
        if best_similarity < 0.3:
            best_intent = IntentType.UNKNOWN
            best_action_type = ActionType.UNKNOWN
            confidence = 0.2

        # Compute risk
        risk_score = RiskScorer.compute_combined_risk(best_action_type, best_intent, event, confidence)
        risk_level = RiskScorer.risk_level_from_score(risk_score)
        
        # CRITICAL OVERRIDE: Writing to critical file paths is ALWAYS CRITICAL
        if RiskScorer.is_critical_file_write(best_action_type, event):
            risk_level = RiskLevel.CRITICAL
            explanation = f"ML classification: {best_intent.value} (similarity: {best_similarity:.2f}, confidence: {confidence:.2f}) | OVERRIDE: Critical file write detected -> CRITICAL risk"
        else:
            explanation = f"ML classification: {best_intent.value} (similarity: {best_similarity:.2f}, confidence: {confidence:.2f})"

        return IntentResult(
            action_type=best_action_type,
            intent=best_intent,
            risk=risk_level,
            confidence=confidence,
            explanation=explanation,
            rule_matched=None,
            ml_confidence=confidence,
        )

