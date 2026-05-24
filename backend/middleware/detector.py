"""
detector.py — Classifier ML pour détecter les intentions malveillantes
Deuxième ligne de défense, basé sur un modèle léger HuggingFace
"""

from __future__ import annotations
from dataclasses import dataclass
from .scanner import ThreatLevel, ThreatType, ScanResult


@dataclass
class DetectionResult:
    threat_level: ThreatLevel
    threat_type : ThreatType
    confidence  : float
    details     : str




SUSPICIOUS_KEYWORDS = {
    ThreatType.JAILBREAK: [
        "jailbreak", "bypass", "unrestricted", "no limits", "no rules",
        "override", "ignore instructions", "disregard", "without restrictions",
        "as an AI without", "you are free to",
    ],
    ThreatType.PROMPT_INJECTION: [
        "new instructions", "updated instructions", "your real instructions",
        "hidden instructions", "secret prompt", "system prompt", "ignore previous",
        "disregard above", "forget previous",
    ],
}


CONFIDENCE_THRESHOLD = 0.70


class IntentDetector:

    def __init__(self, use_ml: bool = False):
        """
        use_ml=False  → mode heuristique (rapide, pas de dépendances)
        use_ml=True   → mode ML avec HuggingFace (plus précis, plus lent)
        """
        self.use_ml = use_ml
        self._model = None

        if use_ml:
            self._load_model()

    def _load_model(self):
        """Charge le modèle HuggingFace (lazy loading)."""
        try:
            from transformers import pipeline
            self._model = pipeline(
                "text-classification",
                model="martin-ha/toxic-comment-model",
                truncation=True,
                max_length=512,
            )
        except ImportError:
            print("[GuardianAI] transformers non installé, fallback heuristique.")
            self.use_ml = False

    def detect(self, text: str) -> DetectionResult:
        """Analyse l'intention du texte."""
        if self.use_ml and self._model:
            return self._detect_ml(text)
        return self._detect_heuristic(text)

    def _detect_heuristic(self, text: str) -> DetectionResult:
        """Détection par mots-clés pondérés."""
        text_lower = text.lower()
        scores: dict[ThreatType, float] = {}

        for threat_type, keywords in SUSPICIOUS_KEYWORDS.items():
            matches = sum(1 for kw in keywords if kw in text_lower)
            if matches:
                scores[threat_type] = min(0.5 + (matches * 0.15), 0.95)

        if not scores:
            return DetectionResult(
                threat_level=ThreatLevel.SAFE,
                threat_type=ThreatType.NONE,
                confidence=1.0,
                details="Intention normale détectée",
            )

        top_threat = max(scores, key=lambda t: scores[t])
        confidence = scores[top_threat]

        level = ThreatLevel.HIGH if confidence >= CONFIDENCE_THRESHOLD else ThreatLevel.LOW

        return DetectionResult(
            threat_level=level,
            threat_type=top_threat,
            confidence=confidence,
            details=f"Intention suspecte ({top_threat.value}), confiance : {confidence:.0%}",
        )

    def _detect_ml(self, text: str) -> DetectionResult:
        """Détection via modèle ML HuggingFace."""
        result = self._model(text)[0]
        label      = result["label"]
        confidence = result["score"]

        is_threat = label == "toxic" and confidence >= CONFIDENCE_THRESHOLD

        return DetectionResult(
            threat_level=ThreatLevel.HIGH if is_threat else ThreatLevel.SAFE,
            threat_type=ThreatType.JAILBREAK if is_threat else ThreatType.NONE,
            confidence=confidence,
            details=f"Modèle ML → label: {label}, confiance: {confidence:.0%}",
        )
