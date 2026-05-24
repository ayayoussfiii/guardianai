
import re
from dataclasses import dataclass
from enum import Enum


# ── Niveaux de menace ─────────────────────────────────────────────────────────

class ThreatLevel(str, Enum):
    SAFE     = "safe"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class ThreatType(str, Enum):
    JAILBREAK        = "jailbreak"
    PROMPT_INJECTION = "prompt_injection"
    PII_LEAK         = "pii_leak"
    SECRET_LEAK      = "secret_leak"
    NONE             = "none"


@dataclass
class ScanResult:
    threat_level   : ThreatLevel
    threat_type    : ThreatType
    matched_pattern: str | None
    confidence     : float
    details        : str


# ── Patterns jailbreak ────────────────────────────────────────────────────────

JAILBREAK_PATTERNS = [
    r"ignore (all |your |previous |prior )?(instructions|rules|guidelines)",
    r"you are now (DAN|AIM|STAN|DUDE|jailbreak)",
    r"act as (if you have no|an unrestricted|a jailbroken)",
    r"pretend (you are|to be) without (restrictions|limits|ethics)",
    r"forget (everything|all) you (know|were trained)",
    r"(enable|activate|unlock) (developer|god|jailbreak) mode",
    r"do anything now",
]

# ── Patterns injection de prompt ──────────────────────────────────────────────

INJECTION_PATTERNS = [
    r"<\|.*?\|>",
    r"\[INST\]|\[\/INST\]",
    r"###\s*(Instruction|System|Human|Assistant):",
    r"<(system|user|assistant)>",
    r"SYSTEM:\s*You are",
    r"ignore the above and (instead|now)",
]

# ── Patterns PII ──────────────────────────────────────────────────────────────

PII_PATTERNS = [
    (r"\b\d{3}-\d{2}-\d{4}\b",                                        "SSN"),
    (r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",                     "carte bancaire"),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",          "email"),
    (r"\b(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "téléphone"),
]

# ── Patterns secrets techniques ───────────────────────────────────────────────

SECRET_PATTERNS = [
    (r"sk-[a-zA-Z0-9]{48}",                  "OpenAI API key"),
    (r"ghp_[a-zA-Z0-9]{36}",                 "GitHub token"),
    (r"AKIA[0-9A-Z]{16}",                    "AWS Access Key"),
    (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "clé privée"),
    (r"(?i)(password|secret|api_key)\s*[:=]\s*\S+", "credential"),
]


# ── Scanner principal ─────────────────────────────────────────────────────────

class PromptScanner:

    def __init__(self):
        self._jailbreak  = [re.compile(p, re.IGNORECASE) for p in JAILBREAK_PATTERNS]
        self._injection  = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in INJECTION_PATTERNS]
        self._pii        = [(re.compile(p), label) for p, label in PII_PATTERNS]
        self._secrets    = [(re.compile(p), label) for p, label in SECRET_PATTERNS]

    def scan(self, text: str) -> ScanResult:

        # 1. Secrets → CRITICAL
        for pattern, label in self._secrets:
            if pattern.search(text):
                return ScanResult(
                    threat_level=ThreatLevel.CRITICAL,
                    threat_type=ThreatType.SECRET_LEAK,
                    matched_pattern=label,
                    confidence=0.99,
                    details=f"Secret détecté : {label}",
                )

        # 2. Jailbreak → HIGH
        for pattern in self._jailbreak:
            match = pattern.search(text)
            if match:
                return ScanResult(
                    threat_level=ThreatLevel.HIGH,
                    threat_type=ThreatType.JAILBREAK,
                    matched_pattern=match.group(),
                    confidence=0.95,
                    details=f"Jailbreak détecté : '{match.group()}'",
                )

        # 3. Injection → HIGH
        for pattern in self._injection:
            match = pattern.search(text)
            if match:
                return ScanResult(
                    threat_level=ThreatLevel.HIGH,
                    threat_type=ThreatType.PROMPT_INJECTION,
                    matched_pattern=match.group(),
                    confidence=0.90,
                    details=f"Injection détectée : '{match.group()}'",
                )

        # 4. PII → MEDIUM
        for pattern, label in self._pii:
            if pattern.search(text):
                return ScanResult(
                    threat_level=ThreatLevel.MEDIUM,
                    threat_type=ThreatType.PII_LEAK,
                    matched_pattern=label,
                    confidence=0.85,
                    details=f"Donnée personnelle détectée : {label}",
                )

        # ✅ Rien trouvé
        return ScanResult(
            threat_level=ThreatLevel.SAFE,
            threat_type=ThreatType.NONE,
            matched_pattern=None,
            confidence=1.0,
            details="Aucune menace détectée",
        )
