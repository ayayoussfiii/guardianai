"""
backend/middleware/__init__.py
──────────────────────────────
Point d'entrée du package middleware.

Expose les trois composants du pipeline de sécurité ainsi que
leurs types publics pour simplifier les imports dans le reste
de l'application :

    from middleware import Scanner, Filter, Detector
    from middleware import ScanResult, FilterResult, DetectionResult
"""

from .scanner  import Scanner,  ScanResult
from .filter   import Filter,   FilterResult
from .detector import Detector, DetectionResult

__all__ = [
    # Classes
    "Scanner",
    "Filter",
    "Detector",
    # Types
    "ScanResult",
    "FilterResult",
    "DetectionResult",
]
