"""
Middleware de sécurité — point d'entrée public du package.

Pipeline :
    Scanner ──► Filter ──► Detector

Chaque composant est indépendant et peut être utilisé seul,
ou enchaîné dans l'ordre recommandé ci-dessus.

Usage rapide :
    from middleware import Scanner, Filter, Detector
    from middleware import ScanResult, FilterResult, DetectionResult

    result = Scanner().scan(data)
    if result.is_clean:
        filtered = Filter().apply(result)
        verdict  = Detector().analyse(filtered)
"""

from .scanner  import Scanner,  ScanResult
from .filter   import Filter,   FilterResult
from .detector import Detector, DetectionResult

__all__ = [
    # Composants du pipeline
    "Scanner",
    "Filter",
    "Detector",
    # Types de retour
    "ScanResult",
    "FilterResult",
    "DetectionResult",
]
