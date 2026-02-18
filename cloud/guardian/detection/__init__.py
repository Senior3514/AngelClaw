"""AngelClaw – Guardian Detection Subsystem (V2.2).

Exports the three detection engines:
  - PatternDetector: known-dangerous event patterns (MITRE ATT&CK aligned)
  - AnomalyDetector: behavioral baseline deviation scoring
  - CorrelationEngine: cross-agent / cross-time kill-chain linkage
"""

from cloud.guardian.detection.anomaly import AnomalyDetector, anomaly_detector
from cloud.guardian.detection.correlator import CorrelationEngine, correlation_engine
from cloud.guardian.detection.patterns import PatternDetector, pattern_detector

__all__ = [
    "PatternDetector",
    "pattern_detector",
    "AnomalyDetector",
    "anomaly_detector",
    "CorrelationEngine",
    "correlation_engine",
]
