"""AI / IDS module — Phase 3 contributes the feature extractor; the
Random Forest classifier itself lands in Phase 4.

Importing this package today gives you `FeatureExtractor` only.
"""

from .feature_extractor import FeatureExtractor, FrameRecord

__all__ = ["FeatureExtractor", "FrameRecord"]
