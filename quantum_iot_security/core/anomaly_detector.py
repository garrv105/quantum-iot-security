"""Lightweight anomaly detection for resource-constrained IoT environments.

Uses Isolation Forest and Local Outlier Factor for unsupervised anomaly detection
on network traffic features.
"""

from __future__ import annotations

import uuid
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler

from quantum_iot_security.core.models import AnomalyEvent, ThreatLevel


def _score_to_threat_level(score: float) -> ThreatLevel:
    """Map an anomaly score to a threat level."""
    if score < -0.5:
        return ThreatLevel.CRITICAL
    if score < -0.3:
        return ThreatLevel.HIGH
    if score < -0.1:
        return ThreatLevel.MEDIUM
    if score < 0.0:
        return ThreatLevel.LOW
    return ThreatLevel.INFO


class AnomalyDetector:
    """Lightweight anomaly detection engine for IoT network traffic.

    Supports two algorithms:
      - Isolation Forest: efficient for high-dimensional data
      - Local Outlier Factor: good for density-based anomalies

    The detector works on feature vectors extracted from traffic observations.
    """

    def __init__(
        self,
        algorithm: str = "isolation_forest",
        contamination: float = 0.1,
        n_estimators: int = 100,
        n_neighbors: int = 20,
    ) -> None:
        self._algorithm = algorithm
        self._contamination = contamination
        self._scaler = StandardScaler()
        self._fitted = False

        if algorithm == "isolation_forest":
            self._model = IsolationForest(
                n_estimators=n_estimators,
                contamination=contamination,
                random_state=42,
            )
        elif algorithm == "lof":
            self._model = LocalOutlierFactor(
                n_neighbors=n_neighbors,
                contamination=contamination,
                novelty=True,
            )
        else:
            raise ValueError(f"Unknown algorithm: {algorithm}. Use 'isolation_forest' or 'lof'.")

    @property
    def is_fitted(self) -> bool:
        return self._fitted

    def extract_features(self, traffic_data: list[dict[str, Any]]) -> np.ndarray:
        """Extract numeric features from raw traffic observations.

        Expected keys per observation:
            - packet_size: int
            - interval_ms: float
            - port: int
            - protocol_id: int (numeric encoding of protocol)
            - payload_entropy: float (optional, default 0.0)
        """
        features = []
        for obs in traffic_data:
            features.append([
                obs.get("packet_size", 0),
                obs.get("interval_ms", 0.0),
                obs.get("port", 0),
                obs.get("protocol_id", 0),
                obs.get("payload_entropy", 0.0),
            ])
        return np.array(features, dtype=np.float64)

    def fit(self, feature_matrix: np.ndarray) -> None:
        """Fit the anomaly detection model on normal traffic features."""
        if feature_matrix.shape[0] < 2:
            raise ValueError("Need at least 2 samples to fit the model.")
        scaled = self._scaler.fit_transform(feature_matrix)
        self._model.fit(scaled)
        self._fitted = True

    def predict(self, feature_matrix: np.ndarray) -> np.ndarray:
        """Predict anomaly labels: 1 = normal, -1 = anomaly."""
        if not self._fitted:
            raise RuntimeError("Model must be fitted before prediction.")
        scaled = self._scaler.transform(feature_matrix)
        return self._model.predict(scaled)

    def score_samples(self, feature_matrix: np.ndarray) -> np.ndarray:
        """Return anomaly scores. Lower (more negative) = more anomalous."""
        if not self._fitted:
            raise RuntimeError("Model must be fitted before scoring.")
        scaled = self._scaler.transform(feature_matrix)
        if hasattr(self._model, "score_samples"):
            return self._model.score_samples(scaled)
        return self._model.decision_function(scaled)

    def detect(
        self,
        device_id: str,
        traffic_data: list[dict[str, Any]],
    ) -> list[AnomalyEvent]:
        """Run anomaly detection on traffic and return AnomalyEvent objects."""
        if not self._fitted:
            raise RuntimeError("Model must be fitted before detection.")

        features = self.extract_features(traffic_data)
        labels = self.predict(features)
        scores = self.score_samples(features)

        events: list[AnomalyEvent] = []
        for i, (label, score) in enumerate(zip(labels, scores)):
            is_anomaly = bool(label == -1)
            event = AnomalyEvent(
                event_id=uuid.uuid4().hex[:12],
                device_id=device_id,
                anomaly_score=float(score),
                threat_level=_score_to_threat_level(float(score)),
                description=f"{'Anomaly' if is_anomaly else 'Normal'} traffic pattern detected",
                features={k: float(v) for k, v in zip(
                    ["packet_size", "interval_ms", "port", "protocol_id", "payload_entropy"],
                    features[i],
                )},
                is_anomaly=is_anomaly,
            )
            events.append(event)
        return events
