"""Tests for anomaly detection engine."""

from __future__ import annotations

import numpy as np
import pytest

from quantum_iot_security.core.anomaly_detector import AnomalyDetector


class TestAnomalyDetector:
    def test_fit_and_predict(self, fitted_detector: AnomalyDetector):
        """Fitted detector should return predictions."""
        test_data = np.array([[100, 50, 80, 1, 3.0]])
        labels = fitted_detector.predict(test_data)
        assert labels.shape == (1,)
        assert labels[0] in (1, -1)

    def test_detect_obvious_anomaly(self, fitted_detector: AnomalyDetector):
        """Extreme outlier should be detected as anomaly."""
        outlier = np.array([[9999, 0.001, 60000, 99, 8.0]])
        labels = fitted_detector.predict(outlier)
        assert labels[0] == -1

    def test_normal_traffic_passes(self, fitted_detector: AnomalyDetector):
        """Normal-range data should not be flagged."""
        normal = np.array([[100, 50, 80, 1, 3.0]])
        labels = fitted_detector.predict(normal)
        assert labels[0] == 1

    def test_score_samples(self, fitted_detector: AnomalyDetector):
        """Score samples should return numeric scores."""
        data = np.array([[100, 50, 80, 1, 3.0], [9999, 0, 60000, 99, 8.0]])
        scores = fitted_detector.score_samples(data)
        assert scores.shape == (2,)
        # Outlier should have lower score
        assert scores[1] < scores[0]

    def test_detect_returns_events(self, fitted_detector: AnomalyDetector):
        """detect() should return AnomalyEvent objects."""
        traffic = [
            {"packet_size": 100, "interval_ms": 50, "port": 80, "protocol_id": 1, "payload_entropy": 3.0},
            {"packet_size": 9999, "interval_ms": 0, "port": 60000, "protocol_id": 99, "payload_entropy": 8.0},
        ]
        events = fitted_detector.detect("device-001", traffic)
        assert len(events) == 2
        assert events[1].is_anomaly is True
        assert events[1].device_id == "device-001"

    def test_unfitted_raises(self):
        """Using an unfitted detector should raise RuntimeError."""
        detector = AnomalyDetector()
        with pytest.raises(RuntimeError, match="fitted"):
            detector.predict(np.array([[1, 2, 3, 4, 5]]))

    def test_lof_algorithm(self):
        """LOF algorithm should also work."""
        detector = AnomalyDetector(algorithm="lof", n_neighbors=5)
        rng = np.random.RandomState(42)
        data = rng.normal(size=(50, 5))
        detector.fit(data)
        labels = detector.predict(data[:5])
        assert labels.shape == (5,)

    def test_invalid_algorithm(self):
        """Invalid algorithm name should raise ValueError."""
        with pytest.raises(ValueError, match="Unknown algorithm"):
            AnomalyDetector(algorithm="invalid")

    def test_extract_features(self):
        """Feature extraction should produce correct shape."""
        detector = AnomalyDetector()
        traffic = [
            {"packet_size": 100, "interval_ms": 50, "port": 80, "protocol_id": 1, "payload_entropy": 3.0},
        ]
        features = detector.extract_features(traffic)
        assert features.shape == (1, 5)
