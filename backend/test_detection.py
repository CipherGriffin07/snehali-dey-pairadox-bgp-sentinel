
import pytest

from detector import BGPDetector
from risk import calculate_risk


@pytest.fixture
def detector(tmp_path, monkeypatch):
    import storage

    monkeypatch.setattr(
        storage, "DB_PATH", tmp_path / "test.db"
    )

    return BGPDetector()


def test_valid_origin(detector):
    result = detector.analyze(
        "203.0.113.0/24", 64500
    )

    assert result["anomaly_detected"] is False
    assert result["rpki"]["status"] == "VALID"


def test_origin_change(detector):
    detector.analyze("203.0.113.0/24", 64500)

    result = detector.analyze(
        "203.0.113.0/24", 64599
    )

    types = {
        a["type"] for a in result["anomalies"]
    }

    assert "ORIGIN_CHANGE" in types
    assert "RPKI_INVALID" in types


def test_subprefix_anomaly(detector):
    detector.analyze("203.0.113.0/24", 64500)

    result = detector.analyze(
        "203.0.113.0/25", 64598
    )

    types = {
        a["type"] for a in result["anomalies"]
    }

    assert "SUBPREFIX_ANOMALY" in types


def test_rpki_invalid(detector):
    result = detector.analyze(
        "203.0.113.0/24", 64599
    )

    assert result["rpki"]["status"] == "INVALID"
    assert result["risk"]["score"] >= 50


def test_risk_score_cap():
    anomalies = [
        {"type": "ORIGIN_CHANGE"},
        {"type": "SUBPREFIX_ANOMALY"},
        {"type": "RPKI_INVALID"}
    ]

    result = calculate_risk(anomalies, "INVALID")

    assert result["score"] == 100
    assert result["level"] == "CRITICAL"


def test_persistence(detector):
    detector.analyze("203.0.113.0/24", 64500)
    detector.analyze("203.0.113.0/24", 64599)

    restored = BGPDetector()

    assert restored.routes["203.0.113.0/24"] == 64599
    assert len(restored.alerts) == 2
