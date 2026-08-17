from datetime import datetime, timedelta

from detection.alert_manager import AlertManager
from detection.detection_result import DetectionResult


def make_result(
    source_ip,
    score,
    severity,
    reasons,
    detected=True,
):
    return DetectionResult(
        detected=detected,
        severity=severity,
        score=score,
        source_ip=source_ip,
        reasons=reasons,
    )


def main():

    manager = AlertManager(
        stale_after_seconds=60
    )

    start = datetime.now()

    # =========================================
    # 1. First detection
    # =========================================

    result_1 = make_result(
        source_ip="192.168.100.4",
        score=70,
        severity="HIGH",
        reasons=[
            "Port Scan detected",
        ],
    )

    alert_1 = manager.process(
        result_1,
        start,
    )

    assert alert_1 is not None
    assert alert_1.status == "OPEN"
    assert alert_1.occurrence_count == 1

    # =========================================
    # 2. Same detection after 10 seconds
    # =========================================

    result_2 = make_result(
        source_ip="192.168.100.4",
        score=85,
        severity="HIGH",
        reasons=[
            "Port Scan detected",
            "High SYN ratio",
        ],
    )

    alert_2 = manager.process(
        result_2,
        start + timedelta(seconds=10),
    )

    # Same incident
    assert alert_2 is alert_1

    assert alert_2.status == "OPEN"
    assert alert_2.occurrence_count == 2
    assert alert_2.risk_score == 85

    assert "High SYN ratio" in alert_2.reasons

    # =========================================
    # 3. 50 seconds after last detection
    # =========================================

    manager.resolve_stale_alerts(
        start + timedelta(seconds=60)
    )

    # Exactly 50 seconds since last_seen (t=10)
    assert alert_1.status == "OPEN"

    # =========================================
    # 4. 61 seconds after last detection
    # =========================================

    manager.resolve_stale_alerts(
        start + timedelta(seconds=71)
    )

    assert alert_1.status == "RESOLVED"

    # =========================================
    # 5. Same source + same detection
    #    after resolution
    # =========================================

    result_3 = make_result(
        source_ip="192.168.100.4",
        score=90,
        severity="HIGH",
        reasons=[
            "Port Scan detected",
        ],
    )

    alert_3 = manager.process(
        result_3,
        start + timedelta(seconds=80),
    )

    # This must be a NEW incident
    assert alert_3 is not alert_1

    assert alert_3.status == "OPEN"
    assert alert_3.occurrence_count == 1
    assert alert_3.risk_score == 90

    # =========================================
    # 6. Different source
    # =========================================

    result_4 = make_result(
        source_ip="192.168.100.5",
        score=80,
        severity="HIGH",
        reasons=[
            "Port Scan detected",
        ],
    )

    alert_4 = manager.process(
        result_4,
        start + timedelta(seconds=81),
    )

    assert alert_4 is not alert_3
    assert alert_4.source_ip == "192.168.100.5"

    # =========================================
    # 7. Different detection
    # =========================================

    result_5 = make_result(
        source_ip="192.168.100.4",
        score=90,
        severity="HIGH",
        reasons=[
            "High ICMP traffic rate",
        ],
    )

    alert_5 = manager.process(
        result_5,
        start + timedelta(seconds=82),
    )

    assert alert_5 is not alert_3
    assert alert_5.source_ip == "192.168.100.4"

    # =========================================
    # 8. Non-detection
    # =========================================

    result_6 = make_result(
        source_ip="192.168.100.6",
        score=0,
        severity="NONE",
        reasons=[],
        detected=False,
    )

    alert_6 = manager.process(
        result_6,
        start + timedelta(seconds=83),
    )

    assert alert_6 is None

    # =========================================
    # Final state
    # =========================================

    alerts = manager.get_alerts()

    print("\nFinal alerts:")

    for alert in alerts:
        print(alert)

    assert len(alerts) == 3

    print("\nAlert lifecycle test passed")


if __name__ == "__main__":
    main()