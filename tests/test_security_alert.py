from datetime import datetime

from detection.security_alert import SecurityAlert


def main():

    timestamp = datetime.now()

    alert = SecurityAlert(
        alert_id="TL-TEST001",

        source_ip="192.168.100.4",

        detection_type="Port Scan",

        severity="HIGH",

        risk_score=85,

        first_seen=timestamp,

        last_seen=timestamp,

        occurrence_count=1,

        reasons=[
            "High SYN connection-attempt rate",
            "High destination-port diversity",
        ],

        status="OPEN",
    )

    print("\nSecurity Alert:")
    print(alert)

    assert alert.alert_id == "TL-TEST001"

    assert alert.source_ip == (
        "192.168.100.4"
    )

    assert alert.detection_type == (
        "Port Scan"
    )

    assert alert.severity == "HIGH"

    assert alert.risk_score == 85

    assert alert.first_seen == timestamp

    assert alert.last_seen == timestamp

    assert alert.occurrence_count == 1

    assert len(alert.reasons) == 2

    assert alert.status == "OPEN"

    print("\nSecurity alert test passed")


if __name__ == "__main__":
    main()