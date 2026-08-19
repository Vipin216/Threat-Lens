from datetime import datetime
from uuid import uuid4

from detection.detection_result import DetectionResult
from detection.security_alert import SecurityAlert


class AlertManager:

    def __init__(
        self,
        stale_after_seconds: int = 60,
    ):
        self.stale_after_seconds = (
            stale_after_seconds
        )

        self._alerts: dict[
            tuple[str, str],
            SecurityAlert,
        ] = {}

    def process(
        self,
        result: DetectionResult,
        timestamp: datetime,
    ) -> SecurityAlert | None:

        if not result.detected:
            return None

        key = (
            result.source_ip,
            self._get_detection_type(result),
        )

        existing_alert = self._alerts.get(key)

        if existing_alert is None:

            alert = self._create_alert(
                result,
                timestamp,
            )

            self._alerts[key] = alert

            return alert

        if existing_alert.status == "RESOLVED":

            alert = self._create_alert(
                result,
                timestamp,
            )

            self._alerts[key] = alert

            return alert

        self._update_alert(
            existing_alert,
            result,
            timestamp,
        )

        return None

    def resolve_stale_alerts(
        self,
        current_time: datetime,
    ) -> None:

        for alert in self._alerts.values():

            if alert.status != "OPEN":
                continue

            elapsed = (
                current_time
                - alert.last_seen
            ).total_seconds()

            if (
                elapsed
                >= self.stale_after_seconds
            ):
                alert.status = "RESOLVED"

    def _create_alert(
        self,
        result: DetectionResult,
        timestamp: datetime,
    ) -> SecurityAlert:

        return SecurityAlert(
            alert_id=(
                f"TL-{uuid4().hex[:8].upper()}"
            ),
            source_ip=result.source_ip,
            detection_type=(
                self._get_detection_type(result)
            ),
            severity=result.severity,
            risk_score=result.score,
            first_seen=timestamp,
            last_seen=timestamp,
            occurrence_count=1,
            reasons=list(result.reasons),
            status="OPEN",
        )

    def _update_alert(
        self,
        alert: SecurityAlert,
        result: DetectionResult,
        timestamp: datetime,
    ) -> None:

        alert.last_seen = timestamp

        alert.occurrence_count += 1

        alert.risk_score = max(
            alert.risk_score,
            result.score,
        )

        alert.severity = self._higher_severity(
            alert.severity,
            result.severity,
        )

        for reason in result.reasons:

            if reason not in alert.reasons:
                alert.reasons.append(reason)

    @staticmethod
    def _get_detection_type(
        result: DetectionResult,
    ) -> str:

        if result.reasons:
            return result.reasons[0]

        return "Network Anomaly"

    @staticmethod
    def _higher_severity(
        current: str,
        new: str,
    ) -> str:

        levels = {
            "NONE": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }

        if levels.get(new, 0) > levels.get(
            current,
            0,
        ):
            return new

        return current

    def get_alerts(
        self,
    ) -> list[SecurityAlert]:

        return list(
            self._alerts.values()
        )