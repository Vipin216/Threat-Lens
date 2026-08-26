import json
import os
from datetime import datetime, timezone


class WazuhClient:
    

    def __init__(self, log_path=None):
        self.log_path = log_path or os.getenv(
            "THREATLENS_WAZUH_LOG",
            "logs/threatlens_alerts.json"
        )

        log_dir = os.path.dirname(self.log_path)

        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

    def send_alert(
        self,
        alert,
        enrichment,
        feature_vector,
    ) -> None:

        event = {
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),

            "source": "ThreatLens",

            "alert_id": alert.alert_id,

            "source_ip": (
                alert.source_ip
            ),

            "detection_type": (
                alert.detection_type
            ),

            "risk_score": (
                alert.risk_score
            ),

            "severity": (
                alert.severity
            ),

            "status": (
                alert.status
            ),

            "occurrence_count": (
                alert.occurrence_count
            ),

            "detection_reasons": (
                alert.reasons
            ),

            "ai_enrichment": {
                "attack_type": (
                    enrichment.get(
                        "attack_type"
                    )
                ),

                "severity": (
                    enrichment.get(
                        "severity"
                    )
                ),

                "confidence": (
                    enrichment.get(
                        "confidence"
                    )
                ),

                "mitre_attack_id": (
                    enrichment.get(
                        "mitre_attack_id"
                    )
                ),

                "mitre_attack_name": (
                    enrichment.get(
                        "mitre_attack_name"
                    )
                ),

                "summary": (
                    enrichment.get(
                        "summary"
                    )
                ),

                "recommendations": (
                    enrichment.get(
                        "recommendations",
                        [],
                    )
                ),
            },

            "network_features": {
                "flow_packet_count": (
                    feature_vector.flow_packet_count
                ),

                "flow_packets_per_second": (
                    feature_vector.flow_packets_per_second
                ),

                "unique_destination_ips": (
                    feature_vector.unique_destination_ips
                ),

                "unique_destination_ports": (
                    feature_vector.unique_destination_ports
                ),

                "sensitive_port_count": (
                    feature_vector.sensitive_port_count
                ),

                "window_icmp_packet_count": (
                    feature_vector.window_icmp_packet_count
                ),

                "window_icmp_request_count": (
                    feature_vector.window_icmp_request_count
                ),

                "window_icmp_reply_count": (
                    feature_vector.window_icmp_reply_count
                ),
            },
        }

        with open(
            self.log_path,
            "a",
            encoding="utf-8",
        ) as log_file:

            log_file.write(
                json.dumps(
                    event,
                    separators=(",", ":")
                )
                + "\n"
            )