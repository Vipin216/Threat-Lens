import json
import os
from datetime import datetime, timezone


class WazuhLogger:

    LOG_DIR = "/var/log/threatlens"
    LOG_FILE = os.path.join(
        LOG_DIR,
        "alerts.json"
    )

    def __init__(self):
        self._ensure_log_directory()

    def _ensure_log_directory(self):
        os.makedirs(
            self.LOG_DIR,
            exist_ok=True
        )

    def log_alert(
        self,
        alert,
        result,
        feature_vector,
        airia_result,
    ) -> None:

        event = {
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),

            "event_type": "threatlens_alert",

            # ==========================
            # ThreatLens identity
            # ==========================

            "threatlens": {
                "alert_id": alert.alert_id,
                "detection_type": alert.detection_type,
                "status": alert.status,
                "occurrence_count": (
                    alert.occurrence_count
                ),
                "risk_score": alert.risk_score,
                "severity": alert.severity,
                "reasons": alert.reasons,
            },

            # ==========================
            # Network information
            # ==========================

            "network": {
                "source_ip": (
                    feature_vector.source_ip
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
            },

            # ==========================
            # Traffic statistics
            # ==========================

            "traffic": {
                "packet_count": (
                    feature_vector.flow_packet_count
                ),
                "byte_count": (
                    feature_vector.flow_byte_count
                ),
                "packets_per_second": (
                    feature_vector.flow_packets_per_second
                ),
                "bytes_per_second": (
                    feature_vector.flow_bytes_per_second
                ),
                "syn_ratio": (
                    feature_vector.flow_syn_ratio
                ),
                "ack_ratio": (
                    feature_vector.flow_ack_ratio
                ),
                "rst_ratio": (
                    feature_vector.flow_rst_ratio
                ),
            },

            # ==========================
            # Window statistics
            # ==========================

            "window": {
                "packet_count": (
                    feature_vector.window_packet_count
                ),
                "flow_count": (
                    feature_vector.window_flow_count
                ),
                "packets_per_second": (
                    feature_vector.window_packets_per_second
                ),
                "flows_per_second": (
                    feature_vector.window_flows_per_second
                ),
                "icmp_packet_count": (
                    feature_vector.window_icmp_packet_count
                ),
                "icmp_request_count": (
                    feature_vector.window_icmp_request_count
                ),
                "icmp_reply_count": (
                    feature_vector.window_icmp_reply_count
                ),
                "icmp_request_ratio": (
                    feature_vector.window_icmp_request_ratio
                ),
            },

            # ==========================
            # Airia AI enrichment
            # ==========================

            "ai_enrichment": {
                "attack_type": (
                    airia_result.get(
                        "attack_type"
                    )
                ),
                "severity": (
                    airia_result.get(
                        "severity"
                    )
                ),
                "confidence": (
                    airia_result.get(
                        "confidence"
                    )
                ),
                "mitre_attack_id": (
                    airia_result.get(
                        "mitre_attack_id"
                    )
                ),
                "mitre_attack_name": (
                    airia_result.get(
                        "mitre_attack_name"
                    )
                ),
                "summary": (
                    airia_result.get(
                        "summary"
                    )
                ),
                "recommendations": (
                    airia_result.get(
                        "recommendations",
                        []
                    )
                ),
            },
        }

        with open(
            self.LOG_FILE,
            "a",
            encoding="utf-8",
        ) as log_file:

            log_file.write(
                json.dumps(
                    event,
                    separators=(
                        ",",
                        ":"
                    )
                )
                + "\n"
            )