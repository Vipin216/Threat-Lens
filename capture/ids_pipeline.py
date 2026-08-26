from capture.tshark_capture import TsharkCapture

from processing.flow_manager import FlowManager
from processing.parser import PacketParser

from detection.traffic_window import TrafficWindow
from detection.features import FeatureExtractor
from detection.window_features import WindowFeatureExtractor
from detection.feature_vector import FeatureVectorBuilder
from detection.detection_context import DetectionContext
from detection.detection_engine import DetectionEngine
from detection.detection_scheduler import DetectionScheduler
from detection.alert_manager import AlertManager

from ai.airia_client import AiriaClient
from integrations.wazuh_logger import WazuhLogger


class IDSPipeline:

    def __init__(self, interface: str):

        self.capture = TsharkCapture(interface)

        self.parser = PacketParser()

        self.flow_manager = FlowManager()

        self.traffic_window = TrafficWindow(
            window_seconds=60
        )

        self.flow_feature_extractor = (
            FeatureExtractor()
        )

        self.window_feature_extractor = (
            WindowFeatureExtractor(
                window_seconds=60
            )
        )

        self.feature_vector_builder = (
            FeatureVectorBuilder()
        )

        self.detection_context = (
            DetectionContext(
                window_seconds=60
            )
        )

        self.detection_engine = (
            DetectionEngine()
        )

        self.scheduler = DetectionScheduler(
            interval_seconds=1,
            packet_threshold=50,
        )

        self.alert_manager = AlertManager(
            stale_after_seconds=60
        )

        # ==================================
        # Airia AI enrichment client
        # ==================================

        self.airia_client = AiriaClient()

        # ==================================
        # Wazuh security event logger
        # ==================================

        self.wazuh_logger = WazuhLogger()

    def run(self) -> None:

        print(
            f"[+] Starting IDS capture on "
            f"{self.capture.interface}"
        )

        for raw_line in (
            self.capture.stream_packets()
        ):

            packet = self.parser.parse(
                raw_line
            )

            if packet is None:
                continue

            # ==================================
            # Add packet to traffic window
            # ==================================

            self.traffic_window.add_packet(
                packet
            )

            # ==================================
            # Process packet into flows
            # ==================================

            self.flow_manager.process_packet(
                packet
            )

            # ==================================
            # Periodic detection snapshot
            # ==================================

            if self.scheduler.should_run():

                print(
                    "\n[DEBUG] Running "
                    "detection snapshot"
                )

                self._run_detection_snapshot(
                    packet.timestamp
                )

            # ==================================
            # Expire inactive flows
            # ==================================

            expired_flows = (
                self.flow_manager.expire_flows(
                    packet.timestamp
                )
            )

            for flow in expired_flows:

                self._handle_expired_flow(
                    flow
                )

            # ==================================
            # Resolve stale alerts
            # ==================================

            self.alert_manager.resolve_stale_alerts(
                packet.timestamp
            )

    def _run_detection_snapshot(
        self,
        timestamp,
    ) -> None:

        source_ips = (
            self.traffic_window
            .get_active_sources()
        )

        print(
            f"[DEBUG] Active window sources: "
            f"{len(source_ips)}"
        )

        for source_ip in source_ips:

            # ==================================
            # Window statistics
            # ==================================

            stats = (
                self.traffic_window
                .get_stats(source_ip)
            )

            window_features = (
                self.window_feature_extractor
                .extract(stats)
            )

            # ==================================
            # Find active flows belonging
            # to this source
            # ==================================

            active_flows = [

                flow

                for flow in (
                    self.flow_manager
                    .get_active_flows()
                )

                if flow.src_ip == source_ip
            ]

            if not active_flows:
                continue

            # ==================================
            # Select latest active flow
            # ==================================

            latest_flow = max(
                active_flows,
                key=lambda flow: flow.last_seen,
            )

            # ==================================
            # Extract flow features
            # ==================================

            flow_features = (
                self.flow_feature_extractor
                .extract_flow_features(
                    latest_flow
                )
            )

            print(
                f"[DEBUG] {source_ip} | "
                f"packets={stats.packet_count} | "
                f"pps="
                f"{window_features.packets_per_second:.2f} | "
                f"ports="
                f"{window_features.unique_destination_ports} | "
                f"syn_ratio="
                f"{window_features.syn_ratio:.2f} | "
                f"syns/sec="
                f"{window_features.syns_per_second:.2f}"
            )

            # ==================================
            # Build feature vector
            # ==================================

            feature_vector = (
                self.feature_vector_builder.build(
                    flow_features,
                    window_features,
                )
            )

            # ==================================
            # Add vector to detection context
            # ==================================

            self.detection_context.add(
                feature_vector,
                timestamp,
            )

        # ==================================
        # Run detection engine
        # ==================================

        results = (
            self.detection_engine.detect(
                self.detection_context
            )
        )

        print(
            f"[DEBUG] Detection results: "
            f"{len(results)}"
        )

        for result in results:

            print(
                f"[DEBUG] Detection: "
                f"{result.source_ip} | "
                f"score={result.score} | "
                f"detected={result.detected}"
            )

            # ==================================
            # Ignore non-detections
            # ==================================

            if not result.detected:
                continue

            # ==================================
            # Create/update security alert
            # ==================================

            alert = (
                self.alert_manager.process(
                    result,
                    timestamp,
                )
            )

            if alert is None:
                continue

            # ==================================
            # Print alert
            # ==================================

            self._print_alert(alert)

            # ==================================
            # Get latest feature vector
            # for this source
            # ==================================

            source_vectors = (
                self.detection_context
                .get_source_vectors(
                    result.source_ip
                )
            )

            if not source_vectors:

                print(
                    "[AIRIA] No feature vector "
                    "available for enrichment"
                )

                continue

            latest_vector = source_vectors[-1]

            # ==================================
            # Airia enrichment
            # ==================================

            self._enrich_with_airia(
                alert,
                result,
                latest_vector,
            )

    def _enrich_with_airia(
        self,
        alert,
        result,
        feature_vector,
    ) -> None:

        print(
            "\n[AIRIA] Sending alert for "
            "AI enrichment..."
        )

        # ==================================
        # Prepare Airia input
        # ==================================

        airia_input = {

            # ==============================
            # Network identity
            # ==============================

            "source_ip": (
                feature_vector.source_ip
            ),

            # ==============================
            # Detection result
            # ==============================

            "detected": result.detected,

            "risk_score": result.score,

            "severity": result.severity,

            "detection_type": (
                alert.detection_type
            ),

            "occurrence_count": (
                alert.occurrence_count
            ),

            "detections": alert.reasons,

            # ==============================
            # Flow features
            # ==============================

            "flow_packet_count": (
                feature_vector.flow_packet_count
            ),

            "flow_byte_count": (
                feature_vector.flow_byte_count
            ),

            "flow_duration": (
                feature_vector.flow_duration
            ),

            "flow_packets_per_second": (
                feature_vector.flow_packets_per_second
            ),

            "flow_bytes_per_second": (
                feature_vector.flow_bytes_per_second
            ),

            # ==============================
            # TCP behavior
            # ==============================

            "syns_per_second": (
                feature_vector.syns_per_second
            ),

            "flow_syn_ratio": (
                feature_vector.flow_syn_ratio
            ),

            "flow_ack_ratio": (
                feature_vector.flow_ack_ratio
            ),

            "flow_rst_ratio": (
                feature_vector.flow_rst_ratio
            ),

            "flow_fin_ratio": (
                feature_vector.flow_fin_ratio
            ),

            # ==============================
            # Window statistics
            # ==============================

            "window_packet_count": (
                feature_vector.window_packet_count
            ),

            "window_byte_count": (
                feature_vector.window_byte_count
            ),

            "window_flow_count": (
                feature_vector.window_flow_count
            ),

            "window_packets_per_second": (
                feature_vector.window_packets_per_second
            ),

            "window_bytes_per_second": (
                feature_vector.window_bytes_per_second
            ),

            "window_flows_per_second": (
                feature_vector.window_flows_per_second
            ),

            # ==============================
            # Network scanning indicators
            # ==============================

            "unique_destination_ips": (
                feature_vector.unique_destination_ips
            ),

            "unique_destination_ports": (
                feature_vector.unique_destination_ports
            ),

            "sensitive_port_count": (
                feature_vector.sensitive_port_count
            ),

            "ports_per_second": (
                feature_vector.ports_per_second
            ),

            "ips_per_second": (
                feature_vector.ips_per_second
            ),

            # ==============================
            # ICMP behavior
            # ==============================

            "window_icmp_packet_count": (
                feature_vector.window_icmp_packet_count
            ),

            "window_icmp_request_count": (
                feature_vector.window_icmp_request_count
            ),

            "window_icmp_reply_count": (
                feature_vector.window_icmp_reply_count
            ),

            "window_icmp_ratio": (
                feature_vector.window_icmp_ratio
            ),

            "window_icmp_request_ratio": (
                feature_vector.window_icmp_request_ratio
            ),

            # ==============================
            # TCP window behavior
            # ==============================

            "window_tcp_packet_count": (
                feature_vector.window_tcp_packet_count
            ),

            "window_syn_ratio": (
                feature_vector.window_syn_ratio
            ),

            "window_ack_ratio": (
                feature_vector.window_ack_ratio
            ),

            "window_rst_ratio": (
                feature_vector.window_rst_ratio
            ),
        }

        try:

            # ==================================
            # Step 1
            # Send alert to Airia
            # ==================================

            enrichment = (
                self.airia_client.analyze(
                    airia_input
                )
            )

            print(
                "\n[AIRIA] AI enrichment received"
            )

            print(
                f"  Attack Type : "
                f"{enrichment.get('attack_type')}"
            )

            print(
                f"  Severity    : "
                f"{enrichment.get('severity')}"
            )

            print(
                f"  Confidence  : "
                f"{enrichment.get('confidence')}"
            )

            print(
                f"  MITRE ID    : "
                f"{enrichment.get('mitre_attack_id')}"
            )

            print(
                f"  MITRE Name  : "
                f"{enrichment.get('mitre_attack_name')}"
            )

            print(
                f"  Summary     : "
                f"{enrichment.get('summary')}"
            )

            print(
                "\n  Recommendations:"
            )

            for recommendation in (
                enrichment.get(
                    "recommendations",
                    [],
                )
            ):

                print(
                    f"    - {recommendation}"
                )

            # ==================================
            # Step 2
            # Write enriched event for Wazuh
            # ==================================

            print(
                "\n[WAZUH] Writing enriched "
                "security event..."
            )

            self.wazuh_logger.log_alert(
                alert=alert,
                result=result,
                feature_vector=feature_vector,
                airia_result=enrichment,
            )

            print(
                "[WAZUH] Security event written"
            )

        except Exception as exc:

            # ==================================
            # Integration failures must never
            # crash the core IDS pipeline.
            # ==================================

            print(
                f"[AIRIA/WAZUH] Integration failed: "
                f"{exc}"
            )

    @staticmethod
    def _handle_expired_flow(flow) -> None:

        print(
            f"\n[FLOW CLOSED] "
            f"{flow.src_ip}:{flow.src_port}->"
            f"{flow.dst_ip}:{flow.dst_port} "
            f"{flow.protocol}"
        )

        print(
            f" packets={flow.packet_count} "
            f"bytes={flow.byte_count} "
            f"duration={flow.duration:.2f}s"
        )

    @staticmethod
    def _print_alert(alert) -> None:

        print(
            "\n[ALERT] "
            f"{alert.severity} | "
            f"{alert.detection_type} | "
            f"source={alert.source_ip} | "
            f"risk={alert.risk_score}"
        )

        print(
            f" occurrences="
            f"{alert.occurrence_count}"
        )

        for reason in alert.reasons:

            print(
                f"  - {reason}"
            )