from datetime import datetime

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


class IDSPipeline:

    def __init__(self, interface: str):

        # -----------------------------------------
        # Capture / processing
        # -----------------------------------------

        self.capture = TsharkCapture(interface)
        self.parser = PacketParser()
        self.flow_manager = FlowManager()

        # -----------------------------------------
        # Traffic window
        # -----------------------------------------

        self.traffic_window = TrafficWindow(
            window_seconds=60
        )

        # -----------------------------------------
        # Feature extraction
        # -----------------------------------------

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

        # -----------------------------------------
        # Detection
        # -----------------------------------------

        self.detection_context = (
            DetectionContext(
                window_seconds=60
            )
        )

        self.detection_engine = DetectionEngine()

        # Detection runs every 5 seconds
        self.scheduler = DetectionScheduler(
            interval_seconds=5
        )

        # -----------------------------------------
        # Alert management
        # -----------------------------------------

        self.alert_manager = AlertManager(
            stale_after_seconds=60
        )

    def run(self) -> None:

        print(
            f"[+] Starting IDS capture on "
            f"{self.capture.interface}"
        )

        for raw_line in self.capture.stream_packets():

            packet = self.parser.parse(raw_line)

            if packet is None:
                continue

            # -------------------------------------
            # Update source traffic window
            # -------------------------------------

            self.traffic_window.add_packet(packet)

            # -------------------------------------
            # Expire inactive flows
            # -------------------------------------

            expired_flows = (
                self.flow_manager.expire_flows(
                    packet.timestamp
                )
            )

            for flow in expired_flows:
                self._handle_expired_flow(flow)

            # -------------------------------------
            # Update current flow
            # -------------------------------------

            flow = (
                self.flow_manager.process_packet(
                    packet
                )
            )

            # -------------------------------------
            # Debug flow output
            # -------------------------------------

            #print(
             #   f"[FLOW] "
              #  f"{flow.src_ip}:{flow.src_port}->"
               # f"{flow.dst_ip}:{flow.dst_port} "
                #f"{flow.protocol} | "
                #f"packets={flow.packet_count} "
                #f"bytes={flow.byte_count}"
            #)

            # -------------------------------------
            # Periodic detection snapshot
            #
            # IMPORTANT:
            # Use wall-clock time for scheduling
            # live IDS detection.
            # -------------------------------------

            current_time = datetime.now()

            if self.scheduler.should_run(
                current_time
            ):

                print(
                    "\n[DEBUG] "
                    "Running detection snapshot"
                )

                self._run_detection_snapshot(
                    packet.timestamp
                )

            # -------------------------------------
            # Resolve stale alerts
            # -------------------------------------

            self.alert_manager.resolve_stale_alerts(
                packet.timestamp
            )

    def _run_detection_snapshot(
        self,
        timestamp: datetime,
    ) -> None:

        active_flows = (
            self.flow_manager.get_active_flows()
        )

        print(
            f"[DEBUG] Active flows: "
            f"{len(active_flows)}"
        )

        # -----------------------------------------
        # Build feature vectors
        # -----------------------------------------

        for flow in active_flows:

            flow_features = (
                self.flow_feature_extractor
                .extract_flow_features(flow)
            )

            stats = (
                self.traffic_window
                .get_stats(flow.src_ip)
            )

            window_features = (
                self.window_feature_extractor
                .extract(stats)
            )

            feature_vector = (
                self.feature_vector_builder
                .build(
                    flow_features,
                    window_features,
                )
            )

            self.detection_context.add(
                feature_vector,
                timestamp,
            )

            print(
                f"[DEBUG] "
                f"{flow.src_ip} | "
                f"packets="
                f"{window_features.packet_count} | "
                f"pps="
                f"{window_features.packets_per_second:.2f} | "
                f"icmp_ratio="
                f"{window_features.icmp_ratio:.2f}"
            )

        # -----------------------------------------
        # Run detection
        # -----------------------------------------

        results = (
            self.detection_engine.detect(
                self.detection_context
            )
        )

        print(
            f"[DEBUG] Detection results: "
            f"{len(results)}"
        )

        # -----------------------------------------
        # Process alerts
        # -----------------------------------------

        for result in results:

            print(
                f"[DEBUG] Detection: "
                f"{result.source_ip} | "
                f"score={result.score} | "
                f"detected={result.detected}"
            )

            alert = (
                self.alert_manager.process(
                    result,
                    timestamp,
                )
            )

            if alert is not None:
                self._print_alert(alert)

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