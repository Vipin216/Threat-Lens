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
        self.capture = TsharkCapture(interface)
        self.parser = PacketParser()
        self.flow_manager = FlowManager()

        self.traffic_window = TrafficWindow(
            window_seconds=60
        )

        self.flow_feature_extractor = FeatureExtractor()

        self.window_feature_extractor = WindowFeatureExtractor(
            window_seconds=60
        )

        self.feature_vector_builder = FeatureVectorBuilder()

        self.detection_context = DetectionContext(
            window_seconds=60
        )

        self.detection_engine = DetectionEngine()

        self.scheduler = DetectionScheduler(
            interval_seconds=5
        )

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

            self.traffic_window.add_packet(packet)

            self.flow_manager.process_packet(packet)

            if self.scheduler.should_run(packet.timestamp):
                print(
                    "\n[DEBUG] Running detection snapshot"
                )

                self._run_detection_snapshot(
                    packet.timestamp
                )

            expired_flows = self.flow_manager.expire_flows(
                packet.timestamp
            )

            for flow in expired_flows:
                self._handle_expired_flow(flow)

            self.alert_manager.resolve_stale_alerts(
                packet.timestamp
            )

    def _run_detection_snapshot(
        self,
        timestamp,
    ) -> None:

        source_ips = (
            self.traffic_window.get_active_sources()
        )

        print(
            f"[DEBUG] Active window sources: "
            f"{len(source_ips)}"
        )

        for source_ip in source_ips:

            stats = self.traffic_window.get_stats(
                source_ip
            )

            window_features = (
                self.window_feature_extractor.extract(
                    stats
                )
            )

            active_flows = [
                flow
                for flow in self.flow_manager.get_active_flows()
                if flow.src_ip == source_ip
            ]

            if not active_flows:
                continue

            latest_flow = max(
                active_flows,
                key=lambda flow: flow.last_seen
            )

            flow_features = (
                self.flow_feature_extractor
                .extract_flow_features(
                    latest_flow
                )
            )

            print(
                f"[DEBUG] {source_ip} | "
                f"packets={stats.packet_count} | "
                f"pps={window_features.packets_per_second:.2f} | "
                f"ports={window_features.unique_destination_ports} | "
                f"syn_ratio={window_features.syn_ratio:.2f} | "
                f"syns/sec={window_features.syns_per_second:.2f}"
            )

            feature_vector = (
                self.feature_vector_builder.build(
                    flow_features,
                    window_features,
                )
            )

            self.detection_context.add(
                feature_vector,
                timestamp,
            )

        results = self.detection_engine.detect(
            self.detection_context
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

            alert = self.alert_manager.process(
                result,
                timestamp,
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
            f" occurrences={alert.occurrence_count}"
        )

        for reason in alert.reasons:
            print(
                f"  - {reason}"
            )