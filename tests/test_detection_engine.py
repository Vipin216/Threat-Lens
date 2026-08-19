from datetime import datetime

from detection.detection_context import DetectionContext
from detection.detection_engine import DetectionEngine
from detection.feature_vector import FeatureVector


def make_vector(
    source_ip,
    icmp_packets,
    icmp_requests,
    icmp_replies,
    packets_per_second,
):
    return FeatureVector(
        source_ip=source_ip,

        flow_packet_count=10,
        flow_byte_count=980,
        flow_duration=2.0,
        flow_packets_per_second=5.0,
        flow_bytes_per_second=490.0,

        syns_per_second=0.0,
        flow_syn_ratio=0.0,
        flow_ack_ratio=0.0,
        flow_rst_ratio=0.0,
        flow_fin_ratio=0.0,

        window_packet_count=100,
        window_byte_count=9800,
        window_flow_count=1,

        unique_destination_ips=1,
        unique_destination_ports=0,
        sensitive_port_count=0,

        window_packets_per_second=packets_per_second,
        window_bytes_per_second=163.3,
        window_flows_per_second=1 / 60,

        ports_per_second=0.0,
        ips_per_second=1 / 60,

        window_icmp_packet_count=icmp_packets,
        window_icmp_request_count=icmp_requests,
        window_icmp_reply_count=icmp_replies,
        window_tcp_packet_count=0,
        window_icmp_ratio=icmp_packets / 100,
        window_icmp_request_ratio=icmp_requests / 100,

        window_syn_ratio=0.0,
        window_ack_ratio=0.0,
        window_rst_ratio=0.0,
    )


def main():
    context = DetectionContext()

    timestamp = datetime.now()

    context.add(
        make_vector(
            source_ip="192.168.100.4",
            icmp_packets=100,
            icmp_requests=100,
            icmp_replies=0,
            packets_per_second=10.0,
        ),
        timestamp,
    )

    context.add(
        make_vector(
            source_ip="192.168.100.3",
            icmp_packets=100,
            icmp_requests=0,
            icmp_replies=100,
            packets_per_second=10.0,
        ),
        timestamp,
    )

    engine = DetectionEngine()

    results = engine.detect(context)

    print("\nDetection results:")

    for result in results:
        print(result)

    assert len(results) == 1

    result = results[0]

    assert result.source_ip == "192.168.100.4"
    assert result.detected is True
    assert result.score >= 50

    assert any(
        "ICMP echo-request" in reason
        for reason in result.reasons
    )

    print("\nICMP direction detection test passed")


if __name__ == "__main__":
    main()