from datetime import datetime

from detection.detection_context import DetectionContext
from detection.detection_engine import DetectionEngine
from detection.feature_vector import FeatureVector


def make_vector(
    source_ip,
    unique_ports,
    syn_ratio,
    packets_per_second,
    syns_per_second,
):
    return FeatureVector(
        source_ip=source_ip,

        flow_packet_count=10,
        flow_byte_count=600,
        flow_duration=2.0,
        flow_packets_per_second=5.0,
        flow_bytes_per_second=300.0,

        syns_per_second=syns_per_second,
        flow_syn_ratio=syn_ratio,
        flow_ack_ratio=0.1,
        flow_rst_ratio=0.0,
        flow_fin_ratio=0.0,

        window_packet_count=100,
        window_byte_count=6000,
        window_flow_count=20,

        unique_destination_ips=1,
        unique_destination_ports=unique_ports,
        sensitive_port_count=0,

        window_packets_per_second=packets_per_second,
        window_bytes_per_second=100.0,
        window_flows_per_second=1.0,

        ports_per_second=unique_ports / 60,
        ips_per_second=1 / 60,

        window_icmp_packet_count=0,
        window_icmp_request_count=0,
        window_icmp_reply_count=0,
        window_tcp_packet_count=100,
        window_icmp_ratio=0.0,
        window_icmp_request_ratio=0.0,

        window_syn_ratio=syn_ratio,
        window_ack_ratio=0.1,
        window_rst_ratio=0.0,
    )


def main():

    context = DetectionContext()

    timestamp = datetime.now()

    context.add(
        make_vector(
            source_ip="192.168.100.4",
            unique_ports=20,
            syn_ratio=0.9,
            packets_per_second=3.0,
            syns_per_second=3.0,
        ),
        timestamp,
    )

    context.add(
        make_vector(
            source_ip="192.168.100.5",
            unique_ports=2,
            syn_ratio=0.2,
            packets_per_second=0.2,
            syns_per_second=0.1,
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
    assert result.score >= 40

    assert any(
        "SYN" in reason
        for reason in result.reasons
    )

    print("\nSYN scan detection test passed")


if __name__ == "__main__":
    main()