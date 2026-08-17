from datetime import datetime, timedelta

from detection.features import FeatureExtractor
from processing.flow import Flow
from processing.packet import Packet


def main():
    start = datetime.now()

    flow = Flow(
        src_ip="192.168.100.4",
        src_port=49152,
        dst_ip="192.168.100.3",
        dst_port=22,
        protocol="TCP",
        start_time=start,
        last_seen=start,
    )

    packets = [
        Packet(
            timestamp=start,
            src_ip="192.168.100.4",
            dst_ip="192.168.100.3",
            src_port=49152,
            dst_port=22,
            protocol="TCP",
            length=60,
            tcp_flags="S",
        ),
        Packet(
            timestamp=start + timedelta(seconds=1),
            src_ip="192.168.100.4",
            dst_ip="192.168.100.3",
            src_port=49152,
            dst_port=22,
            protocol="TCP",
            length=52,
            tcp_flags="A",
        ),
        Packet(
            timestamp=start + timedelta(seconds=2),
            src_ip="192.168.100.4",
            dst_ip="192.168.100.3",
            src_port=49152,
            dst_port=22,
            protocol="TCP",
            length=100,
            tcp_flags="A",
        ),
    ]

    for packet in packets:
        flow.add_packet(packet)

    extractor = FeatureExtractor()
    features = extractor.extract_flow_features(flow)

    print(features)

    assert features.packet_count == 3
    assert features.byte_count == 212
    assert features.duration == 2
    assert features.syn_ratio == 1 / 3
    assert features.ack_ratio == 2 / 3
    assert features.icmp_packet_count == 20
    assert features.tcp_packet_count == 80
    assert features.icmp_ratio == 0.2
    print("Feature extraction test passed")


if __name__ == "__main__":
    main()