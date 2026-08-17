from detection.traffic_window import WindowStats
from detection.window_features import WindowFeatureExtractor


destination_ports={22, 80, 443}

def main():
    stats = WindowStats(
        source_ip="192.168.100.4",
        packet_count=120,
        byte_count=12000,
        flow_count=60,
        unique_destination_ips=4,
        unique_destination_ports=40,
        syn_count=50,
        ack_count=10,
        rst_count=30,
    )

    extractor = WindowFeatureExtractor(window_seconds=60)

    features = extractor.extract(stats)

    print(features)
    assert features.source_ip == "192.168.100.4"
    assert features.packet_count == 120
    assert features.byte_count == 12000
    assert features.flow_count == 60

    assert features.packets_per_second == 2
    assert features.bytes_per_second == 200
    assert features.flows_per_second == 1

    assert features.ports_per_second == 40 / 60
    assert features.ips_per_second == 4 / 60

    assert features.syn_ratio == 50 / 120
    assert features.ack_ratio == 10 / 120
    assert features.rst_ratio == 30 / 120
    assert features.sensitive_port_count == 1
    print("Window feature extraction test passed")


if __name__ == "__main__":
    main()