from detection.feature_vector import FeatureVectorBuilder
from detection.features import FlowFeatures
from detection.window_features import WindowFeatures



def test_source_mismatch():
    flow_features = FlowFeatures(
        source_ip="192.168.100.4",

        packet_count=10,
        byte_count=600,
        duration=2.0,
        packets_per_second=5.0,
        bytes_per_second=300.0,

        syn_ratio=0.8,
        ack_ratio=0.2,
        rst_ratio=0.0,
        fin_ratio=0.0,
    )

    window_features = WindowFeatures(
        source_ip="192.168.100.5",

        packet_count=100,
        byte_count=6000,
        flow_count=20,

        unique_destination_ips=3,
        unique_destination_ports=15,

        packets_per_second=100 / 60,
        bytes_per_second=6000 / 60,
        flows_per_second=20 / 60,

        ports_per_second=15 / 60,
        ips_per_second=3 / 60,

        syn_ratio=0.7,
        ack_ratio=0.2,
        rst_ratio=0.1,
    )

    builder = FeatureVectorBuilder()

    try:
        builder.build(
            flow_features,
            window_features,
        )

        assert False, "Expected ValueError"

    except ValueError as error:
        assert str(error) == (
            "Flow and window source IPs must match"
        )

    print("Source mismatch validation test passed")

def main():

    flow_features = FlowFeatures(
        source_ip="192.168.100.4",
        packet_count=10,
        byte_count=600,
        duration=2.0,
        packets_per_second=5.0,
        bytes_per_second=300.0,
        syn_ratio=0.8,
        ack_ratio=0.2,
        rst_ratio=0.0,
        fin_ratio=0.0,
    )

    window_features = WindowFeatures(
        source_ip="192.168.100.4",
        packet_count=100,
        byte_count=6000,
        flow_count=20,
        unique_destination_ips=3,
        unique_destination_ports=15,
        packets_per_second=100 / 60,
        bytes_per_second=6000 / 60,
        flows_per_second=20 / 60,
        ports_per_second=15 / 60,
        ips_per_second=3 / 60,
        syn_ratio=0.7,
        ack_ratio=0.2,
        rst_ratio=0.1,
    )

    builder = FeatureVectorBuilder()

    vector = builder.build(
        flow_features,
        window_features,
    )

    print(vector)
    assert vector.source_ip == "192.168.100.4"
    assert vector.flow_packet_count == 10
    assert vector.flow_byte_count == 600
    assert vector.flow_duration == 2.0

    assert vector.flow_syn_ratio == 0.8
    assert vector.flow_ack_ratio == 0.2

    assert vector.window_packet_count == 100
    assert vector.window_flow_count == 20

    assert vector.unique_destination_ports == 15
    assert vector.unique_destination_ips == 3

    assert vector.window_syn_ratio == 0.7
    assert vector.window_icmp_packet_count == 20
    assert vector.window_tcp_packet_count == 80
    assert vector.window_icmp_ratio == 0.2

    print("Feature vector test passed")




if __name__ == "__main__":
    main()
    test_source_mismatch()
    print("All feature vector tests passed")