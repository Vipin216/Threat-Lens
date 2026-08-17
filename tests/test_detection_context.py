from datetime import datetime, timedelta

from detection.detection_context import DetectionContext
from detection.feature_vector import FeatureVector


def make_vector(source_ip):
    return FeatureVector(
        source_ip=source_ip,

        # Flow-level features
        flow_packet_count=10,
        flow_byte_count=600,
        flow_duration=2.0,
        flow_packets_per_second=5.0,
        flow_bytes_per_second=300.0,

        flow_syn_ratio=0.8,
        flow_ack_ratio=0.2,
        flow_rst_ratio=0.0,
        flow_fin_ratio=0.0,

        # Window-level features
        window_packet_count=100,
        window_byte_count=6000,
        window_flow_count=20,

        unique_destination_ips=3,
        unique_destination_ports=15,

        window_packets_per_second=100 / 60,
        window_bytes_per_second=6000 / 60,
        window_flows_per_second=20 / 60,

        ports_per_second=15 / 60,
        ips_per_second=3 / 60,

        window_syn_ratio=0.7,
        window_ack_ratio=0.2,
        window_rst_ratio=0.1,
    )


def main():

    start = datetime.now()

    context = DetectionContext(window_seconds=60)

    # ------------------------------------------------
    # t = 0
    # Source A → Feature Vector 1
    # ------------------------------------------------

    context.add(
        make_vector("192.168.100.4"),
        start,
    )

    # ------------------------------------------------
    # t = 10
    # Source A → Feature Vector 2
    # ------------------------------------------------

    context.add(
        make_vector("192.168.100.4"),
        start + timedelta(seconds=10),
    )

    # ------------------------------------------------
    # t = 20
    # Source B → Feature Vector 1
    # ------------------------------------------------

    context.add(
        make_vector("192.168.100.5"),
        start + timedelta(seconds=20),
    )

    # ------------------------------------------------
    # Check state before expiration
    # ------------------------------------------------

    source_a = context.get_source_vectors(
        "192.168.100.4"
    )

    source_b = context.get_source_vectors(
        "192.168.100.5"
    )

    print("Before expiration:")
    print("Source A vectors:", len(source_a))
    print("Source B vectors:", len(source_b))
    print("All sources:", context.get_all_sources())

    assert len(source_a) == 2
    assert len(source_b) == 1

    assert context.get_all_sources() == {
        "192.168.100.4",
        "192.168.100.5",
    }

    # ------------------------------------------------
    # t = 61
    #
    # This should cause the t=0 vector to expire.
    # The t=10 and t=20 vectors are still active.
    # ------------------------------------------------

    context.add(
        make_vector("192.168.100.6"),
        start + timedelta(seconds=61),
    )

    # ------------------------------------------------
    # Check state after expiration
    # ------------------------------------------------

    source_a = context.get_source_vectors(
        "192.168.100.4"
    )

    source_b = context.get_source_vectors(
        "192.168.100.5"
    )

    source_c = context.get_source_vectors(
        "192.168.100.6"
    )

    print("\nAfter expiration:")
    print("Source A vectors:", len(source_a))
    print("Source B vectors:", len(source_b))
    print("Source C vectors:", len(source_c))
    print("All sources:", context.get_all_sources())

    # Source A originally had 2 vectors.
    # The t=0 vector expired.
    # The t=10 vector remains.
    assert len(source_a) == 1

    # Source B's vector was created at t=20.
    # It is still inside the 60-second window.
    assert len(source_b) == 1

    # Source C was just added at t=61.
    assert len(source_c) == 1

    # The t=0 vector from Source A is gone,
    # but Source A is still represented because
    # its t=10 vector is still active.
    assert context.get_all_sources() == {
        "192.168.100.4",
        "192.168.100.5",
        "192.168.100.6",
    }

    print("\nDetection context test passed")


if __name__ == "__main__":
    main()