from datetime import datetime, timedelta

from detection.traffic_window import TrafficWindow
from processing.packet import Packet

destination_ports={22, 80, 443}

def make_packet(
    timestamp,
    src_ip,
    dst_ip,
    dst_port,
    flags="S",
    length=60,
):
    return Packet(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=49152,
        dst_port=dst_port,
        protocol="TCP",
        length=length,
        tcp_flags=flags,
    )


def test_basic_window():
    start = datetime.now()

    window = TrafficWindow(window_seconds=60)

    window.add_packet(
        make_packet(
            start,
            "192.168.100.4",
            "192.168.100.3",
            22,
        )
    )

    window.add_packet(
        make_packet(
            start + timedelta(seconds=1),
            "192.168.100.4",
            "192.168.100.3",
            80,
        )
    )

    window.add_packet(
        make_packet(
            start + timedelta(seconds=2),
            "192.168.100.4",
            "192.168.100.3",
            443,
        )
    )

    stats = window.get_stats("192.168.100.4")

    print(stats)

    assert stats.packet_count == 3
    assert stats.byte_count == 180
    assert stats.flow_count == 3
    assert stats.unique_destination_ips == 1
    assert stats.unique_destination_ports == 3
    assert stats.syn_count == 3

    print("Basic traffic window test passed")


def test_expiration():
    start = datetime.now()

    window = TrafficWindow(window_seconds=60)

    # Packet at t=0 → port 22
    window.add_packet(
        make_packet(
            start,
            "192.168.100.4",
            "192.168.100.3",
            22,
        )
    )

    # Packet at t=1 → port 80
    window.add_packet(
        make_packet(
            start + timedelta(seconds=1),
            "192.168.100.4",
            "192.168.100.3",
            80,
        )
    )

    # Packet at t=61 → port 443
    # The t=0 packet should now expire.
    window.add_packet(
        make_packet(
            start + timedelta(seconds=61),
            "192.168.100.4",
            "192.168.100.3",
            443,
        )
    )

    stats = window.get_stats("192.168.100.4")

    print(stats)

    assert stats.packet_count == 2
    assert stats.byte_count == 120
    assert stats.unique_destination_ports == 2
    assert stats.icmp_packet_count == 2
    assert stats.tcp_packet_count == 3

    print("Traffic window expiration test passed")


if __name__ == "__main__":
    test_basic_window()
    test_expiration()
    print("All traffic window tests passed")