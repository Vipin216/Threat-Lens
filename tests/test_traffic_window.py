from datetime import datetime, timedelta

from detection.traffic_window import TrafficWindow
from processing.packet import Packet


def make_packet(
    timestamp,
    src_ip,
    dst_ip,
    icmp_type,
):
    return Packet(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=None,
        dst_port=None,
        protocol="ICMP",
        length=98,
        tcp_flags=None,
        icmp_type=icmp_type,
    )


def main():
    window = TrafficWindow(window_seconds=60)

    start = datetime.now()

    # Attacker -> victim: Echo Requests
    for i in range(5):
        window.add_packet(
            make_packet(
                start + timedelta(seconds=i),
                "192.168.100.4",
                "192.168.100.3",
                8,
            )
        )

    # Victim -> attacker: Echo Replies
    for i in range(5):
        window.add_packet(
            make_packet(
                start + timedelta(seconds=i),
                "192.168.100.3",
                "192.168.100.4",
                0,
            )
        )

    attacker = window.get_stats(
        "192.168.100.4"
    )

    victim = window.get_stats(
        "192.168.100.3"
    )

    print("Attacker stats:")
    print(attacker)

    print("\nVictim stats:")
    print(victim)

    assert attacker.icmp_packet_count == 5
    assert attacker.icmp_request_count == 5
    assert attacker.icmp_reply_count == 0

    assert victim.icmp_packet_count == 5
    assert victim.icmp_request_count == 0
    assert victim.icmp_reply_count == 5

    print("\nTraffic window ICMP test passed")


if __name__ == "__main__":
    main()