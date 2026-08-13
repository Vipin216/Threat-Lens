from datetime import datetime, timedelta

from processing.flow_manager import FlowManager
from processing.packet import Packet


def main():
    manager = FlowManager(timeout_seconds=60)

    start = datetime.now()

    packet = Packet(
        timestamp=start,
        src_ip="192.168.100.4",
        dst_ip="192.168.100.3",
        src_port=49152,
        dst_port=22,
        protocol="TCP",
        length=60,
        tcp_flags="S",
    )

    manager.process_packet(packet)

    print(f"Active flows: {len(manager.flows)}")

    expired = manager.expire_flows(
        start + timedelta(seconds=61)
    )

    print(f"Expired flows: {len(expired)}")
    print(f"Active flows: {len(manager.flows)}")

    assert len(expired) == 1
    assert len(manager.flows) == 0

    print("Flow expiration test passed")


if __name__ == "__main__":
    main()