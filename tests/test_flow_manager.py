from datetime import datetime, timedelta

from processing.packet import Packet
from processing.flow_manager import FlowManager


def main():
    manager = FlowManager()

    start = datetime.now()

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
        flow = manager.process_packet(packet)

    print("Flow:")
    print(f"  Source: {flow.src_ip}:{flow.src_port}")
    print(f"  Destination: {flow.dst_ip}:{flow.dst_port}")
    print(f"  Protocol: {flow.protocol}")
    print(f"  Packets: {flow.packet_count}")
    print(f"  Bytes: {flow.byte_count}")
    print(f"  Duration: {flow.duration:.2f}s")
    print(f"  SYN: {flow.syn_count}")
    print(f"  ACK: {flow.ack_count}")
    print(f"  Packets/sec: {flow.packets_per_second:.2f}")


if __name__ == "__main__":
    main()