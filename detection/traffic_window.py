from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta

from processing.packet import Packet


@dataclass
class WindowStats:
    source_ip: str
    packet_count: int
    byte_count: int
    flow_count: int
    unique_destination_ips: int
    unique_destination_ports: int
    destination_ports: set[int]
    icmp_packet_count: int
    tcp_packet_count: int
    syn_count: int
    ack_count: int
    rst_count: int
    icmp_request_count: int
    icmp_reply_count: int


class TrafficWindow:

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        self._packets = deque()

        self._source_data = defaultdict(
            lambda: {
                "destination_ips": defaultdict(int),
                "destination_ports": defaultdict(int),
                "packet_count": 0,
                "byte_count": 0,
                "flow_keys": defaultdict(int),
                "icmp_packet_count": 0,
                "tcp_packet_count": 0,
                "syn_count": 0,
                "ack_count": 0,
                "rst_count": 0,
                "icmp_request_count": 0,
                "icmp_reply_count": 0,
            }
        )

    def add_packet(self, packet: Packet) -> None:
        self._packets.append(packet)

        data = self._source_data[packet.src_ip]

        data["destination_ips"][packet.dst_ip] += 1

        if packet.dst_port is not None:
            data["destination_ports"][packet.dst_port] += 1

        data["packet_count"] += 1
        data["byte_count"] += packet.length

        if packet.protocol == "ICMP":
            data["icmp_packet_count"] += 1

            if packet.icmp_type == 8:
                data["icmp_request_count"] += 1

            elif packet.icmp_type == 0:
                data["icmp_reply_count"] += 1

        elif packet.protocol == "TCP":
            data["tcp_packet_count"] += 1

        flow_key = (
            packet.src_ip,
            packet.src_port,
            packet.dst_ip,
            packet.dst_port,
            packet.protocol,
        )

        data["flow_keys"][flow_key] += 1

        self._update_tcp_flags(
            data,
            packet,
        )

        self._expire_old_packets(
            packet.timestamp
        )

    def get_active_sources(self) -> set[str]:
        return set(self._source_data.keys())

    def get_stats(
        self,
        source_ip: str,
    ) -> WindowStats:

        data = self._source_data.get(source_ip)

        if data is None:
            return WindowStats(
                source_ip=source_ip,
                packet_count=0,
                byte_count=0,
                flow_count=0,
                unique_destination_ips=0,
                unique_destination_ports=0,
                destination_ports=set(),
                icmp_packet_count=0,
                tcp_packet_count=0,
                syn_count=0,
                ack_count=0,
                rst_count=0,
                icmp_request_count=0,
                icmp_reply_count=0,
            )

        return WindowStats(
            source_ip=source_ip,
            packet_count=data["packet_count"],
            byte_count=data["byte_count"],
            flow_count=len(data["flow_keys"]),
            unique_destination_ips=len(
                data["destination_ips"]
            ),
            unique_destination_ports=len(
                data["destination_ports"]
            ),
            destination_ports=set(
                data["destination_ports"].keys()
            ),
            icmp_packet_count=data[
                "icmp_packet_count"
            ],
            tcp_packet_count=data[
                "tcp_packet_count"
            ],
            syn_count=data["syn_count"],
            ack_count=data["ack_count"],
            rst_count=data["rst_count"],
            icmp_request_count=data[
                "icmp_request_count"
            ],
            icmp_reply_count=data[
                "icmp_reply_count"
            ],
        )

    def _expire_old_packets(
        self,
        current_time: datetime,
    ) -> None:

        cutoff = (
            current_time
            - timedelta(
                seconds=self.window_seconds
            )
        )

        while (
            self._packets
            and self._packets[0].timestamp < cutoff
        ):
            old_packet = self._packets.popleft()

            self._remove_packet(old_packet)

    def _remove_packet(
        self,
        packet: Packet,
    ) -> None:

        data = self._source_data.get(
            packet.src_ip
        )

        if data is None:
            return

        data["packet_count"] -= 1
        data["byte_count"] -= packet.length

        data["destination_ips"][
            packet.dst_ip
        ] -= 1

        if packet.dst_port is not None:
            data["destination_ports"][
                packet.dst_port
            ] -= 1

        flow_key = (
            packet.src_ip,
            packet.src_port,
            packet.dst_ip,
            packet.dst_port,
            packet.protocol,
        )

        data["flow_keys"][
            flow_key
        ] -= 1

        if packet.protocol == "ICMP":
            data["icmp_packet_count"] -= 1

            if packet.icmp_type == 8:
                data["icmp_request_count"] -= 1

            elif packet.icmp_type == 0:
                data["icmp_reply_count"] -= 1

        elif packet.protocol == "TCP":
            data["tcp_packet_count"] -= 1

        self._update_tcp_flags(
            data,
            packet,
            remove=True,
        )

        if (
            data["destination_ips"][
                packet.dst_ip
            ] <= 0
        ):
            del data["destination_ips"][
                packet.dst_ip
            ]

        if (
            packet.dst_port is not None
            and data["destination_ports"][
                packet.dst_port
            ] <= 0
        ):
            del data["destination_ports"][
                packet.dst_port
            ]

        if (
            data["flow_keys"][
                flow_key
            ] <= 0
        ):
            del data["flow_keys"][
                flow_key
            ]

        if data["packet_count"] <= 0:
            del self._source_data[
                packet.src_ip
            ]

    @staticmethod
    def _update_tcp_flags(
        data: dict,
        packet: Packet,
        remove: bool = False,
    ) -> None:

        if packet.protocol != "TCP":
            return

        flags = (
            packet.tcp_flags or ""
        ).upper()

        if flags.startswith("0X"):
            try:
                flag_value = int(
                    flags,
                    16,
                )
            except ValueError:
                flag_value = 0

            syn = bool(flag_value & 0x002)
            ack = bool(flag_value & 0x010)
            rst = bool(flag_value & 0x004)

        else:
            syn = "S" in flags
            ack = "A" in flags
            rst = "R" in flags

        multiplier = -1 if remove else 1

        if syn:
            data["syn_count"] += multiplier

        if ack:
            data["ack_count"] += multiplier

        if rst:
            data["rst_count"] += multiplier