from datetime import timedelta

from processing.packet import Packet
from processing.flow import Flow


class FlowManager:

    def __init__(self, timeout_seconds: int = 60):
        self.timeout_seconds = timeout_seconds
        self.flows: dict[tuple, Flow] = {}

    @staticmethod
    def _flow_key(packet: Packet) -> tuple:
        return (
            packet.src_ip,
            packet.src_port,
            packet.dst_ip,
            packet.dst_port,
            packet.protocol,
        )

    def process_packet(self, packet: Packet) -> Flow:
        key = self._flow_key(packet)

        if key not in self.flows:
            self.flows[key] = Flow(
                src_ip=packet.src_ip,
                src_port=packet.src_port,
                dst_ip=packet.dst_ip,
                dst_port=packet.dst_port,
                protocol=packet.protocol,
                start_time=packet.timestamp,
                last_seen=packet.timestamp,
            )

        flow = self.flows[key]

        flow.add_packet(packet)

        return flow

    def expire_flows(
        self,
        current_time,
    ) -> list[Flow]:

        expired = []

        for key, flow in list(self.flows.items()):

            if (
                current_time - flow.last_seen
                > timedelta(seconds=self.timeout_seconds)
            ):
                expired.append(flow)
                del self.flows[key]

        return expired

    def get_active_flows(self) -> list[Flow]:
        return list(self.flows.values())