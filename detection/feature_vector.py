from dataclasses import dataclass

from detection.features import FlowFeatures
from detection.window_features import WindowFeatures


@dataclass
class FeatureVector:
    source_ip:str
    flow_packet_count: int
    flow_byte_count: int
    flow_duration: float
    flow_packets_per_second: float
    flow_bytes_per_second: float
    syns_per_second: float
    flow_syn_ratio: float
    flow_ack_ratio: float
    flow_rst_ratio: float
    flow_fin_ratio: float




   
    window_packet_count: int
    window_byte_count: int
    window_flow_count: int

    unique_destination_ips: int
    unique_destination_ports: int
    sensitive_port_count: int
    window_packets_per_second: float
    window_bytes_per_second: float
    window_flows_per_second: float

    ports_per_second: float
    ips_per_second: float


    window_icmp_packet_count: int
    window_tcp_packet_count: int
    window_icmp_ratio: float


    window_syn_ratio: float
    window_ack_ratio: float
    window_rst_ratio: float


class FeatureVectorBuilder:

    def build(
        self,
        flow_features: FlowFeatures,
        window_features: WindowFeatures,
    ) -> FeatureVector:
        if flow_features.source_ip != window_features.source_ip:
            raise ValueError(
                "Flow and window source IPs must match"
    )

        return FeatureVector(
            # Flow
            source_ip=flow_features.source_ip,
            flow_packet_count=flow_features.packet_count,
            flow_byte_count=flow_features.byte_count,
            flow_duration=flow_features.duration,
            flow_packets_per_second=flow_features.packets_per_second,
            flow_bytes_per_second=flow_features.bytes_per_second,

            flow_syn_ratio=flow_features.syn_ratio,
            flow_ack_ratio=flow_features.ack_ratio,
            flow_rst_ratio=flow_features.rst_ratio,
            flow_fin_ratio=flow_features.fin_ratio,

            # Window
            window_packet_count=window_features.packet_count,
            window_byte_count=window_features.byte_count,
            window_flow_count=window_features.flow_count,

            unique_destination_ips=(
                window_features.unique_destination_ips
            ),

            unique_destination_ports=(
                window_features.unique_destination_ports
            ),

            sensitive_port_count=(
                window_features.sensitive_port_count
            ),

            window_packets_per_second=(
                window_features.packets_per_second
            ),

            window_bytes_per_second=(
                window_features.bytes_per_second
            ),

            window_flows_per_second=(
                window_features.flows_per_second
            ),

            ports_per_second=window_features.ports_per_second,
            ips_per_second=window_features.ips_per_second,



            window_icmp_packet_count=(window_features.icmp_packet_count),
            window_tcp_packet_count=(window_features.tcp_packet_count),
            window_icmp_ratio=(window_features.icmp_ratio),

            syns_per_second=(window_features.syns_per_second),
            window_syn_ratio=window_features.syn_ratio,
            window_ack_ratio=window_features.ack_ratio,
            window_rst_ratio=window_features.rst_ratio,
        )