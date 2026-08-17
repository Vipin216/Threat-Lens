from dataclasses import dataclass
from detection.traffic_window import WindowStats


SENSITIVE_PORTS = {
    22,     # SSH
    23,     # Telnet
    3389,   # RDP
}

@dataclass
class WindowFeatures:

    source_ip:str
    packet_count:int
    byte_count:int
    flow_count:int

    unique_destination_ips:int
    unique_destination_ports:int
    sensitive_port_count: int
    packets_per_second:float
    bytes_per_second:float
    flows_per_second:float

    icmp_packet_count: int
    tcp_packet_count: int
    icmp_ratio: float

    ports_per_second:float
    ips_per_second:float

    syns_per_second: float
    syn_ratio:float
    ack_ratio:float
    rst_ratio:float




class WindowFeatureExtractor:
    def __init__(self,window_seconds:int =60):
        self.window_seconds  = window_seconds

    def extract(self,stats:WindowStats)-> WindowFeatures:
        seconds = max(self.window_seconds,1)
        sensitive_port_count = len(
            set(stats.destination_ports) & SENSITIVE_PORTS
        )

        packets_per_second=(stats.packet_count/seconds)
        bytes_per_second=(stats.byte_count/seconds)
        flows_per_second=(stats.flow_count/seconds)
        ports_per_second=(stats.unique_destination_ports/seconds)
        ips_per_second=(stats.unique_destination_ips/seconds)
        syns_per_second = (stats.syn_count / self.window_seconds)



        if stats.packet_count>0:
            if stats.packet_count > 0:
                icmp_ratio = (stats.icmp_packet_count /stats.packet_count)
            else:
                icmp_ratio = 0.0

            syn_ratio = stats.syn_count / stats.packet_count
            ack_ratio = stats.ack_count / stats.packet_count
            rst_ratio = stats.rst_count/stats.packet_count
        else:
            syn_ratio=0.0
            ack_ratio=0.0
            rst_ratio=0.0



        return WindowFeatures(
            source_ip=stats.source_ip,
            packet_count=stats.packet_count,
            byte_count=stats.byte_count,
            flow_count=stats.flow_count,
            unique_destination_ips=stats.unique_destination_ips,
            unique_destination_ports=stats.unique_destination_ports,
            sensitive_port_count=sensitive_port_count,
            packets_per_second=packets_per_second,
            bytes_per_second=bytes_per_second,
            flows_per_second=flows_per_second,
            icmp_packet_count=stats.icmp_packet_count,
            tcp_packet_count=stats.tcp_packet_count,
            icmp_ratio=icmp_ratio,
            ports_per_second=ports_per_second,
            ips_per_second=ips_per_second,
            syn_ratio=syn_ratio,
            ack_ratio=ack_ratio,
            rst_ratio=rst_ratio,



        )
