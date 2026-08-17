from dataclasses import dataclass
from processing.flow import Flow


@dataclass
class FlowFeatures:
    source_ip:str
    packet_count:int
    byte_count:int
    duration:int

    packets_per_second:float
    bytes_per_second:float

    syn_ratio:float
    ack_ratio:float
    rst_ratio:float
    fin_ratio:float


class FeatureExtractor:
    def extract_flow_features(self,flow:Flow)->FlowFeatures:
        packet_count=flow.packet_count
        byte_count=flow.byte_count
        duration=flow.duration

        packets_per_second = flow.packets_per_second
        bytes_per_second=flow.bytes_per_second

        if packet_count>0:
            syn_ratio = flow.syn_count/packet_count
            ack_ratio = flow.ack_count/packet_count
            rst_ratio = flow.rst_count/packet_count
            fin_ratio = flow.fin_count/packet_count

        else:
            syn_ratio=0
            ack_ratio=0
            fin_ratio=0
            rst_ratio=0


        return FlowFeatures(
            source_ip=flow.src_ip,
            packet_count=packet_count,
            byte_count=byte_count,
            duration=duration,
            packets_per_second=packets_per_second,
            bytes_per_second=bytes_per_second,
            syn_ratio=syn_ratio,
            ack_ratio=ack_ratio,
            rst_ratio=rst_ratio,
            fin_ratio=fin_ratio,
        )  