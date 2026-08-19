from dataclasses import dataclass
from datetime import datetime


from processing.packet import Packet

@dataclass
class Flow:
    src_ip:str
    src_port:int | None
    dst_ip:str
    dst_port:int| None
    protocol:str

    start_time:datetime
    last_seen:datetime

    packet_count: int=0
    byte_count:int=0
    syn_count:int=0
    ack_count:int=0
    rst_count:int=0
    fin_count:int=0


    def add_packet(self,packet:Packet)->None:
        self.packet_count+=1
        self.byte_count+=packet.length
        self.last_seen=packet.timestamp


        if packet.tcp_flags:
            flags=packet.tcp_flags.upper()

            if "S" in flags:
                self.syn_count+=1

            if "A" in flags:
                self.ack_count+=1

            if "R" in flags:
                self.rst_count+=1

            if "F" in flags:
                self.fin_count+=1



    @property
    def duration(self)->float:
        return (self.last_seen - self.start_time).total_seconds()

    @property
    def packets_per_second(self)->float:
        if self.duration<=0:
            return float(self.packet_count)

        return self.packet_count / self.duration


    @property
    def bytes_per_second(self)->float:
        if self.duration<=0:
            return float(self.byte_count)

        return self.byte_count/self.duration

    
