from dataclasses import dataclass
from datetime import datetime


@dataclass
class Packet:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    length: int
    tcp_flags: str | None = None
    icmp_type: int | None = None