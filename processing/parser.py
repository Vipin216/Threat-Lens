from datetime import datetime

from processing.packet import Packet


class PacketParser:
    def parse(self,line:str)->Packet | None:
        parts = line.split("|")


        if len(parts)!=9:
            return None

        (
            timestamp,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            length,
            tcp_flags,
            icmp_type,
        )=parts

        try:
            timestamp_value = datetime.fromtimestamp(float(timestamp))
        except ValueError:
            return None

        return Packet(
            timestamp=timestamp_value,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=int(src_port) if src_port else None,
            dst_port=int(dst_port) if dst_port else None,
            protocol=self._normalize_protocol(protocol),
            length=int(length) if length else 0,
            tcp_flags=tcp_flags if tcp_flags else None,
            icmp_type=int(icmp_type) if icmp_type else None,
        )

    @staticmethod
    def _normalize_protocol(protocol:str)->str:
        if protocol == "6":
            return "TCP"

        if protocol == "1":
            return "ICMP"

        return protocol