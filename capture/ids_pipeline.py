from capture.tshark_capture import TsharkCapture
from processing.flow_manager import FlowManager
from processing.parser import PacketParser


class IDSPipeline:
    def __init__(self,interface:str):
        self.capture = TsharkCapture(interface)
        self.parser=PacketParser()
        self.flow_manager=FlowManager()


    def run(self)->None:
        print(f"[+] Starting IDS capture on {self.capture.interface}")

        for raw_line in self.capture.stream_packets():
            packet=self.parser.parse(raw_line)


            if packet is None:
                continue


            expired_flows = self.flow_manager.expire_flows(packet.timestamp)
            for flow in expired_flows:
                self._handle_expired_flow(flow)

            flow=self.flow_manager.process_packet(packet)


            print(
                f"[FLOW] "
                f"{flow.src_ip}:{flow.src_port}-> "
                f"{flow.dst_ip}:{flow.dst_port} "
                f"{flow.protocol} |"
                f"packets={flow.packet_count} "
                f"bytes={flow.byte_count}"

            )


    @staticmethod
    def _handle_expired_flow(flow)->None:
        print(
            f"\n[FLOW CLOSED] "
            f"{flow.src_ip}:{flow.src_port}->"
            f"{flow.dst_ip}:{flow.dst_port}"
            f"{flow.protocol}"
        )

        print(
            f" packets={flow.packet_count} "
            f"bytes={flow.byte_count} "
            f"duration={flow.duration:.2f}s"
        )
    