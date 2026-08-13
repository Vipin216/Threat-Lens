import subprocess
from collections.abc import Iterator


class TsharkCapture:
    def __init__(self,interface:str):
        self.interface=interface

    def stream_packets(self)->Iterator[str]:
        command = [
            "tshark",
            "-i",self.interface,
            "-f","tcp or icmp",
            "-T","fields",
            "-E","separator=|",
            "-E","occurrence=f",
            "-e","frame.time_epoch",
            "-e","ip.src",
            "-e","ip.dst",
            "-e","ip.proto",
            "-e","tcp.srcport",
            "-e","tcp.dstport",
            "-e","frame.len",
            "-e","tcp.flags",
        ]

        process = subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1,)
        if process.stdout is None:
            raise RuntimeError("Failed to open tshark output stream")


        for line in process.stdout:
            line=line.strip()

            if line:
                yield line