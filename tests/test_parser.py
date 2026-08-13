from processing.parser import PacketParser


def main():
    parser = PacketParser()

    tcp_line = (
        "1755100000.123|"
        "192.168.100.4|"
        "192.168.100.3|"
        "6|"
        "49152|"
        "22|"
        "60|"
        "0x002"
    )

    icmp_line = (
        "1755100001.456|"
        "192.168.100.4|"
        "192.168.100.3|"
        "1|||"
        "98|"
    )

    tcp_packet = parser.parse(tcp_line)
    icmp_packet = parser.parse(icmp_line)

    print("TCP packet:")
    print(tcp_packet)

    print("\nICMP packet:")
    print(icmp_packet)


if __name__ == "__main__":
    main()