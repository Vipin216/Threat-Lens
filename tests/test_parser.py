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
        "0x002|"
    )

    icmp_request_line = (
        "1755100001.456|"
        "192.168.100.4|"
        "192.168.100.3|"
        "1|||"
        "98||8"
    )

    icmp_reply_line = (
        "1755100002.456|"
        "192.168.100.3|"
        "192.168.100.4|"
        "1|||"
        "98||0"
    )

    tcp_packet = parser.parse(tcp_line)
    icmp_request = parser.parse(icmp_request_line)
    icmp_reply = parser.parse(icmp_reply_line)

    print("TCP packet:")
    print(tcp_packet)

    print("\nICMP request:")
    print(icmp_request)

    print("\nICMP reply:")
    print(icmp_reply)

    assert tcp_packet is not None
    assert tcp_packet.protocol == "TCP"
    assert tcp_packet.icmp_type is None

    assert icmp_request is not None
    assert icmp_request.protocol == "ICMP"
    assert icmp_request.icmp_type == 8

    assert icmp_reply is not None
    assert icmp_reply.protocol == "ICMP"
    assert icmp_reply.icmp_type == 0

    print("\nParser test passed")


if __name__ == "__main__":
    main()