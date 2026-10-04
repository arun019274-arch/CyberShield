from scapy.all import rdpcap, IP, TCP, UDP


PCAP_FILE = "pcaps/sample.pcap"


def parse_packets():

    packets = rdpcap(PCAP_FILE)

    results = []

    for packet in packets:

        if IP not in packet:
            continue

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        packet_length = len(packet)

        protocol = "OTHER"
        source_port = "-"
        destination_port = "-"

        if TCP in packet:
            protocol = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        elif UDP in packet:
            protocol = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        results.append({
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol": protocol,
            "source_port": source_port,
            "destination_port": destination_port,
            "packet_length": packet_length
        })

    return results


if __name__ == "__main__":

    packets = parse_packets()

    print("\nCyberShield - Network Traffic Parser")
    print("=" * 70)

    for packet in packets:

        print(
            f"Source: {packet['source_ip']} | "
            f"Destination: {packet['destination_ip']} | "
            f"Protocol: {packet['protocol']} | "
            f"Source Port: {packet['source_port']} | "
            f"Destination Port: {packet['destination_port']} | "
            f"Length: {packet['packet_length']}"
        )

    print("\nTotal packets:", len(packets))