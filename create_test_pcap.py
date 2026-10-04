from scapy.all import IP, TCP, wrpcap


PCAP_FILE = "pcaps/sample.pcap"

packets = []

source_ip = "192.168.1.50"
destination_ip = "192.168.1.10"

# Normal connections
normal_ports = [80, 443, 22]

for port in normal_ports:

    packet = IP(
        src=source_ip,
        dst=destination_ip
    ) / TCP(
        sport=40000 + port,
        dport=port,
        flags="S"
    )

    packets.append(packet)


# Simulated port scan
scan_ports = [
    21, 23, 25, 53, 110,
    135, 139, 143, 445, 3306,
    3389, 5432, 5900, 8080, 8443
]

for port in scan_ports:

    packet = IP(
        src=source_ip,
        dst=destination_ip
    ) / TCP(
        sport=50000 + port,
        dport=port,
        flags="S"
    )

    packets.append(packet)


wrpcap(PCAP_FILE, packets)

print("Test PCAP created successfully.")
print(f"Location: {PCAP_FILE}")
print(f"Total packets: {len(packets)}")