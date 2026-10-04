from parser import parse_packets


def detect_port_scan(packets):

    alerts = []

    connections = {}

    for packet in packets:

        source_ip = packet["source_ip"]
        destination_ip = packet["destination_ip"]
        destination_port = packet["destination_port"]

        key = (source_ip, destination_ip)

        if key not in connections:
            connections[key] = set()

        connections[key].add(destination_port)

    for (source_ip, destination_ip), ports in connections.items():

        if len(ports) >= 10:

            alerts.append({
                "attack_type": "PORT_SCAN",
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "count": len(ports),
                "description": (
                    f"Possible port scan detected from "
                    f"{source_ip} targeting {destination_ip}. "
                    f"{len(ports)} different ports were contacted."
                )
            })

    return alerts


def detect_excessive_connections(packets):

    alerts = []

    connection_count = {}

    for packet in packets:

        source_ip = packet["source_ip"]

        if source_ip not in connection_count:
            connection_count[source_ip] = 0

        connection_count[source_ip] += 1

    for source_ip, count in connection_count.items():

        if count >= 15:

            alerts.append({
                "attack_type": "EXCESSIVE_CONNECTIONS",
                "source_ip": source_ip,
                "destination_ip": "Multiple",
                "count": count,
                "description": (
                    f"Excessive network connections detected "
                    f"from {source_ip}. Total connections: {count}."
                )
            })

    return alerts


def detect_suspicious_ports(packets):

    alerts = []

    suspicious_ports = {
        21,
        23,
        445,
        3389,
        5900
    }

    for packet in packets:

        destination_port = packet["destination_port"]

        if destination_port in suspicious_ports:

            alerts.append({
                "attack_type": "SUSPICIOUS_PORT",
                "source_ip": packet["source_ip"],
                "destination_ip": packet["destination_ip"],
                "count": 1,
                "description": (
                    f"Connection to potentially sensitive "
                    f"destination port {destination_port} detected."
                )
            })

    return alerts


def detect_suspicious_activity(packets):

    alerts = []

    alerts.extend(detect_port_scan(packets))
    alerts.extend(detect_excessive_connections(packets))
    alerts.extend(detect_suspicious_ports(packets))

    return alerts


if __name__ == "__main__":

    packets = parse_packets()

    alerts = detect_suspicious_activity(packets)

    print("\nCyberShield - Intrusion Detection")
    print("=" * 70)

    if not alerts:

        print("No suspicious activity detected.")

    else:

        for alert in alerts:

            print("\n" + "-" * 70)
            print(f"Attack Type    : {alert['attack_type']}")
            print(f"Source IP      : {alert['source_ip']}")
            print(f"Destination IP : {alert['destination_ip']}")
            print(f"Count          : {alert['count']}")
            print(f"Description    : {alert['description']}")

    print("\nTotal alerts:", len(alerts))