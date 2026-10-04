SUSPICIOUS_IPS = {
    "192.168.1.50",
    "10.10.10.50",
    "172.16.0.99"
}


def check_ip(ip):

    if ip in SUSPICIOUS_IPS:
        return True

    return False


def check_threat_intelligence(packets):

    alerts = []

    checked_ips = set()

    for packet in packets:

        source_ip = packet["source_ip"]

        if source_ip in checked_ips:
            continue

        checked_ips.add(source_ip)

        if check_ip(source_ip):

            alerts.append({
                "attack_type": "IOC_MATCH",
                "source_ip": source_ip,
                "destination_ip": packet["destination_ip"],
                "count": 1,
                "description": (
                    f"Source IP {source_ip} matched "
                    f"a known suspicious IOC."
                )
            })

    return alerts


if __name__ == "__main__":

    from parser import parse_packets

    packets = parse_packets()

    alerts = check_threat_intelligence(packets)

    print("\nCyberShield - Threat Intelligence")
    print("=" * 70)

    if not alerts:

        print("No IOC matches found.")

    else:

        for alert in alerts:

            print("\n" + "-" * 70)
            print(f"Alert Type    : {alert['attack_type']}")
            print(f"Source IP     : {alert['source_ip']}")
            print(f"Destination IP: {alert['destination_ip']}")
            print(f"Description   : {alert['description']}")

    print("\nTotal IOC alerts:", len(alerts))