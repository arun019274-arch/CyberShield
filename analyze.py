from parser import parse_packets
from detector import detect_suspicious_activity
from threat_intel import check_threat_intelligence
from risk import add_risk_levels
from database import create_database, save_alert


def analyze_network():

    packets = parse_packets()

    detection_alerts = detect_suspicious_activity(packets)

    ioc_alerts = check_threat_intelligence(packets)

    all_alerts = detection_alerts + ioc_alerts

    all_alerts = add_risk_levels(all_alerts)

    return packets, all_alerts


if __name__ == "__main__":

    create_database()

    packets, alerts = analyze_network()

    print("\nCyberShield - Complete Security Analysis")
    print("=" * 80)

    print(f"\nTotal packets analyzed: {len(packets)}")
    print(f"Total security alerts: {len(alerts)}")

    saved_count = 0

    for alert in alerts:

        save_alert(alert)
        saved_count += 1

        print("\n" + "-" * 80)

        print(f"Attack Type    : {alert['attack_type']}")
        print(f"Source IP      : {alert['source_ip']}")
        print(f"Destination IP : {alert['destination_ip']}")
        print(f"Count          : {alert['count']}")
        print(f"Risk Level     : {alert['risk']}")
        print(f"Description    : {alert['description']}")

    print("\n" + "=" * 80)
    print(f"Alerts saved to database: {saved_count}")