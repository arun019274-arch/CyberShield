from database import get_alerts


alerts = get_alerts()

print("\nCyberShield - Stored Security Alerts")
print("=" * 80)

for alert in alerts:

    print("\n" + "-" * 80)

    print(f"ID             : {alert['id']}")
    print(f"Attack Type    : {alert['attack_type']}")
    print(f"Source IP      : {alert['source_ip']}")
    print(f"Destination IP : {alert['destination_ip']}")
    print(f"Count          : {alert['count']}")
    print(f"Risk Level     : {alert['risk_level']}")
    print(f"Description    : {alert['description']}")

print("\n" + "=" * 80)
print("Total stored alerts:", len(alerts))