def classify_risk(alert):

    attack_type = alert["attack_type"]
    count = alert["count"]

    if attack_type == "IOC_MATCH":
        return "Critical"

    elif attack_type == "PORT_SCAN" and count >= 15:
        return "High"

    elif attack_type == "EXCESSIVE_CONNECTIONS" and count >= 15:
        return "High"

    elif attack_type == "SUSPICIOUS_PORT":
        return "Medium"

    else:
        return "Low"


def add_risk_levels(alerts):

    for alert in alerts:
        alert["risk"] = classify_risk(alert)

    return alerts


if __name__ == "__main__":

    test_alerts = [
        {
            "attack_type": "PORT_SCAN",
            "count": 18
        },
        {
            "attack_type": "EXCESSIVE_CONNECTIONS",
            "count": 18
        },
        {
            "attack_type": "SUSPICIOUS_PORT",
            "count": 1
        },
        {
            "attack_type": "IOC_MATCH",
            "count": 1
        }
    ]

    alerts = add_risk_levels(test_alerts)

    print("\nCyberShield - Risk Classification")
    print("=" * 50)

    for alert in alerts:

        print(
            f"{alert['attack_type']:<25} "
            f"Risk: {alert['risk']}"
        )