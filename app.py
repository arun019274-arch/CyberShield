from flask import Flask, render_template
from database import get_alerts


app = Flask(__name__)


@app.route("/")
def dashboard():

    alerts = get_alerts()

    total_alerts = len(alerts)

    critical = 0
    high = 0
    medium = 0
    low = 0

    for alert in alerts:

        if alert["risk_level"] == "Critical":
            critical += 1

        elif alert["risk_level"] == "High":
            high += 1

        elif alert["risk_level"] == "Medium":
            medium += 1

        elif alert["risk_level"] == "Low":
            low += 1

    return render_template(
        "dashboard.html",
        alerts=alerts,
        total_alerts=total_alerts,
        critical=critical,
        high=high,
        medium=medium,
        low=low
    )


if __name__ == "__main__":
    app.run(debug=True)