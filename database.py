import sqlite3


DATABASE = "data/cybershield.db"


def create_database():

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            attack_type TEXT,

            source_ip TEXT,

            destination_ip TEXT,

            count INTEGER,

            risk_level TEXT,

            description TEXT

        )
    """)

    connection.commit()
    connection.close()

def save_alert(alert):

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id
        FROM security_alerts
        WHERE attack_type = ?
        AND source_ip = ?
        AND destination_ip = ?
        AND count = ?
        AND risk_level = ?
        AND description = ?
    """, (
        alert["attack_type"],
        alert["source_ip"],
        alert["destination_ip"],
        alert["count"],
        alert["risk"],
        alert["description"]
    ))

    existing = cursor.fetchone()

    if existing:
        connection.close()
        return False

    cursor.execute("""
        INSERT INTO security_alerts (
            attack_type,
            source_ip,
            destination_ip,
            count,
            risk_level,
            description
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        alert["attack_type"],
        alert["source_ip"],
        alert["destination_ip"],
        alert["count"],
        alert["risk"],
        alert["description"]
    ))

    connection.commit()
    connection.close()

    return True


def get_alerts():

    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM security_alerts
        ORDER BY id DESC
    """)

    alerts = cursor.fetchall()

    connection.close()

    return alerts


if __name__ == "__main__":

    create_database()

    print("CyberShield database created successfully.")
    print(f"Database location: {DATABASE}")