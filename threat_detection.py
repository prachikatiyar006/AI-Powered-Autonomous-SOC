def detect_threats(logs):
    failed_logs = logs[logs["status"] == "failed"]

    threats = failed_logs.groupby(
        ["username", "ip_address"]
    ).size().reset_index(name="failed_attempts")

    threats = threats[threats["failed_attempts"] >= 3]

    threats["severity"] = "HIGH"
    threats["threat"] = "Multiple Failed Login Attempts"

    return threats


if __name__ == "__main__":
    from log_collector import collect_logs

    logs = collect_logs()
    threats = detect_threats(logs)

    print("\nThreat Detection Results:")
    print(threats)