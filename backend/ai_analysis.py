def analyze_incidents(threats):
    analyses = []

    for _, threat in threats.iterrows():
        if threat["severity"] == "HIGH":
            explanation = (
                f"User {threat['username']} has "
                f"{threat['failed_attempts']} failed login attempts. "
                "This may indicate a brute-force attack."
            )
        else:
            explanation = "Suspicious activity detected. Monitor this user."

        analyses.append(explanation)

    result = threats.copy()
    result["ai_analysis"] = analyses

    return result


if __name__ == "__main__":
    from backend.log_collector import collect_logs
    from backend.threat_detection import detect_threats

    logs = collect_logs()
    threats = detect_threats(logs)

    results = analyze_incidents(threats)

    print("\nAI Incident Analysis:")
    print(results[["username", "severity", "ai_analysis"]].to_string(index=False))