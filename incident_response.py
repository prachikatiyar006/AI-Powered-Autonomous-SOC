def respond_to_incidents(threats):
    responses = []

    for _, threat in threats.iterrows():
        if threat["severity"] == "HIGH":
            action = "IP Block Recommended"
        else:
            action = "Monitor Activity"

        responses.append(action)

    threats = threats.copy()
    threats["response_action"] = responses

    return threats


if __name__ == "__main__":
    from log_collector import collect_logs
    from threat_detection import detect_threats

    logs = collect_logs()
    threats = detect_threats(logs)

    results = respond_to_incidents(threats)

    print("\nIncident Response Results:")
    print(results.to_string(index=False))