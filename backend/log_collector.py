import pandas as pd
from pathlib import Path

def collect_logs():
    file_path = Path(__file__).resolve().parent.parent / "data" / "sample_logs.csv"

    logs = pd.read_csv(file_path)

    return logs


if __name__ == "__main__":
    logs = collect_logs()

    print("Security Logs Collected Successfully!")
    print(logs)