"""Convert session JSONL logs to CSV for quick analysis."""

from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INPUT_PATH = ROOT / "logs" / "sessions.jsonl"
OUTPUT_PATH = ROOT / "data" / "processed" / "sessions.csv"

FIELDS = [
    "session_id",
    "ip",
    "protocol",
    "start_time",
    "end_time",
    "duration",
    "total_login_attempts",
    "commands_count",
    "suspicious_commands_count",
    "attack_ratio",
]


def main():
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    count = 0

    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as out_f:
        writer = csv.DictWriter(out_f, fieldnames=FIELDS)
        writer.writeheader()

        if not INPUT_PATH.exists():
            print("Input file not found")
            return

        with open(INPUT_PATH, "r", encoding="utf-8") as in_f:
            for line in in_f:
                line = line.strip()
                if not line:
                    continue

                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    print("Skipping invalid JSON line")
                    continue

                row = {field: data.get(field, 0) for field in FIELDS}
                row["attack_ratio"] = row["suspicious_commands_count"] / max(row["commands_count"], 1)
                writer.writerow(row)
                count += 1

    print(f"Wrote {count} rows to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()