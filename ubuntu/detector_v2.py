
import csv
import re
from collections import defaultdict, Counter

LOG_FILE = "honeypot_events_v2.csv"

# Suspicious command patterns and their classifications
RULES = [
    {
        "pattern": r"\bcat\s+.*password",
        "category": "CREDENTIAL DISCOVERY",
        "severity": "HIGH",
        "reason": "Attempt to inspect a password-related file"
    },
    {
        "pattern": r"\bcat\s+.*(?:/etc/passwd|/etc/shadow)\b",
        "category": "USER ENUMERATION",
        "severity": "HIGH",
        "reason": "Attempt to inspect system account files"
    },
    {
        "pattern": r"\b(?:uname|hostname|lscpu|lsb_release)\b",
        "category": "SYSTEM RECONNAISSANCE",
        "severity": "LOW",
        "reason": "Attempt to gather system information"
    },
    {
        "pattern": r"\b(?:find|locate|tree)\b",
        "category": "FILESYSTEM DISCOVERY",
        "severity": "MEDIUM",
        "reason": "Attempt to discover files or directories"
    },
    {
        "pattern": r"\b(?:ifconfig|ip\s+addr|ip\s+route|netstat|ss)\b",
        "category": "NETWORK RECONNAISSANCE",
        "severity": "MEDIUM",
        "reason": "Attempt to inspect network configuration"
    },
    {
        "pattern": r"\b(?:ps|top|htop)\b",
        "category": "PROCESS RECONNAISSANCE",
        "severity": "LOW",
        "reason": "Attempt to inspect running processes"
    },
    {
        "pattern": r"\b(?:sudo|su)\b",
        "category": "PRIVILEGE ESCALATION INTEREST",
        "severity": "MEDIUM",
        "reason": "Attempt to use elevated privileges or switch users"
    }
]


def classify_command(command):
    """Return all detection rules matching a command."""

    command = command.strip().lower()

    matches = []

    for rule in RULES:
        if re.search(rule["pattern"], command):
            matches.append(rule)

    return matches


def analyze_logs():

    activity = defaultdict(list)
    category_counts = Counter()

    try:
        with open(LOG_FILE, "r", newline="") as file:
            reader = csv.DictReader(file)

            for row in reader:

                if row["event"] != "COMMAND_EXECUTED":
                    continue

                ip = row["source_ip"]
                command = row["details"]

                activity[ip].append(command)

    except FileNotFoundError:
        print(f"[ERROR] {LOG_FILE} not found.")
        return

    print("\n========== HONEYPOT ATTACK ANALYSIS ==========\n")

    total_commands = 0
    total_alerts = 0

    for ip, commands in activity.items():

        print(f"\nSource IP: {ip}")
        print(f"Commands executed: {len(commands)}")

        total_commands += len(commands)

        for command in commands:

            matches = classify_command(command)

            for match in matches:

                total_alerts += 1
                category_counts[match["category"]] += 1

                print(
                    f"\n[ALERT] {match['severity']} - "
                    f"{match['category']}"
                )

                print(f"Command: {command}")
                print(f"Reason: {match['reason']}")

    print("\n========== SUMMARY ==========")
    print(f"Total commands analyzed: {total_commands}")
    print(f"Suspicious activity indicators: {total_alerts}")

    if category_counts:
        print("\nDetection categories:")

        for category, count in category_counts.items():
            print(f"- {category}: {count}")
    else:
        print("\nNo suspicious command patterns detected.")

    print("\n==============================================")


if __name__ == "__main__":
    analyze_logs()
