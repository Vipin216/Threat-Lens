from ai.airia_client import AiriaClient


alert = {
    "source_ip": "192.168.100.4",
    "destination_ip": "192.168.100.3",
    "protocol": "TCP",
    "packets": 100,
    "packets_per_second": 1.67,
    "unique_destination_ports": 100,
    "syn_ratio": 1.0,
    "syns_per_second": 1.67,
    "sensitive_ports": [21, 22],
    "risk_score": 100,
    "detected": True,
    "detections": [
        "High number of unique destination ports",
        "High SYN ratio across multiple ports",
        "Traffic to sensitive ports",
        "Multiple sensitive services targeted"
    ]
}


def main():
    print("[+] Initializing Airia client...")

    client = AiriaClient()

    print("[+] Sending ThreatLens alert to Airia...")

    result = client.analyze(alert)

    print("\n[+] Airia enrichment received:")
    print(f"Attack Type : {result.get('attack_type')}")
    print(f"Severity    : {result.get('severity')}")
    print(f"Confidence  : {result.get('confidence')}")
    print(f"MITRE ID    : {result.get('mitre_attack_id')}")
    print(f"MITRE Name  : {result.get('mitre_attack_name')}")
    print(f"Summary     : {result.get('summary')}")

    print("\nRecommendations:")

    for recommendation in result.get("recommendations", []):
        print(f"  - {recommendation}")


if __name__ == "__main__":
    main()