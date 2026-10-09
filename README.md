# ThreatLens — AI-Powered Network Intrusion Detection System

ThreatLens is a real-time network intrusion detection system that analyzes network traffic, identifies suspicious behavior using rule-based detection, enriches security alerts with Airia AI, and forwards the resulting events to Wazuh for centralized security monitoring and investigation.

The project combines network traffic analysis, automated threat classification, and SIEM integration in a single detection pipeline.

## Architecture

```text
                 Network Traffic
                        |
                        v
              +-------------------+
              |   TShark Capture  |
              | Packet Collection |
              +-------------------+
                        |
                        v
              +-------------------+
              |   Packet Parser   |
              | Flow Management   |
              +-------------------+
                        |
                        v
              +-------------------+
              | Traffic Windows   |
              | Feature Extraction|
              +-------------------+
                        |
                        v
              +-------------------+
              | Rule-Based        |
              | Detection Engine  |
              +-------------------+
                        |
                        v
              +-------------------+
              |    Alert Manager  |
              | Deduplication     |
              | Alert Lifecycle   |
              +-------------------+
                        |
                        v
              +-------------------+
              |     Airia AI      |
              | Threat Enrichment |
              +-------------------+
                        |
                        v
              +-------------------+
              | Enriched JSON Logs|
              +-------------------+
                        |
                        v
              +-------------------+
              |   Wazuh Agent     |
              +-------------------+
                        |
                        v
              +-------------------+
              |   Wazuh Manager   |
              +-------------------+
                        |
                        v
              +-------------------+
              | Wazuh Indexer and |
              |     Dashboard    |
              +-------------------+
```

## Key Features

### 1. Real-Time Network Traffic Capture
- Uses TShark to capture and parse network packets from a monitored network interface.
- Extracts packet information such as source and destination IP addresses, ports, protocols, packet sizes, and TCP flags.
- Processes observed traffic through a Python-based detection pipeline.

### 2. Flow Tracking and Traffic Analysis
- Groups related packets into network flows.
- Maintains traffic statistics using sliding time windows.
- Extracts behavioral features to identify suspicious network activity.

Features used by the detection pipeline include:
- Packet and byte rates.
- TCP SYN, ACK, RST, and FIN statistics.
- Unique destination IP addresses and ports.
- Connections to sensitive ports.
- ICMP traffic statistics.
- Flow duration and traffic volume.

### 3. Rule-Based Intrusion Detection
ThreatLens evaluates extracted traffic features against detection rules to identify suspicious network behavior.

Examples of relevant indicators include:
- High numbers of unique destination ports.
- Unusual TCP SYN activity.
- Connections involving sensitive ports.
- Abnormal ICMP activity.
- Unusual packet or byte rates.

The detection engine produces structured results containing a risk score, severity, detection reasons, and relevant traffic context.

**Detection approach:** ThreatLens uses rule-based anomaly detection. Airia AI is used to enrich alerts after detection rather than replacing the core detection engine.

### 4. Alert Management
The Alert Manager organizes repeated detections into manageable security alerts.

Its responsibilities include:
- Deduplicating alerts using the source IP and detection type.
- Tracking alert IDs, occurrence counts, timestamps, risk scores, and severity.
- Maintaining alert states such as `OPEN` and `RESOLVED`.
- Updating existing alerts when repeated activity is detected.
- Resolving stale alerts after a configured period of inactivity.

This helps reduce repetitive notifications and provides a clearer view of ongoing suspicious activity.

### 5. AI-Powered Security Enrichment
ThreatLens integrates Airia AI through a REST API to enrich alerts with additional security context.

The pipeline supplies structured detection results and traffic features to the AI service. The returned enrichment can include:

- Attack classification.
- Confidence and severity assessments.
- MITRE ATT&CK technique mapping.
- Investigation summaries.
- Recommended investigation and remediation steps.

For example, traffic contacting numerous destination ports with repeated TCP SYN attempts may be classified as **Network Service Scanning**, with the associated MITRE ATT&CK technique **T1046 — Network Service Discovery**.

AI enrichment supplements the rule-based engine; it is not treated as independent proof that an attack occurred.

### 6. Wazuh SIEM Integration
ThreatLens forwards enriched security events into a Wazuh monitoring workflow.

The integration works as follows:

1. ThreatLens writes enriched events as JSON lines to `/var/log/threatlens/alerts.json`.
2. The Wazuh Agent monitors the file and forwards new events to the Wazuh Manager.
3. Wazuh decodes the JSON fields and applies configured detection rules.
4. The Wazuh Indexer stores the resulting security events.
5. The Wazuh Dashboard provides a centralized interface for monitoring and investigating alerts.

A custom Wazuh rule identifies ThreatLens events using the `event_type` field.

This integration demonstrates how a custom detection application can feed security events into a SIEM workflow.

## Technology Stack

| Component | Technology |
|---|---|
| Programming language | Python |
| Packet capture and analysis | TShark |
| Traffic processing | Flow tracking and sliding-window analysis |
| Detection | Rule-based anomaly detection |
| AI enrichment | Airia AI REST API |
| Event format | JSON |
| SIEM integration | Wazuh Agent, Manager, Indexer, Dashboard |
| Operating environment | Linux |
| Networking concepts | TCP/IP, ports, packet analysis, network flows |

## Example Detection Scenario

An Nmap service scan can be used to demonstrate ThreatLens in an authorized lab environment.

1. Nmap generates network traffic toward a monitored machine.
2. TShark captures the packets observed on the monitored interface.
3. ThreatLens groups packets into flows and calculates traffic features.
4. The detection engine identifies suspicious behavior, such as a high number of unique destination ports and a high TCP SYN ratio.
5. The Alert Manager creates or updates a security alert.
6. Airia AI enriches the alert with an attack classification, MITRE ATT&CK mapping, and investigation recommendations.
7. The enriched JSON event is forwarded through Wazuh and becomes available in the dashboard.

An example of an AI-enriched classification is:

- **Attack classification:** Network Service Scanning
- **Severity:** High
- **MITRE ATT&CK:** T1046 — Network Service Discovery
- **Investigation:** Verify whether the scanning source is authorized and examine the targeted hosts and ports.

The classification is an assessment based on observed traffic and should be validated against the surrounding environment.

## Project Setup

### Prerequisites

Before running ThreatLens, ensure you have:

- A Linux environment with Python installed.
- TShark installed and access to the network interface you intend to monitor.
- The project dependencies installed.
- An Airia API key and configured API endpoint for AI enrichment.
- A running Wazuh environment if you want centralized SIEM monitoring.

### 1. Clone the Repository

```bash
git clone <YOUR_REPOSITORY_URL>
cd ThreatLens
```

Replace the repository URL with your GitHub repository URL.

### 2. Install TShark

On Ubuntu or a compatible Debian-based distribution:

```bash
sudo apt update
sudo apt install tshark
```

Verify the installation:

```bash
tshark --version
```

Ensure the capture interface is available and that the account running ThreatLens has the necessary packet-capture permissions.

### 3. Set Up Python

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the dependencies listed in the project's `requirements.txt`:

```bash
pip install -r requirements.txt
```

If your repository does not yet contain a `requirements.txt`, create one from the actual project environment before publishing the setup instructions.

### 4. Configure Airia AI

Configure the API credentials in your local environment. For example:

```bash
export AIRIA_API_KEY="your_api_key"
export AIRIA_API_URL="your_airia_endpoint"
```

Use the actual endpoint expected by your `AiriaClient` implementation.

Do not commit API keys, credentials, or `.env` files containing secrets to version control. If the project uses a `.env` file, ensure it is excluded through `.gitignore`.

### 5. Configure Wazuh

For centralized monitoring:

1. Install and configure the Wazuh Manager and Dashboard.
2. Enroll the Linux machine running ThreatLens as a Wazuh Agent.
3. Configure the agent to monitor the ThreatLens JSON log file.

Add the following entry to the Wazuh Agent configuration file, typically `/var/ossec/etc/ossec.conf`:

```xml
<localfile>
    <location>/var/log/threatlens/alerts.json</location>
    <log_format>json</log_format>
</localfile>
```

Configure the corresponding custom Wazuh detection rule on the manager:

```xml
<rule id="100500" level="12">
    <decoded_as>json</decoded_as>
    <field name="event_type">threatlens_alert</field>
    <description>ThreatLens: Security alert detected</description>
    <group>threatlens,network_security,</group>
</rule>
```

Ensure the log file exists, permissions allow the agent to read it, and the agent can communicate with the manager. Restart or reload the relevant services after configuration changes.

Refer to the [official Wazuh documentation](https://documentation.wazuh.com/current/) for installation, agent enrollment, and configuration instructions.

### 6. Run ThreatLens

Start the application using the project's entry point:

```bash
python3 run_ids.py
```

Use the appropriate privileges and interface configuration required by your environment. If elevated privileges are necessary and you rely on exported environment variables, make sure they are preserved securely rather than assuming `sudo` will inherit them.

With the pipeline running, generate authorized test traffic from another machine and observe the detection output and enriched events.

## Security and Testing

ThreatLens is intended for authorized network monitoring and controlled security testing.

Recommended validation scenarios include:

- Authorized Nmap scans against a lab target.
- Controlled TCP connection attempts.
- Traffic involving multiple destination ports.
- Repeated traffic from a known test source.
- Verification that enriched JSON events appear in the Wazuh Dashboard.
- Verification that AI enrichment failures do not terminate the core detection pipeline.

Run tests only on systems and networks you own or have explicit permission to assess.

## Current Scope and Limitations

- Detection is based on implemented rules and extracted traffic features; it is not a trained machine-learning intrusion detection model.
- AI enrichment depends on the availability and correctness of the external Airia service.
- Detection quality depends on packet visibility, capture permissions, traffic patterns, feature extraction, and rule thresholds.
- Rule-based detection can produce false positives or miss attacks that do not match the implemented patterns.
- Wazuh provides centralized event monitoring and investigation; it does not automatically guarantee that every event represents a confirmed intrusion.

Potential future improvements include additional detection rules, improved source/destination directionality, configurable thresholds, broader protocol coverage, persistent alert storage, and systematic false-positive evaluation.

## Future Enhancements

- Expand detection coverage for additional network attack patterns.
- Improve detection accuracy through rule tuning and contextual analysis.
- Add configurable thresholds and detection policies.
- Improve alert investigation workflows and event correlation.
- Evaluate detection precision, recall, latency, and throughput using repeatable test datasets.
- Explore statistical or machine-learning-based detection as a separate, experimentally validated component.

## Learning Outcomes

This project brings together practical concepts in:

- Network packet capture and TCP/IP analysis.
- Network flow tracking and traffic feature extraction.
- Rule-based intrusion detection.
- REST API integration and AI-assisted security analysis.
- MITRE ATT&CK mapping.
- JSON-based security event logging.
- SIEM integration and centralized security monitoring.
- Linux-based security tooling and troubleshooting.

## Author

**Vipin Chandran**

B.Tech — Computer Science and Engineering

Interested in backend engineering, cloud infrastructure, and cybersecurity.

## Disclaimer

ThreatLens is an educational cybersecurity project. It is not a replacement for a production-grade IDS or SIEM, and its alerts should be investigated before taking defensive action. Use it only in environments where you have authorization to monitor network traffic.
