# Crypto Project TLS IDS Documentation

## Project Overview

This project is a TLS Intrusion Detection System built in separate parts and then connected into one pipeline.

The current implemented flow is:

```text
PCAP file
  -> Part 1: TLS extraction
  -> sessions_tls.json
  -> Part 2: Detection engine
  -> alerts.json
  -> Part 3: Signature, database, and report export
  -> alerts.db / report.json
```

Part 4 is planned for the dashboard interface. It can consume the JSON reports or read alerts from the SQLite database.

## Part 1 - TLS Extraction

Folder:

```text
part1_extraction/
```

### Role

Part 1 reads network traffic and extracts TLS session information. It can work from a PCAP file and is designed to identify TLS packets, parse ClientHello and ServerHello messages, extract certificate data when available, and calculate JA3/JA3S fingerprints.

### Main Files

```text
capture.py
```

Captures packets or reads packets from a PCAP file.

Important functions:

```python
capture_depuis_pcap(chemin_fichier)
extraire_payload(paquet)
est_tls(data)
est_client_hello(data)
est_server_hello(data)
```

```text
tls_parser.py
```

Parses TLS handshake messages.

Important functions:

```python
parser_client_hello(data)
parser_server_hello(data)
```

Extracted fields include:

```text
TLS version
SNI
cipher suites
extensions
elliptic groups
selected cipher suite
```

```text
ja3.py
```

Calculates JA3 and JA3S fingerprints.

Important functions:

```python
calculer_ja3(client_hello)
calculer_ja3s(server_hello)
```

```text
cert_parser.py
```

Extracts and analyzes X.509 certificates when certificate packets are available.

Important functions:

```python
extraire_certificat_depuis_paquet(data)
analyser_certificat(cert_bytes)
```

```text
session.py
```

Orchestrates all extraction modules and creates complete TLS session objects.

Important functions:

```python
sessions_depuis_pcap(chemin_pcap)
sauvegarder_sessions(sessions, fichier_sortie)
```

### Output

Part 1 produces a JSON file such as:

```text
sessions_tls.json
```

Example structure:

```json
{
  "session_id": "unique-session-id",
  "timestamp": 1780146276.0808506,
  "src_ip": "192.168.1.10",
  "dst_ip": "93.184.216.34",
  "src_port": 54231,
  "dst_port": 443,
  "client_hello": {
    "version_nom": "TLS 1.2",
    "sni": "example.com",
    "cipher_suites": [49195, 49196]
  },
  "server_hello": null,
  "certificat": null,
  "empreintes": {
    "ja3": "d6bb84ccd120d816163f21d0125cad1b",
    "ja3s": null
  }
}
```

## Part 2 - Detection Engine

Folder:

```text
partie2_moteursoc/
```

### Role

Part 2 analyzes TLS session objects and generates security alerts. It accepts either:

1. A full session object from Part 1.
2. A simple flat dictionary used for testing.

### Main Files

```text
rules.py
```

Contains detection lists and thresholds:

```python
WEAK_TLS_VERSIONS
WEAK_CIPHER_KEYWORDS
WEAK_CIPHER_IDS
BLACKLISTED_JA3
BLACKLISTED_JA3S
SUSPICIOUS_SNI_KEYWORDS
CERT_EXPIRY_WARNING_DAYS
MAX_REASONABLE_CIPHER_SUITES
```

```text
alert_engine.py
```

Creates standardized alerts compatible with Part 3.

Main function:

```python
create_alert(...)
```

```text
detector.py
```

Contains the main detection logic.

Main class:

```python
TLSDetector
```

Main method:

```python
TLSDetector().analyze(tls_data)
```

### Detection Features

Part 2 currently detects:

```text
Weak TLS versions: SSL 3.0, TLS 1.0, TLS 1.1
Weak selected cipher suites
Weak offered cipher suites
Expired certificates
Self-signed certificates
Certificates close to expiration
Missing certificates
Missing SNI
Malformed SNI
Suspicious SNI keywords
Blacklisted JA3 fingerprints
Blacklisted JA3S fingerprints
Unusual cipher suite counts
External public TLS flows
```

### Alert Output

Part 2 produces alerts in this format:

```json
{
  "timestamp": "2026-06-05T09:36:16.561430",
  "severity": "info",
  "alert_type": "missing_certificate",
  "source_ip": "192.168.1.10",
  "dest_ip": "93.184.216.34",
  "details": {
    "session_id": "session-id",
    "src_port": 54231,
    "dst_port": 443,
    "sni": "example.com",
    "message": "No server certificate was extracted for this TLS session",
    "ja3": "d6bb84ccd120d816163f21d0125cad1b"
  }
}
```

The alert also keeps older compatibility fields:

```text
rule
description
src_ip
dst_ip
ja3
```

This makes it usable by both the old Part 2 prototype and the newer Part 3 storage system.

## Part 3 - Signature, Storage, and Report Export

Folder:

```text
partie_3/
```

### Role

Part 3 secures and stores alerts. It signs alerts using ECDSA, verifies signatures, stores signed alerts in SQLite, and exports a signed report.

### Main Files

```text
key_manager.py
```

Generates and loads ECDSA keys.

Important functions:

```python
generate_keys()
load_private_key()
load_public_key()
```

Keys are stored in:

```text
keys/private_key.pem
keys/public_key.pem
```

```text
signer.py
```

Signs an alert.

Important function:

```python
sign_alert(alert)
```

```text
verifier.py
```

Verifies a signed alert.

Important function:

```python
verify_alert(signed_alert)
```

```text
database.py
```

Stores signed alerts in SQLite.

Important functions:

```python
init_db()
insert_alert(signed_alert)
get_all_alerts()
get_alerts_by_severity(severity)
```

Database output:

```text
alerts.db
```

```text
exporter.py
```

Exports all stored alerts into a signed report.

Important function:

```python
export_signed_report(output_path)
```

Report output:

```text
report.json
```

### Security Purpose

Part 3 helps guarantee alert integrity. If an alert is modified after signing, verification should fail. This is useful for forensic or SOC workflows where alert data must be trusted.

## Main Integration File

File:

```text
code.py
```

### Role

This file connects Part 1, Part 2, and Part 3 into one command-line pipeline.

### Commands

Analyze an existing sessions file:

```powershell
python code.py --sessions sessions_tls.json --alerts-out alerts.json
```

Analyze a PCAP file:

```powershell
python code.py --pcap test.pcap --sessions-out sessions_tls.json --alerts-out alerts.json
```

Analyze sessions, sign alerts, store them in SQLite, and export a signed report:

```powershell
python code.py --sessions sessions_tls.json --alerts-out alerts.json --store --report-out report.json
```

### Windows Dependency Note

If dependencies were installed into `.deps`, run this before testing:

```powershell
$env:PYTHONPATH='.deps'
$env:PYTHONDONTWRITEBYTECODE='1'
```

## Part 4 - Dashboard

Status:

```text
Prototype dashboard available locally.
Final dashboard can still be completed or replaced by the dashboard team.
```

### Planned Role

Part 4 should provide a visual dashboard for the alerts and reports generated by the first three parts.

Current prototype folder:

```text
partie_4_dashboard/
```

Run it with:

```powershell
python -m partie_4_dashboard.app
```

### Recommended Inputs

The dashboard can use one of these data sources:

```text
alerts.json
report.json
alerts.db
```

### Recommended Features

The dashboard should show:

```text
Total alerts
Alerts by severity
Alerts by type
Recent alerts
Source and destination IPs
JA3/JA3S fingerprints
SNI/domain indicators
Certificate problems
Signed report verification status
```

### Suggested Pages

```text
Overview page
Alerts table
Alert details page
Reports page
Search/filter page
```

### Integration Suggestion

The simplest dashboard integration is:

```text
Dashboard reads alerts.json or report.json
Dashboard displays alert statistics and details
```

A more advanced integration is:

```text
Dashboard reads alerts.db
Dashboard provides filtering by severity, IP, alert type, and timestamp
```

## End-to-End Test Scenario

Run:

```powershell
$env:PYTHONPATH='.deps'
$env:PYTHONDONTWRITEBYTECODE='1'
python code.py --pcap test.pcap --sessions-out sessions_tls.json --alerts-out alerts.json
python code.py --sessions sessions_tls.json --alerts-out alerts.json --store --report-out report.json
```

Expected outputs:

```text
sessions_tls.json
alerts.json
alerts.db
report.json
keys/private_key.pem
keys/public_key.pem
```

## Summary

The three completed parts now form a connected TLS IDS:

```text
Part 1 extracts TLS sessions.
Part 2 analyzes sessions and generates security alerts.
Part 3 signs, verifies, stores, and exports alerts.
Part 4 will display the results in a dashboard.
```
