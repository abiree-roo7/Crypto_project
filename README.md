# Crypto Project - TLS IDS

This project connects three parts of a TLS intrusion detection workflow:

1. `part1_extraction`: extracts TLS sessions from a PCAP file.
2. `partie2_moteursoc`: analyzes TLS sessions and generates security alerts.
3. `partie_3`: signs alerts, stores them in SQLite, and exports signed reports.

## Install

```bash
python -m pip install -r requirements.txt
```

## Run the Complete Pipeline

Analyze an existing sessions JSON file:

```bash
python code.py --sessions sessions_tls.json --alerts-out alerts.json
```

Analyze a PCAP file and create sessions plus alerts:

```bash
python code.py --pcap test.pcap --sessions-out sessions_tls.json --alerts-out alerts.json
```

Sign alerts, store them in SQLite, and export a signed report:

```bash
python code.py --sessions sessions_tls.json --alerts-out alerts.json --store --report-out report.json
```

## Part 2 Features

The detection engine now supports:

- weak TLS version detection
- weak selected cipher detection
- weak offered cipher detection
- expired and self-signed certificate detection
- certificate near-expiry warnings
- missing certificate detection
- missing or malformed SNI detection
- suspicious SNI keyword detection
- blacklisted JA3 and JA3S detection
- unusual cipher-suite count detection
