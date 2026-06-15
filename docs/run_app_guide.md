# Complete Run Guide

This guide explains how to run and test the TLS IDS application from a fresh clone or from the local project folder.

## 1. Project Overview

The application is a four-part TLS Intrusion Detection System:

```text
PCAP / PCAPNG capture
  -> Part 1: TLS metadata extraction
  -> Part 2: rule-based detection
  -> Part 3: alert signing, SQLite storage, report export
  -> Part 4: Flask dashboard
```

The project analyzes TLS metadata only. It does not decrypt HTTPS payloads.

## 2. Requirements

Install Python 3.10 or newer, then install the project dependencies:

```powershell
python -m pip install -r requirements.txt
```

Required Python packages are listed in `requirements.txt`:

```text
scapy
pyshark
dpkt
cryptography
flask
flask-login
```

On the local Windows workspace used during development, dependencies may be installed into `.deps`. If that folder is used, run these commands before testing:

```powershell
$env:PYTHONPATH='.deps'
$env:PYTHONDONTWRITEBYTECODE='1'
```

## 3. Start the Dashboard Application

From the project root:

```powershell
cd "C:\Users\taele\OneDrive\Documents\IDS project"
$env:PYTHONPATH='.deps'
$env:PYTHONDONTWRITEBYTECODE='1'
python -m partie_4_dashboard.app
```

Open the dashboard:

```text
http://127.0.0.1:5000/
```

If port `5000` is already busy:

```powershell
python -m partie_4_dashboard.app --port 5001
```

Then open:

```text
http://127.0.0.1:5001/
```

## 4. Test With the Included Capture

The repo includes `test.pcap`, which can be used for a quick application test.

1. Start the dashboard.
2. Open `http://127.0.0.1:5000/`.
3. In `Capture file`, choose `test.pcap`.
4. Select `Run pipeline`.

Expected result:

```text
Pipeline complete for test.pcap: 1 session(s), 1 alert(s), 1 stored alert(s).
```

The dashboard should show alert counters, an alert queue, alert type counts, and top source IPs.

## 5. Test From the Command Line

You can also test the pipeline without the dashboard.

Extract TLS sessions and generate alerts:

```powershell
python code.py --pcap test.pcap --sessions-out sessions_tls.json --alerts-out alerts.json
```

Expected terminal output includes:

```text
Sessions analyzed: 1
Alerts generated: 1
Alerts saved to: alerts.json
```

Sign alerts, store them in SQLite, and export a signed report:

```powershell
python code.py --sessions sessions_tls.json --alerts-out alerts.json --store --report-out report.json
```

Expected terminal output includes:

```text
Signed and stored alerts: 1
Signed report saved to: report.json
```

## 6. Generated Files

Running the app creates or updates these files:

```text
sessions_tls.json
alerts.json
alerts.db
report.json
keys/private_key.pem
keys/public_key.pem
uploads/
```

Meaning:

```text
sessions_tls.json        TLS session metadata extracted from the capture
alerts.json              raw generated IDS alerts
alerts.db                SQLite database of signed alerts
report.json              signed JSON report used first by the dashboard
keys/                    ECDSA key pair used for alert/report signing
uploads/                 captures uploaded through the dashboard
```

These are runtime outputs and should normally not be committed to Git.

## 7. Dashboard Features

The dashboard can:

- upload `.pcap`, `.pcapng`, and `.cap` files
- run the full IDS pipeline from the browser
- start each analysis with a clean report
- show total, critical, warning, and info alert counts
- show the number of extracted sessions
- show alert queue rows with severity, rule, flow, timestamp, SNI, and JA3
- filter by severity
- search across IPs, SNI, JA3, rule names, and alert details
- summarize alert types
- summarize top source IPs
- download the signed report, raw alerts, and extracted sessions
- clear runtime data for a fresh demo

Data source priority:

```text
1. report.json
2. alerts.json
3. alerts.db
```

If `report.json` exists, the dashboard uses it first because it contains signed report output from Part 3.

For a real Wireshark test, keep `Start with a clean report` checked before selecting `Analyze capture`. After the run finishes, download `tls_ids_report.json` from the `Report Downloads` panel.

## 8. Test With a Real Capture

To test with your own network traffic:

1. Open Wireshark.
2. Start capture on `Wi-Fi` or `Ethernet`.
3. Open a few HTTPS websites after capture starts.
4. Stop capture after 20 to 40 seconds.
5. Save the file as `capture_test.pcapng` or `capture_test.pcap`.
6. Upload the file through the dashboard, or run it from the command line:

```powershell
python code.py --pcap capture_test.pcapng --sessions-out sessions_tls.json --alerts-out alerts.json
python code.py --sessions sessions_tls.json --alerts-out alerts.json --store --report-out report.json
python -m partie_4_dashboard.app
```

Important: start Wireshark before opening HTTPS websites. The extractor needs to see the TLS ClientHello at the beginning of the connection.

## 9. Troubleshooting

If imports fail:

```powershell
python -m pip install -r requirements.txt
```

If this local workspace uses `.deps`:

```powershell
$env:PYTHONPATH='.deps'
```

If the dashboard does not show new data:

```text
Refresh the browser after running the pipeline.
Check whether report.json exists.
Remember that report.json has priority over alerts.json and alerts.db.
```

If the alert count keeps increasing:

```text
Each stored run appends alerts to alerts.db.
For a clean demo, remove runtime outputs before running again.
```

PowerShell cleanup example:

```powershell
Remove-Item alerts.db, alerts.json, report.json, sessions_tls.json -ErrorAction SilentlyContinue
Remove-Item keys -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item uploads -Recurse -Force -ErrorAction SilentlyContinue
```

If no sessions are extracted from a real capture:

```text
Make sure the capture contains TCP port 443 traffic.
Make sure the capture includes the start of the TLS handshake.
Try opening new HTTPS websites after starting Wireshark.
```

## 10. Quick Demo Script

Use this sequence for a project demo:

```powershell
cd "C:\Users\taele\OneDrive\Documents\IDS project"
$env:PYTHONPATH='.deps'
$env:PYTHONDONTWRITEBYTECODE='1'

python code.py --pcap test.pcap --sessions-out sessions_tls.json --alerts-out alerts.json
python code.py --sessions sessions_tls.json --alerts-out alerts.json --store --report-out report.json
python -m partie_4_dashboard.app
```

Then open:

```text
http://127.0.0.1:5000/
```
