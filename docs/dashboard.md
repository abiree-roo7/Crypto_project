# Dashboard Guide

## Overview

The dashboard is a local Flask prototype for visualizing IDS alerts.

Folder:

```text
partie_4_dashboard/
```

Main file:

```text
partie_4_dashboard/app.py
```

## Run

```bash
python -m partie_4_dashboard.app
```

Open:

```text
http://127.0.0.1:5000/
```

## Data Sources

The dashboard loads data in this priority order:

```text
1. report.json
2. alerts.json
3. alerts.db
```

If `report.json` exists, it is used first because it contains the signed report output from Part 3.

## Current Views

The dashboard currently shows:

- total alert count
- session count from the latest capture
- critical alert count
- warning alert count
- info alert count
- alert table
- alert type summary
- top source IP summary
- severity filter
- text search
- PCAP/PCAPNG upload
- end-to-end pipeline run from the browser
- signed report download
- alerts and sessions JSON downloads
- runtime data reset for clean demos

## Run a Capture From the Dashboard

1. Start the dashboard.
2. Open `http://127.0.0.1:5000/`.
3. Choose a `.pcap`, `.pcapng`, or `.cap` file.
4. Select `Run pipeline`.

The dashboard saves the uploaded capture under `uploads/`, runs the same pipeline as `code.py`, writes `sessions_tls.json`, `alerts.json`, `alerts.db`, and `report.json`, then reloads the alert view.

By default, `Start with a clean report` is enabled. This clears old runtime outputs before analyzing the uploaded capture, so a new Wireshark test produces a fresh report instead of appending to previous demo data.

After a successful run, use the `Report Downloads` panel to download:

```text
tls_ids_report.json
tls_ids_alerts.json
tls_ids_sessions.json
```

Use `Clear runtime data` to reset the local dashboard outputs before another demo.

## Future Improvements

Recommended improvements for the final dashboard:

- alert detail page
- report verification status
- date range filtering
- severity charts
- JA3/JA3S search
- source/destination IP drilldown
