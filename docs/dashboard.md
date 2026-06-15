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

## Run a Capture From the Dashboard

1. Start the dashboard.
2. Open `http://127.0.0.1:5000/`.
3. Choose a `.pcap`, `.pcapng`, or `.cap` file.
4. Select `Run pipeline`.

The dashboard saves the uploaded capture under `uploads/`, runs the same pipeline as `code.py`, writes `sessions_tls.json`, `alerts.json`, `alerts.db`, and `report.json`, then reloads the alert view.

## Future Improvements

Recommended improvements for the final dashboard:

- alert detail page
- report verification status
- date range filtering
- severity charts
- JA3/JA3S search
- source/destination IP drilldown
