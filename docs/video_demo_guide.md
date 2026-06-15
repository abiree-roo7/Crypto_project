# Video Demo Guide

Use this guide to record a short supervisor demo of the TLS IDS app.

## Recommended Video Length

Aim for 2 to 4 minutes.

## What To Show

1. Open the dashboard at `http://127.0.0.1:5000/`.
2. Point out the main areas:
   - capture upload
   - pipeline run log
   - alert counters
   - alert queue
   - report downloads
3. Upload a Wireshark `.pcapng` or the included `test.pcap`.
4. Keep `Start with a clean report` checked.
5. Select `Analyze capture`.
6. Show the `Pipeline Run Log` updating after the run.
7. Show the alert table and severity counters.
8. Download the signed report from `Report Downloads`.
9. Explain that the app analyzes TLS metadata only and does not decrypt HTTPS content.

## Suggested Script

```text
This is our TLS IDS dashboard. We upload a Wireshark capture, then the app extracts TLS sessions, calculates TLS fingerprints such as JA3 and JA3S, runs detection rules, signs the alerts, stores them, and exports a signed report.

I will run a clean analysis now. The backend log shows each step: extraction, alert detection, signing, database storage, and report export.

After the run, the dashboard shows the number of sessions and alerts, the alert queue, the rule that triggered, the traffic flow, the SNI, and the JA3 fingerprint.

Finally, we can download the signed report, the raw alerts JSON, and the extracted sessions JSON.
```

## Windows Recording Options

Use one of these:

```text
Xbox Game Bar: Win + G, then Record
PowerPoint: Insert -> Screen Recording
OBS Studio: Display Capture or Window Capture
```

## Demo Tips

- Start with a clean report for a clear result.
- Use a small capture for a fast demo.
- Start Wireshark before opening websites, otherwise the TLS ClientHello may be missing.
- Keep the browser zoom around 90% or 100% so the run log and report downloads are visible.
