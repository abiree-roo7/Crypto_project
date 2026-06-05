from datetime import datetime

def create_alert(
    severity,
    rule,
    description,
    src_ip,
    dst_ip,
    ja3=None
):
    return {
        "timestamp": datetime.now().isoformat(),
        "severity": severity,
        "rule": rule,
        "description": description,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "ja3": ja3
    }