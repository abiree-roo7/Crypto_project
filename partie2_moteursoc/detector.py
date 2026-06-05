from rules import *
from alert_engine import create_alert

class TLSDetector:

    def analyze(self, tls_data):

        alerts = []

        src_ip = tls_data["src_ip"]
        dst_ip = tls_data["dst_ip"]

        

        if tls_data["tls_version"] in WEAK_TLS_VERSIONS:

            alerts.append(
                create_alert(
                    "warning",
                    "Weak TLS Version",
                    f"{tls_data['tls_version']} detected",
                    src_ip,
                    dst_ip,
                    tls_data.get("ja3")
                )
            )



        if tls_data["certificate_expired"]:

            alerts.append(
                create_alert(
                    "critical",
                    "Expired Certificate",
                    "Server certificate expired",
                    src_ip,
                    dst_ip,
                    tls_data.get("ja3")
                )
            )

       

        if tls_data["self_signed"]:

            alerts.append(
                create_alert(
                    "warning",
                    "Self-Signed Certificate",
                    "Self-signed certificate detected",
                    src_ip,
                    dst_ip,
                    tls_data.get("ja3")
                )
            )

        

        cipher = tls_data["cipher_suite"]

        for weak in WEAK_CIPHERS:

            if weak in cipher:

                alerts.append(
                    create_alert(
                        "warning",
                        "Weak Cipher Suite",
                        f"Weak cipher detected: {cipher}",
                        src_ip,
                        dst_ip,
                        tls_data.get("ja3")
                    )
                )

        

        if tls_data.get("ja3") in BLACKLISTED_JA3:

            alerts.append(
                create_alert(
                    "critical",
                    "Suspicious JA3",
                    "Known malicious fingerprint",
                    src_ip,
                    dst_ip,
                    tls_data.get("ja3")
                )
            )

        return alerts