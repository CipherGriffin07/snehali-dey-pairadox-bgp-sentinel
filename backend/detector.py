
import ipaddress
from datetime import datetime, timezone

import storage
from rpki import validate_rpki
from risk import calculate_risk


class BGPDetector:
    def __init__(self):
        storage.initialize()
        self.routes = {}
        self.alerts = storage.load_alerts()

        for prefix, asn in storage.load_announcements():
            self.routes[prefix] = asn

    def analyze(self, prefix, origin_asn):
        network = ipaddress.ip_network(prefix, strict=True)
        prefix = str(network)
        origin_asn = int(origin_asn)

        timestamp = datetime.now(timezone.utc).isoformat()
        anomalies = []
        rpki = validate_rpki(prefix, origin_asn)

        previous = self.routes.get(prefix)

        if previous is not None and previous != origin_asn:
            anomalies.append({
                "type": "ORIGIN_CHANGE",
                "prefix": prefix,
                "previous_origin": previous,
                "new_origin": origin_asn,
                "explanation": (
                    f"Origin ASN changed from AS{previous} "
                    f"to AS{origin_asn} for {prefix}. "
                    "Verify whether this change is authorized."
                )
            })

        for known_prefix, known_asn in self.routes.items():
            known = ipaddress.ip_network(known_prefix)

            if network.version != known.version:
                continue

            if (
                network != known
                and network.subnet_of(known)
                and origin_asn != known_asn
            ):
                anomalies.append({
                    "type": "SUBPREFIX_ANOMALY",
                    "prefix": prefix,
                    "covering_prefix": known_prefix,
                    "previous_origin": known_asn,
                    "new_origin": origin_asn,
                    "explanation": (
                        f"{prefix} is a more-specific announcement "
                        f"inside {known_prefix}, but its origin "
                        f"AS{origin_asn} differs from "
                        f"AS{known_asn}. Investigate a possible "
                        "subprefix hijack."
                    )
                })

        if rpki["status"] == "INVALID":
            anomalies.append({
                "type": "RPKI_INVALID",
                "prefix": prefix,
                "previous_origin": previous,
                "new_origin": origin_asn,
                "explanation": rpki["reason"]
            })

        risk = calculate_risk(anomalies, rpki["status"])

        for alert in anomalies:
            alert["severity"] = risk["level"]
            alert["risk_score"] = risk["score"]
            alert["timestamp"] = timestamp
            alert["rpki_status"] = rpki["status"]
            alert["confidence"] = risk["confidence"]

            storage.save_alert(alert)
            self.alerts.append(alert)

        self.routes[prefix] = origin_asn
        storage.save_announcement(
            prefix, origin_asn, timestamp
        )

        return {
            "prefix": prefix,
            "origin_asn": origin_asn,
            "rpki": rpki,
            "risk": risk,
            "anomaly_detected": bool(anomalies),
            "anomalies": anomalies
        }
