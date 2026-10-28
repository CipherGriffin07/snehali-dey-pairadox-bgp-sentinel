
SEVERITY_WEIGHTS = {
    "ORIGIN_CHANGE": 35,
    "SUBPREFIX_ANOMALY": 45,
    "RPKI_INVALID": 60
}

def calculate_risk(anomalies, rpki_status):
    types = {alert["type"] for alert in anomalies}

    if not types:
        return {
            "score": 0,
            "level": "LOW",
            "confidence": "NO_ANOMALY"
        }

    score = sum(
        SEVERITY_WEIGHTS.get(t, 0)
        for t in types
    )

    if rpki_status == "INVALID":
        score += 10

    score = min(score, 100)

    if score >= 80:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": score,
        "level": level,
        "confidence": "HEURISTIC",
        "indicators": sorted(types),
        "note": (
            "Risk score is a heuristic priority measure, "
            "not a probability of BGP hijacking."
        )
    }
