
import ipaddress

DEMO_ROAS = [
    {
        "prefix": "203.0.113.0/24",
        "max_length": 24,
        "asn": 64500
    },
    {
        "prefix": "198.51.100.0/24",
        "max_length": 24,
        "asn": 64510
    }
]

def validate_rpki(prefix, origin_asn):
    network = ipaddress.ip_network(prefix, strict=True)

    covering = [
        roa for roa in DEMO_ROAS
        if network.version ==
           ipaddress.ip_network(roa["prefix"]).version
        and network.subnet_of(
            ipaddress.ip_network(roa["prefix"])
        )
    ]

    if not covering:
        return {
            "status": "NOT_FOUND",
            "reason": "No matching demo ROA exists."
        }

    for roa in covering:
        if (
            origin_asn == roa["asn"]
            and network.prefixlen <= roa["max_length"]
        ):
            return {
                "status": "VALID",
                "reason": "Origin ASN and prefix length match a demo ROA."
            }

    return {
        "status": "INVALID",
        "reason": "Announcement conflicts with the demo ROA records.",
        "matching_roas": covering
    }
