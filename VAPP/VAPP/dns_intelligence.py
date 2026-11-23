from __future__ import annotations

import ipaddress

import dns.exception
import dns.resolver


def inspect_domain_dns(
    hostname: str,
    timeout: float = 1.5,
    lifetime: float = 3.0,
) -> dict:
    """Resolve a hostname and report DNS evidence without opening a website."""

    result = {
        "hostname": str(hostname or "").strip().rstrip(".").lower(),
        "dns_status": "UNKNOWN",
        "resolved_ips": [],
        "findings": [],
        "records_checked": ["A", "AAAA"],
    }

    host = result["hostname"]

    if not host:
        result["dns_status"] = "INVALID"
        result["findings"].append("Hostname is empty")
        return result

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = lifetime

        for record_type in ("A", "AAAA"):
            try:
                answers = resolver.resolve(
                    host,
                    record_type,
                    lifetime=lifetime,
                    search=False,
                )

                for answer in answers:
                    address = str(answer.address)
                    if address not in result["resolved_ips"]:
                        result["resolved_ips"].append(address)

            except dns.resolver.NXDOMAIN:
                result["findings"].append(
                    f"{record_type} lookup returned NXDOMAIN"
                )
            except dns.resolver.NoAnswer:
                result["findings"].append(
                    f"No {record_type} records returned"
                )
            except dns.exception.Timeout:
                result["findings"].append(
                    f"{record_type} lookup timed out"
                )
            except dns.resolver.NoNameservers:
                result["findings"].append(
                    f"No usable DNS nameserver for {record_type}"
                )
            except dns.exception.DNSException:
                result["findings"].append(
                    f"{record_type} lookup failed"
                )

    except Exception:
        result["dns_status"] = "UNKNOWN"
        result["findings"].append(
            "DNS resolver could not be initialized"
        )
        return result

    if result["resolved_ips"]:
        non_public = []

        for address in result["resolved_ips"]:
            try:
                ip = ipaddress.ip_address(address)
                if not ip.is_global:
                    non_public.append(address)
            except ValueError:
                result["findings"].append(
                    "Invalid IP address returned by DNS"
                )

        if non_public:
            result["dns_status"] = "BLOCKED_DESTINATION"
            result["findings"].append(
                "DNS returned non-public IP address(es): "
                + ", ".join(non_public)
            )
        else:
            result["dns_status"] = "RESOLVED"
            result["findings"].append(
                "DNS returned public IP address(es); "
                "this does not establish domain safety"
            )

    elif any(
        "NXDOMAIN" in finding
        for finding in result["findings"]
    ):
        result["dns_status"] = "UNRESOLVED"

    else:
        result["dns_status"] = "UNKNOWN"
        result["findings"].append(
            "DNS status could not be established"
        )

    return result
