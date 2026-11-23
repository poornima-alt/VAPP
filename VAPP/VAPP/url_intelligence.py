
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from dns_intelligence import inspect_domain_dns


LOCAL_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".home",
    ".lan",
)

RESERVED_LOCAL_NAMES = {
    "localhost",
    "localhost.localdomain",
}


def inspect_url(raw_url: str) -> dict:
    """Inspect URL structure and DNS evidence without opening the website."""
    result = {
        "url": str(raw_url or ""),
        "status": "REVIEW",
        "hostname": None,
        "scheme": None,
        "findings": [],
        "reputation": "UNAVAILABLE",
        "redirect_status": "NOT_CHECKED",
        "dns_intelligence": None,
    }

    value = str(raw_url or "").strip()

    if not value:
        result["status"] = "INVALID"
        result["findings"].append("Empty URL")
        return result

    candidate = (
        value
        if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", value)
        else "https://" + value
    )

    try:
        parsed = urlsplit(candidate)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        username = parsed.username
        port = parsed.port
    except ValueError:
        result["status"] = "INVALID"
        result["findings"].append("Malformed URL")
        return result

    result["scheme"] = scheme

    if scheme not in ("http", "https"):
        result["status"] = "INVALID"
        result["findings"].append("Unsupported URL scheme")
        return result

    if not hostname:
        result["status"] = "INVALID"
        result["findings"].append("Missing hostname")
        return result

    hostname = hostname.rstrip(".").lower()
    result["hostname"] = hostname

    if username is not None:
        result["findings"].append("URL contains user-info credentials")

    if parsed.password is not None:
        result["findings"].append(
            "URL contains password-like user-info"
        )

    try:
        ip_value = ipaddress.ip_address(hostname.strip("[]"))
        result["findings"].append(
            "URL uses an IP-address destination"
        )

        if not ip_value.is_global:
            result["findings"].append(
                "Destination IP is private, reserved, loopback or otherwise non-public"
            )
            result["status"] = "BLOCKED_DESTINATION"
        else:
            result["status"] = "REVIEW"

    except ValueError:
        try:
            ascii_hostname = hostname.encode("idna").decode("ascii")
            labels = ascii_hostname.split(".")

            if (
                len(ascii_hostname) > 253
                or any(
                    not label
                    or len(label) > 63
                    or not re.fullmatch(
                        r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                        label,
                    )
                    for label in labels
                )
            ):
                raise ValueError("Invalid hostname")

            if (
                ascii_hostname in RESERVED_LOCAL_NAMES
                or any(
                    ascii_hostname.endswith(suffix)
                    for suffix in LOCAL_SUFFIXES
                )
            ):
                result["findings"].append(
                    "Local or non-public hostname destination"
                )
                result["status"] = "BLOCKED_DESTINATION"

            if any(label.startswith("xn--") for label in labels):
                result["findings"].append(
                    "Punycode hostname detected"
                )

            if any(ord(char) > 127 for char in hostname):
                result["findings"].append(
                    "Unicode hostname detected"
                )

        except (UnicodeError, ValueError):
            result["status"] = "INVALID"
            result["findings"].append(
                "Invalid hostname or internationalized hostname"
            )


    # Resolve valid domain names without opening the website.
    # IP literals and destinations already blocked by passive checks are skipped.
    if result["hostname"] and result["status"] not in ("INVALID", "BLOCKED_DESTINATION"):
        try:
            ipaddress.ip_address(result["hostname"].strip("[]"))
        except ValueError:
            dns_result = inspect_domain_dns(result["hostname"])
            result["dns_intelligence"] = dns_result

            if dns_result["dns_status"] == "BLOCKED_DESTINATION":
                result["status"] = "BLOCKED_DESTINATION"
                result["findings"].extend(
                    "DNS: " + finding
                    for finding in dns_result["findings"]
                )
            elif dns_result["dns_status"] == "RESOLVED":
                result["findings"].append(
                    "DNS resolved to public IP address(es); domain safety is not established"
                )
            elif dns_result["dns_status"] == "UNRESOLVED":
                result["findings"].append(
                    "DNS hostname did not resolve"
                )
            else:
                result["findings"].append(
                    "DNS status unknown; resolution could not be confirmed"
                )


    if not result["findings"]:
        result["findings"].append(
            "No suspicious URL structure detected by passive checks"
        )

    return result


def inspect_urls(urls: list[str]) -> list[dict]:
    """Inspect multiple URLs without visiting them."""
    if not isinstance(urls, list):
        return []

    return [inspect_url(url) for url in urls[:50]]

