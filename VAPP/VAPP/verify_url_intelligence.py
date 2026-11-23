from url_intelligence import inspect_url, inspect_urls


def check(condition, message):
    if not condition:
        raise AssertionError(message)
    print("PASS:", message)


print("========== VAPP URL INTELLIGENCE TEST ==========")

normal = inspect_url("https://example.com")
check(normal["status"] == "REVIEW", "Normal HTTPS URL")

local = inspect_url("http://127.0.0.1")
check(local["status"] == "BLOCKED_DESTINATION", "Loopback IP blocked")

private = inspect_url("http://192.168.1.10")
check(private["status"] == "BLOCKED_DESTINATION", "Private IP blocked")

credentials = inspect_url("https://user:pass@example.com")
check(
    any("credentials" in x.lower() for x in credentials["findings"]),
    "URL credentials detected"
)

javascript = inspect_url("javascript:alert(1)")
check(javascript["status"] == "INVALID", "JavaScript scheme rejected")

punycode = inspect_url("https://xn--pple-43d.com")
check(
    any("Punycode" in x for x in punycode["findings"]),
    "Punycode hostname detected"
)

empty = inspect_url("")
check(empty["status"] == "INVALID", "Empty URL rejected")

invalid_port = inspect_url("https://example.com:bad")
check(invalid_port["status"] == "INVALID", "Invalid port rejected")

missing_host = inspect_url("https:///missing-host")
check(missing_host["status"] == "INVALID", "Missing hostname rejected")

empty_host = inspect_url("https://")
check(empty_host["status"] == "INVALID", "Empty hostname rejected")

ftp = inspect_url("ftp://example.com")
check(ftp["status"] == "INVALID", "FTP scheme rejected")

invalid_ipv6 = inspect_url("http://[invalid-ipv6]")
check(invalid_ipv6["status"] == "INVALID", "Malformed IPv6 rejected")
batch = inspect_urls(["https://example.com", "http://127.0.0.1"])
check(len(batch) == 2, "Multiple URLs processed")

print("========== ALL URL INTELLIGENCE TESTS PASSED ==========")

