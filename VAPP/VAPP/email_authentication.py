import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

import dns.resolver
import dkim
import spf
import tldextract


_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
_VALID_SPF = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"}


def _result(status, reason, **extra):
    return {"status": status, "reason": reason, **extra}


def _txt_records(name):
    answers = dns.resolver.resolve(name, "TXT", lifetime=5)
    return [
        b"".join(record.strings).decode("utf-8", errors="replace")
        for record in answers
    ]


def _organizational_domain(domain):
    extracted = _EXTRACT(domain.lower().rstrip("."))
    if not extracted.domain or not extracted.suffix:
        return None
    return f"{extracted.domain}.{extracted.suffix}"


def _aligned(identifier, from_domain, mode):
    if not identifier or not from_domain:
        return False

    identifier = identifier.lower().rstrip(".")
    from_domain = from_domain.lower().rstrip(".")

    if mode == "s":
        return identifier == from_domain

    left = _organizational_domain(identifier)
    right = _organizational_domain(from_domain)
    return left is not None and left == right


def _verify_spf(client_ip, envelope_from, helo):
    if not all((client_ip, envelope_from, helo)):
        return _result(
            "UNKNOWN",
            "Trusted client IP, envelope sender and HELO are required for SPF."
        )

    try:
        outcome, explanation = spf.check2(
            i=client_ip,
            s=envelope_from,
            h=helo,
            timeout=10
        )
        outcome = str(outcome).lower()

        if outcome not in _VALID_SPF:
            return _result("UNKNOWN", "SPF returned an unrecognised result.")

        status = (
            "PASS" if outcome == "pass"
            else "FAIL" if outcome == "fail"
            else "UNKNOWN"
        )
        return _result(status, str(explanation)[:300], mechanism_result=outcome)

    except Exception as exc:
        return _result("UNKNOWN", f"SPF evaluation error: {type(exc).__name__}")


def _verify_dkim(raw_email, dnsfunc=None):
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw_email)
        signatures = message.get_all("DKIM-Signature", [])

        if not signatures:
            return _result("UNKNOWN", "No DKIM signature found.")

        verifier = dkim.DKIM(raw_email)
        verified = []

        lookup = dkim.get_txt if dnsfunc is None else dnsfunc

        for index in range(len(signatures)):
            try:
                prepared = verifier.verify_headerprep(index)

                if not prepared:
                    verified.append({
                        "signature_index": index,
                        "status": "UNKNOWN",
                        "error": "Signature could not be prepared."
                    })
                    continue

                sig, _, _ = prepared
                key_name = (
                    sig[b"s"] + b"._domainkey." + sig[b"d"] + b"."
                )

                try:
                    lookup_result = lookup(key_name, timeout=5)
                    dkim.evaluate_pk(key_name, lookup_result)
                except Exception as exc:
                    verified.append({
                        "signature_index": index,
                        "status": "UNKNOWN",
                        "error": f"Public-key lookup: {type(exc).__name__}"
                    })
                    continue

                def cached_dnsfunc(requested_name, timeout=5):
                    if requested_name == key_name:
                        return lookup_result
                    return lookup(requested_name, timeout=timeout)

                try:
                    passed = verifier.verify(
                        idx=index,
                        dnsfunc=cached_dnsfunc
                    )

                    verified.append({
                        "signature_index": index,
                        "status": "PASS" if passed else "FAIL"
                    })

                except dkim.ValidationError as exc:
                    reason = str(exc)

                    if "body hash mismatch" in reason.lower():
                        status = "FAIL"
                    else:
                        status = "UNKNOWN"

                    verified.append({
                        "signature_index": index,
                        "status": status,
                        "error": type(exc).__name__,
                        "reason": reason
                    })

                except Exception as exc:
                    verified.append({
                        "signature_index": index,
                        "status": "UNKNOWN",
                        "error": type(exc).__name__
                    })

            except Exception as exc:
                verified.append({
                    "signature_index": index,
                    "status": "UNKNOWN",
                    "error": type(exc).__name__
                })

        if any(item["status"] == "PASS" for item in verified):
            status = "PASS"
        elif any(item["status"] == "UNKNOWN" for item in verified):
            status = "UNKNOWN"
        else:
            status = "FAIL"

        reasons = {
            "PASS": "At least one DKIM signature verified.",
            "FAIL": "DKIM signature verification failed with available public keys.",
            "UNKNOWN": "DKIM verification could not be completed reliably."
        }

        return _result(
            status,
            reasons[status],
            signatures=verified
        )

    except Exception as exc:
        return _result(
            "UNKNOWN",
            f"DKIM evaluation error: {type(exc).__name__}"
        )

def _get_dmarc_record(from_domain):
    candidates = [from_domain]
    organizational = _organizational_domain(from_domain)

    if organizational and organizational not in candidates:
        candidates.append(organizational)

    for domain in candidates:
        try:
            records = [
                item for item in _txt_records(f"_dmarc.{domain}")
                if item.lower().startswith("v=dmarc1")
            ]
            if len(records) > 1:
                return None, "Multiple DMARC records found.", None
            if records:
                return records[0], None, domain
        except dns.resolver.NXDOMAIN:
            continue
        except dns.resolver.NoAnswer:
            continue
        except dns.exception.DNSException:
            return None, "DMARC DNS lookup failed.", None

    return None, "No DMARC policy record found.", None


def _verify_dmarc(from_domain, spf_result, dkim_result):
    record, error, record_domain = _get_dmarc_record(from_domain)

    if error:
        return _result("UNKNOWN", error)

    tags = {}
    for part in record.split(";"):
        if "=" not in part:
            if part.strip():
                return _result("UNKNOWN", "DMARC record contains a malformed tag.")
            continue

        key, value = part.split("=", 1)
        key = key.strip().lower()
        value = value.strip().lower()

        if not key or not value:
            return _result("UNKNOWN", "DMARC record contains an empty tag.")

        if key in tags:
            return _result("UNKNOWN", f"DMARC record contains duplicate tag: {key}.")

        tags[key] = value

    if tags.get("v") != "dmarc1" or "p" not in tags:
        return _result("UNKNOWN", "DMARC record is malformed.")

    valid_policies = {"none", "quarantine", "reject"}

    if tags["p"] not in valid_policies:
        return _result("UNKNOWN", "DMARC policy value is invalid.")

    if "sp" in tags and tags["sp"] not in valid_policies:
        return _result("UNKNOWN", "DMARC subdomain policy value is invalid.")

    is_subdomain_fallback = (
        record_domain is not None
        and from_domain.lower().rstrip(".") != record_domain.lower().rstrip(".")
    )

    effective_policy = (
        tags.get("sp", tags["p"])
        if is_subdomain_fallback
        else tags["p"]
    )

    adkim = tags.get("adkim", "r")
    aspf = tags.get("aspf", "r")

    if adkim not in {"r", "s"} or aspf not in {"r", "s"}:
        return _result("UNKNOWN", "DMARC alignment mode is invalid.")

    aligned_spf = (
        spf_result.get("status") == "PASS"
        and _aligned(
            spf_result.get("authenticated_domain"),
            from_domain,
            "s" if aspf == "s" else "r"
        )
    )

    aligned_dkim = any(
        item.get("status") == "PASS"
        and _aligned(
            item.get("domain"),
            from_domain,
            "s" if adkim == "s" else "r"
        )
        for item in dkim_result.get("signatures", [])
    )

    if aligned_spf or aligned_dkim:
        return _result(
            "PASS",
            "At least one authenticated identifier aligns with the From domain.",
            policy=effective_policy,
            aligned_spf=aligned_spf,
            aligned_dkim=aligned_dkim
        )

    spf_is_uncertain = (
        spf_result.get("status") == "UNKNOWN"
        and spf_result.get("mechanism_result") not in {
            "softfail", "neutral", "none", "permerror"
        }
    )

    if spf_is_uncertain or dkim_result.get("status") == "UNKNOWN":
        return _result(
            "UNKNOWN",
            "Insufficient authentication evidence to determine DMARC alignment.",
            policy=effective_policy
        )

    return _result(
        "FAIL",
        "Neither SPF nor DKIM passed with alignment to the From domain.",
        policy=effective_policy,
        aligned_spf=False,
        aligned_dkim=False
    )


def verify_email_authentication(
    raw_email_bytes,
    trusted_client_ip=None,
    envelope_from=None,
    helo=None,
    dkim_dnsfunc=None
):
    """Evaluate SPF, DKIM and DMARC without trusting arbitrary Received headers."""

    if not isinstance(raw_email_bytes, bytes) or not raw_email_bytes:
        unknown = _result("UNKNOWN", "Original raw email bytes are unavailable.")
        return {"spf": unknown, "dkim": unknown, "dmarc": unknown}

    try:
        message = BytesParser(policy=policy.default).parsebytes(raw_email_bytes)
        from_values = message.get_all("From", [])

        if len(from_values) != 1:
            raise ValueError("Exactly one From header is required.")

        _, from_address = parseaddr(str(from_values[0]))
        if "@" not in from_address:
            raise ValueError("From address is invalid.")

        from_domain = from_address.rsplit("@", 1)[1].lower().rstrip(".")

    except Exception as exc:
        unknown = _result("UNKNOWN", f"Cannot determine From domain: {type(exc).__name__}")
        return {"spf": unknown, "dkim": unknown, "dmarc": unknown}

    spf_result = _verify_spf(trusted_client_ip, envelope_from, helo)

    if spf_result.get("mechanism_result") == "pass" and envelope_from and "@" in envelope_from:
        spf_result["authenticated_domain"] = envelope_from.rsplit("@", 1)[1].lower().rstrip(".")

    dkim_result = _verify_dkim(raw_email_bytes, dnsfunc=dkim_dnsfunc)

    parsed = BytesParser(policy=policy.default).parsebytes(raw_email_bytes)
    signature_results = dkim_result.get("signatures", [])
    signature_headers = parsed.get_all("DKIM-Signature", [])

    for item, header in zip(signature_results, signature_headers):
        match = re.search(
            r"(?:^|;)\s*d\s*=\s*([^;\s]+)",
            str(header),
            re.IGNORECASE
        )
        item["domain"] = (
            match.group(1).strip().lower().rstrip(".")
            if match else None
        )

    dmarc_result = _verify_dmarc(from_domain, spf_result, dkim_result)

    return {
        "from_domain": from_domain,
        "spf": spf_result,
        "dkim": dkim_result,
        "dmarc": dmarc_result
    }
