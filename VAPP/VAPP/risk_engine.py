
import math


def _get_number(event, field, default=0):
    """Read and validate a non-negative numeric event value."""
    value = event.get(field, default)

    if isinstance(value, bool):
        value = int(value)

    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{field} must be numeric.")

    if not math.isfinite(number) or number < 0:
        raise ValueError(
            f"{field} must be a finite non-negative number."
        )

    return number


def _validate_event(event):
    """Validate event data used by the risk engine."""
    if not isinstance(event, dict):
        raise ValueError("Event must be a dictionary.")

    failed_attempts = _get_number(event, "failed_attempts", 0)
    unique_ports = _get_number(event, "unique_ports", 1)
    event_rate = _get_number(event, "event_rate", 0)
    suspicious_keyword = _get_number(
        event, "suspicious_keyword", 0
    )

    if not failed_attempts.is_integer():
        raise ValueError("failed_attempts must be a whole number.")

    if not unique_ports.is_integer():
        raise ValueError("unique_ports must be a whole number.")

    if suspicious_keyword not in (0, 1):
        raise ValueError("suspicious_keyword must be 0 or 1.")

    return {
        "failed_attempts": int(failed_attempts),
        "unique_ports": int(unique_ports),
        "event_rate": event_rate,
        "suspicious_keyword": int(suspicious_keyword)
    }


def calculate_risk(event, threat_type, confidence):
    """
    Calculate a risk score from 0 to 100 using threat type,
    model confidence and event indicators.
    """
    validated = _validate_event(event)

    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        raise ValueError("Confidence must be numeric.")

    if not math.isfinite(confidence) or not 0 <= confidence <= 100:
        raise ValueError("Confidence must be between 0 and 100.")

    threat_scores = {
        "Normal": 10,
        "Suspicious Activity": 45,
        "Phishing / Suspicious Email": 70,
        "Port Scan": 60,
        "Brute Force": 75
    }

    score = threat_scores.get(threat_type, 40)

    # Model confidence contribution
    score += confidence * 0.15

    # Event-rate contribution
    event_rate = validated["event_rate"]

    if event_rate >= 20:
        score += 15
    elif event_rate >= 10:
        score += 10
    elif event_rate >= 5:
        score += 5

    # Failed authentication contribution
    failed_attempts = validated["failed_attempts"]

    if failed_attempts >= 10:
        score += 10
    elif failed_attempts >= 5:
        score += 5

    # Port-scan indicator contribution
    unique_ports = validated["unique_ports"]

    if unique_ports >= 20:
        score += 15
    elif unique_ports >= 10:
        score += 10
    elif unique_ports >= 5:
        score += 5

    # Suspicious email indicator contribution
    if (
        validated["suspicious_keyword"] == 1
        and threat_type == "Phishing / Suspicious Email"
    ):
        score += 5

    score = min(round(score), 100)

    if score >= 80:
        risk_level = "CRITICAL"
    elif score >= 60:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_score": score,
        "risk_level": risk_level
    }


def generate_explanation(event, threat_type, risk_level):
    """Generate a readable explanation of the detected activity."""
    validated = _validate_event(event)

    failed_attempts = validated["failed_attempts"]
    event_rate = validated["event_rate"]
    unique_ports = validated["unique_ports"]

    if threat_type == "Brute Force":
        explanation = (
            f"Multiple failed authentication attempts "
            f"({failed_attempts}) were observed at an event rate "
            f"of {event_rate}. This pattern is consistent with "
            "a possible brute-force attack."
        )

    elif threat_type == "Port Scan":
        explanation = (
            f"The source contacted {unique_ports} different ports. "
            "This may indicate reconnaissance or port-scanning activity."
        )

    elif threat_type == "Phishing / Suspicious Email":
        explanation = (
            "The message contains characteristics associated with "
            "phishing or suspicious email activity. It should be "
            "reviewed before delivery."
        )

    elif threat_type == "Suspicious Activity":
        explanation = (
            "The event contains suspicious characteristics and "
            "deviates from the expected activity pattern."
        )

    else:
        explanation = (
            "The observed activity does not show strong indicators "
            "of a known malicious pattern."
        )

    return f"{explanation} Assessed risk level: {risk_level}."


def generate_recommendation(threat_type, risk_level):
    """Generate defensive recommendations based on threat and severity."""

    recommendations = {
        "Brute Force": (
            "Enable multi-factor authentication (MFA), review "
            "authentication logs, consider account lockout policies, "
            "and investigate the source IP."
        ),

        "Port Scan": (
            "Review exposed services, restrict unnecessary ports, "
            "monitor the source IP, and investigate related events."
        ),

        "Phishing / Suspicious Email": (
            "Do not open suspicious links or attachments. Verify "
            "the sender, quarantine the message, and investigate "
            "the source."
        ),

        "Suspicious Activity": (
            "Review event details, correlate related activity, "
            "and monitor the source for additional suspicious behavior."
        ),

        "Normal": (
            "No immediate defensive action is indicated. "
            "Continue routine monitoring."
        )
    }

    recommendation = recommendations.get(
        threat_type,
        "Continue monitoring the event and investigate related activity."
    )

    if risk_level == "CRITICAL":
        recommendation += (
            " Priority: urgent security-team review and prompt "
            "investigation are recommended."
        )

    elif risk_level == "HIGH":
        recommendation += (
            " Priority: investigate this event as soon as possible."
        )

    elif risk_level == "MEDIUM":
        recommendation += (
            " Priority: review and monitor this event."
        )

    return recommendation
