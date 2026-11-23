
import re
from email_analyzer import analyze_email


# SMS-specific contextual indicators
SMS_PATTERNS = {
    "credential_request": re.compile(
        r"\b(share|send|tell|provide|enter|confirm|verify|submit)\b.{0,60}"
        r"\b(otp|one.time.password|upi.pin|pin|password|cvv)\b",
        re.IGNORECASE,
    ),

    "urgent_account_action": re.compile(
        r"\b(account|bank|upi|card)\b.{0,60}"
        r"\b(blocked|blocking|suspended|suspension|deactivated|expired|closed)\b",
        re.IGNORECASE,
    ),

    "payment_request": re.compile(
        r"\b(pay|transfer|send|deposit|make payment|complete payment)\b.{0,50}"
        r"\b(money|amount|rupees|rs\.?|inr|upi|fee|charge)\b",
        re.IGNORECASE,
    ),

    "reward_or_prize_lure": re.compile(
    r"\b(won|winner|prize|reward|cashback|lottery|"
    r"claim your prize|claim your reward|claim your winnings)\b",
    re.IGNORECASE,
    ),

    "account_recovery_lure": re.compile(
        r"\b(click|tap|open|visit|follow|call)\b.{0,60}"
        r"\b(link|website|url|number|support)\b.{0,60}"
        r"\b(restore|reactivate|unlock|verify|recover|access)\b",
        re.IGNORECASE,
    ),

    "refund_pin_request": re.compile(
        r"\b(refund|receive|credit|get)\b.{0,60}"
        r"\b(upi.pin|pin)\b",
        re.IGNORECASE,
    ),

    "suspicious_link_action": re.compile(
        r"\b(click|tap|open|visit)\b.{0,40}"
        r"\b(link|website|url)\b",
        re.IGNORECASE,
    ),

    "identity_impersonation": re.compile(
        r"\b(pretending to be|impersonating|fake bank|fake courier|"
        r"posing as|unauthorized representative)\b",
        re.IGNORECASE,
    ),

    # Delivery and parcel context
    "parcel_context": re.compile(
        r"\b(parcel|package|shipment|courier|delivery|"
        r"consignment|tracking number)\b",
        re.IGNORECASE,
    ),

    "delivery_release_demand": re.compile(
        r"\b(hold|held|release|release fee|delivery charge|"
        r"customs fee|clearance fee|redelivery)\b",
        re.IGNORECASE,
    ),

    
# Urgent instructions that explicitly ask the recipient to contact someone
"urgent_contact_action": re.compile(
    r"\b(call|contact|reply|respond)\b.{0,50}"
    r"\b(immediately|urgently|right now|today|now|"
    r"within \d+ hours?)\b"
    r"|"
    r"\b(immediately|urgently|right now)\b.{0,50}"
    r"\b(call|contact|reply|respond)\b",
    re.IGNORECASE,
    ),
}


def analyze_sms(sender: str, message: str) -> dict:
    """Analyze SMS using email rules and SMS-specific contextual checks."""

    sender = (sender or "").strip()
    message = (message or "").strip()

    if not message:
        return {
            "threat_type": "Invalid SMS",
            "risk_level": "LOW",
            "risk_score": 0,
            "confidence": 0,
            "matched_indicators": [],
            "sms_indicators": [],
            "explanation": "The SMS message is empty.",
            "recommendation": "Import a message containing text.",
            "urls": [],
            "domains": [],
        }

    result = analyze_email(
        sender=sender or "Unknown SMS sender",
        subject="SMS message",
        body=message,
    )

    base_score = max(
        0,
        min(100, int(result.get("risk_score", 0)))
    )

    sms_indicators = []

    for indicator, pattern in SMS_PATTERNS.items():
        if pattern.search(message):
            sms_indicators.append(indicator)

    urls = result.get("urls", [])
    has_url = bool(urls)

    # Contextual scoring based on combinations of evidence.
    contextual_score = 0

    # Credential requests
    if (
        "credential_request" in sms_indicators
        or "credential_request" in result.get("matched_indicators", [])
    ):
        contextual_score = max(contextual_score, 60)

    if (
        "credential_request" in sms_indicators
        and "urgent_account_action" in sms_indicators
    ):
        contextual_score = max(contextual_score, 70)

    if "refund_pin_request" in sms_indicators:
        contextual_score = max(contextual_score, 75)

    # Explicit sensitive-payment requests, including multilingual matches
    if (
        "payment_or_sensitive_data" in result.get("matched_indicators", [])
        or "payment_request" in sms_indicators
    ):
        contextual_score = max(contextual_score, 50)

    # Account suspension and recovery attempts
    if "urgent_account_action" in sms_indicators:
        contextual_score = max(contextual_score, 40)

    if (
        "urgent_account_action" in sms_indicators
        and (
            "account_recovery_lure" in sms_indicators
            or "urgent_contact_action" in sms_indicators
        )
    ):
        contextual_score = max(contextual_score, 65)

    if (
        "urgent_account_action" in sms_indicators
        and "suspicious_link_action" in sms_indicators
    ):
        contextual_score = max(contextual_score, 70)

    # Prize and reward lures
    if (
        "reward_or_prize_lure" in sms_indicators
        and has_url
    ):
        contextual_score = max(contextual_score, 55)

    # Parcel and courier payment context
    if (
        "parcel_context" in sms_indicators
        and "payment_request" in sms_indicators
    ):
        contextual_score = max(contextual_score, 45)

    if (
        "parcel_context" in sms_indicators
        and "payment_request" in sms_indicators
        and "delivery_release_demand" in sms_indicators
    ):
        contextual_score = max(contextual_score, 60)

    if (
        "parcel_context" in sms_indicators
        and "payment_request" in sms_indicators
        and has_url
    ):
        contextual_score = max(contextual_score, 70)

    # Payment combined with specific impersonation language
    if (
        "payment_request" in sms_indicators
        and "identity_impersonation" in sms_indicators
    ):
        contextual_score = max(contextual_score, 65)

    # Use stronger evidence rather than blindly adding overlapping scores.
    score = min(100, max(base_score, contextual_score))

    if score >= 80:
        risk_level = "CRITICAL"
    elif score >= 60:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    if score >= 60:
        threat_type = "Suspicious SMS"
    elif score >= 30:
        threat_type = "Potentially Suspicious SMS"
    else:
        threat_type = "Low-risk SMS"

    matched = list(result.get("matched_indicators", []))
    matched.extend(sms_indicators)
    matched = list(dict.fromkeys(matched))

    explanation = (
        "SMS analyzed using VAPP's email-analysis rules "
        "and contextual SMS-specific checks. "
        + result.get("explanation", "")
    )

    if sms_indicators:
        explanation += (
            " SMS indicators detected: "
            + ", ".join(sms_indicators)
            + "."
        )

    if has_url:
        explanation += (
            " URLs were detected. Their presence alone "
            "does not prove maliciousness."
        )

    recommendation = (
        "Do not share OTPs, passwords, UPI PINs or banking details. "
        "Do not follow suspicious links or make unverified payments. "
        "Verify requests through official service-provider channels."
        if risk_level in ("MEDIUM", "HIGH", "CRITICAL")
        else
        "Review the sender and message context before taking action. "
        "A low-risk result does not guarantee that the SMS is safe."
    )

    confidence = min(
        95,
        max(
            int(result.get("confidence", 0)),
            50 + score // 2,
        ),
    )

    return {
        **result,
        "threat_type": threat_type,
        "risk_level": risk_level,
        "risk_score": score,
        "confidence": confidence,
        "matched_indicators": matched,
        "sms_indicators": sms_indicators,
        "explanation": explanation,
        "recommendation": recommendation,
    }
