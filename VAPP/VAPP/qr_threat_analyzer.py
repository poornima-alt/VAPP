import re


def analyze_qr_payload(payload):
    text = str(payload or "").strip()
    lower = text.lower()

    indicators = []
    score = 0

    rules = [
        (r"\b(share|send|provide|enter|submit|reveal)\b.{0,45}\b(otp|password|pin|passcode|cvv|verification code)\b", 45, "Requests sensitive credentials"),
        (r"\b(otp|password|pin|passcode|cvv|verification code)\b.{0,45}\b(share|send|provide|enter|submit|reveal)\b", 45, "Requests sensitive credentials"),
        (r"\b(blocked|suspended|closed|deactivated|locked)\b.{0,55}\b(account|bank|card|wallet)\b", 20, "Uses an account restriction threat"),
        (r"\b(urgent|immediately|right now|today|within \d+ hours|act now)\b", 10, "Uses urgency pressure"),
        (r"\b(verify|confirm|update)\b.{0,45}\b(account|bank|card|kyc|identity)\b", 20, "Requests account verification"),
        (r"\b(prize|lottery|winner|reward|cashback)\b.{0,45}\b(claim|collect|won|click)\b", 20, "Uses a prize or reward lure"),
        (r"\b(pay|transfer|send)\b.{0,35}\b(money|payment|fee|deposit)\b", 20, "Requests a payment or money transfer"),
        (r"\b(bank|wallet|upi)\b.{0,45}\b(otp|pin|password|cvv)\b", 25, "Combines financial context with sensitive credentials"),
    ]

    for pattern, points, description in rules:
        if re.search(pattern, lower):
            indicators.append(description)
            score += points

    score = min(score, 100)

    if score >= 70:
        level = "CRITICAL"
        action = "Do not follow the instructions or share information. Verify through the official organization."
    elif score >= 45:
        level = "HIGH"
        action = "Do not share credentials or make payments. Verify independently through official channels."
    elif score >= 25:
        level = "MEDIUM"
        action = "Be cautious. Check the sender and verify the request independently."
    else:
        level = "LOW"
        action = "No strong suspicious patterns were detected. This does not guarantee the content is safe."

    if not indicators:
        indicators.append("No configured suspicious text patterns detected")

    return {
        "risk_score": score,
        "risk_level": level,
        "indicators": indicators,
        "explanation": (
            "The QR text matched " + str(len(indicators)) +
            " configured warning indicator(s)."
        ),
        "recommendation": action,
        "analysis_scope": "Rule-based text analysis; not a definitive safety verdict."
    }
