from __future__ import annotations

import html
import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import urlparse


URL_RE = re.compile(r"""(?ix)(?:https?://|www\.)[^\s<>\"'`]+""")

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
    "rb.gy", "ow.ly", "buff.ly", "rebrand.ly", "lnkd.in", "shorturl.at",
}

# Each category contributes once, even if several phrases in that category match.
# Weights are intentionally explainable; they are not probabilities.
SIGNALS = {
    "credential_request": (
        30,
        [
            r"\bverify your account(?: credentials?)?\b",
            r"\bverify account\b",
            r"\bconfirm your password\b",
            r"\breset your password\b",
            r"\benter your password\b",
            r"\b(?:confirm(?:ing)?|provide|submit|enter)\s+(?:your\s+)?username\s+and\s+password\b",
            r"\bconfirm your login\b",
            r"\bshare your otp\b",
            r"\bsend (?:me )?the otp\b",
            r"\bverify your credentials\b",
            r"\bprovide your login details\b",
        ],
    ),
    "urgent_action": (
        12,
        [
            r"\bact immediately\b",
            r"\baccount will be suspended\b",
            r"\baccount has been suspended\b",
            r"\burgent action required\b",
            r"\bwithin 24 hours\b",
            r"\bimmediate action required\b",
            r"\bimmediate action is required\b",
            r"\bfinal warning\b",
            r"\brespond immediately\b",
            r"\burgent security (?:notice|alert|warning)\b",
        ],
    ),
    "account_security_claim": (
        14,
        [
            r"\bwe detected unusual (?:activity|login)\b",
            r"\byour account has been flagged\b",
            r"\baccount has been flagged for suspicious activity\b",
            r"\bsuspicious activity (?:was )?detected on your account\b",
            r"\byour account (?:was|has been) compromised\b",
            r"\bsecurity alert regarding your account\b",
            r"\bunauthorized login attempt\b",
            r"\bwe (?:noticed|observed) unusual (?:activity|login)(?: on)? your account\b",
            r"\byour account was flagged for suspicious activity\b",
        ],
    ),
    "threat_or_consequence_pressure": (
        12,
        [
            r"\bprevent account suspension\b",
            r"\btemporary account restriction\b",
            r"\bfailure to respond may result\b",
            r"\bfailure to act may result\b",
            r"\byour account (?:may|will) be restricted\b",
            r"\baccess will be disabled\b",
            r"\baccount termination\b",
        ],
    ),
    "financial_lure": (
        25,
        [
            r"\byou have won\b",
            r"\bclaim your (?:prize|reward|refund)\b",
            r"\bfree money\b",
            r"\bpay (?:a )?(?:fee|tax) to receive\b",
            r"\bguaranteed cash reward\b",
            r"\bమీరు గెలుచుకున్నారు\b",
        ],
    ),
    "payment_or_sensitive_data": (
        30,
        [
            r"\btransfer (?:the )?money\b",
            r"\bpay immediately\b",
            r"\bwire transfer\b",
            r"\bcard number and cvv\b",
            r"\bbank details\b",
            r"\bupi pin\b",
            r"\bshare your aadhaar\b",
            r"\bchange the bank account\b",
            r"\bupdate payment details\b",
        ],
    ),
    "impersonation_language": (
        12,
        [
            r"\bsecurity team\b.*\b(?:password|verify|login|credentials)\b",
            r"\bfrom (?:your )?(?:bank|it support)\b.*\b(?:verify|suspend|login)\b",
            r"\bceo\b.*\b(?:urgent|transfer|gift cards?)\b",
            r"\b(?:administrator|support team)\b.*\b(?:verify|password|credentials)\b",
        ],
    ),
}

MULTILINGUAL_FINANCIAL_PHRASES = (
    "अपना यूपीआई पिन साझा करें",
    "apna upi pin share karein",
    "अपना पैसा तुरंत ट्रांसफर करें",
    "apna paisa turant transfer karein",
    "ನಿಮ್ಮ ಯುಪಿಐ ಪಿನ್ ಹಂಚಿಕೊಳ್ಳಿ",
    "nimma upi pin hanchikolli",
    "ನಿಮ್ಮ ಹಣವನ್ನು ತಕ್ಷಣ ವರ್ಗಾಯಿಸಿ",
    "nimma hanavannu takshana vargayisi",
    "మీ యూపీఐ పిన్ పంచుకోండి",
    "mee upi pin panchukondi",
    "మీ డబ్బును వెంటనే బదిలీ చేయండి",
    "mee dabbunu ventane badili cheyandi",
    "உங்கள் யுபிஐ பின்னைப் பகிரவும்",
    "ungal upi pinnai pagiravum",
    "உடனடியாக பணத்தை மாற்றவும்",
    "udanadiyaga panathai mattravum",
    "നിങ്ങളുടെ യുപിഐ പിൻ പങ്കിടുക",
    "ningalude upi pin pankiduka",
    "ഉടൻ പണം കൈമാറുക",
    "udan panam kaimaaruka",
)

MULTILINGUAL_URGENT_PHRASES = (
    "आपका खाता तुरंत बंद हो जाएगा",
    "aapka khata turant band ho jayega",
    "ನಿಮ್ಮ ಖಾತೆಯನ್ನು ತಕ್ಷಣವೇ ಅಮಾನತುಗೊಳಿಸಲಾಗುತ್ತದೆ",
    "nimma khate takshanave amaanatugolisalaguttade",
    "మీ ఖాతా వెంటనే నిలిపివేయబడుతుంది",
    "mee khata ventane nilipiveyabadutundi",
    "உங்கள் கணக்கு உடனடியாக முடக்கப்படும்",
    "ungal kanakku udanadiyaga mudakkappadum",
    "നിങ്ങളുടെ അക്കൗണ്ട് ഉടൻ സസ്പെൻഡ് ചെയ്യും",
    "ningalude account udan suspend cheyyum",
)

MULTILINGUAL_CREDENTIAL_PHRASES = (
    "अपना पासवर्ड दर्ज करें",
    "apna password darj karein",
    "ನಿಮ್ಮ ಪಾಸ್‌ವರ್ಡ್ ನಮೂದಿಸಿ",
    "nimma password namoodisi",
    "మీ పాస్‌వర్డ్ నమోదు చేయండి",
    "mee password namodu cheyandi",
    "உங்கள் கடவுச்சொல்லை உள்ளிடவும்",
    "ungal password enter pannunga",
    "നിങ്ങളുടെ പാസ്‌വേഡ് നൽകുക",
    "ningalude password nalkuka",
)

BENIGN_MARKETING = re.compile(
    r"\b(?:newsletter|unsubscribe|weekly offers?|seasonal sale|shop now|"
    r"new collection|product launch|special offer|discount|promotion|"
    r"limited[- ]time offer|view in browser)\b",
    re.I,
)
INVISIBLE_RE = re.compile(r"[\u200b\u200e\u200f\u202a-\u202e\u2060\ufeff]")
QR_CONTEXT_RE = re.compile(r"\b(?:scan (?:the )?qr|qr code|scan to (?:pay|login|verify))\b", re.I)


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.image_count = 0
        self.hidden_link_count = 0
        self.stack = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag.lower() == "a":
            style = (attrs_dict.get("style") or "").lower().replace(" ", "")
            hidden = (
                attrs_dict.get("hidden") is not None
                or (attrs_dict.get("aria-hidden") or "").lower() == "true"
                or "display:none" in style
                or "visibility:hidden" in style
                or "font-size:0" in style
                or "opacity:0" in style
            )
            self.stack.append({
                "href": (attrs_dict.get("href") or "").strip(),
                "text": [],
                "hidden": hidden,
            })
        elif tag.lower() == "img":
            self.image_count += 1

    def handle_data(self, data):
        if self.stack and data:
            self.stack[-1]["text"].append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self.stack:
            item = self.stack.pop()
            self.links.append({
                "href": item["href"],
                "text": html.unescape(" ".join(item["text"])).strip(),
                "hidden": item["hidden"],
            })
            self.hidden_link_count += int(item["hidden"])


def _clean_url(raw: str) -> str:
    return html.unescape((raw or "").strip()).rstrip(".,;:!?)\\]}>'\"")


def _host(raw: str) -> str:
    url = _clean_url(raw)
    if not url:
        return ""
    if url.startswith("//"):
        url = "https:" + url
    elif url.lower().startswith("www."):
        url = "https://" + url
    elif not re.match(r"(?i)^https?://", url):
        url = "https://" + url
    try:
        return (urlparse(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address((host or "").strip("[]"))
        return True
    except ValueError:
        return False


def _detect_language(text: str) -> str:
    try:
        from langdetect import detect
        return detect(text[:5000]) if text.strip() else "unknown"
    except Exception:
        return "unknown"


def analyze_email(
    sender: str,
    subject: str,
    body: str,
    headers: dict | None = None,
) -> dict:
    """Explainable heuristic email assessment. Never visits URLs or downloads remote content."""
    sender = (sender or "").strip()
    subject = (subject or "").strip()
    body = (body or "").strip()
    headers = headers or {}

    normalized = re.sub(
        r"\s+", " ", f"{subject}\n{body}\nSender: {sender}"
    ).casefold()

    raw_urls = [_clean_url(url) for url in URL_RE.findall(subject + "\n" + body)]
    raw_urls = [url for url in raw_urls if url]

    parser = _LinkParser()
    if re.search(r"(?is)<(?:html|body|a|img|table)\b", body):
        try:
            parser.feed(body)
        except Exception:
            pass

    href_urls = []
    mismatch_count = 0
    for link in parser.links:
        href = _clean_url(link["href"])
        if href and re.match(r"(?i)^(?:https?://|www\.|//)", href):
            href_urls.append(href)
            visible = link["text"]
            actual_host = _host(href)
            visible_host = (
                _host(visible)
                if re.match(r"(?i)^(?:https?://|www\.)", visible)
                else ""
            )
            if visible_host and actual_host and visible_host != actual_host:
                mismatch_count += 1

    urls = list(dict.fromkeys(raw_urls + href_urls))
    domains = list(dict.fromkeys(_host(url) for url in urls if _host(url)))

    score = 0
    matched = []
    link_findings = []

    for name, (weight, patterns) in SIGNALS.items():
        active_patterns = patterns

        if name == "credential_request":
            active_patterns = [
                pattern for pattern in patterns
                if pattern != r"\breset your password\b"
            ]

            otp_warning = re.search(
                r"\b(?:never|do not|don't|dont|must not|should not)\s+"
                r"(?:ever\s+)?share\s+(?:your\s+)?otp\b",
                normalized,
                re.I,
            )

            if otp_warning:
                active_patterns = [
                    pattern for pattern in active_patterns
                    if pattern != r"\bshare your otp\b"
                ]

        if any(
            re.search(pattern, normalized, re.I)
            for pattern in active_patterns
        ):
            score += weight
            matched.append(name)

    if (
        "credential_request" not in matched
        and any(
            re.sub(r"[\\u200c\\u200d]", "", phrase.casefold())
            in re.sub(r"[\\u200c\\u200d]", "", normalized)
            for phrase in MULTILINGUAL_CREDENTIAL_PHRASES
        )
    ):
        score += 30
        matched.append("credential_request")

    normalized_for_multilingual = (
        normalized.replace("\u200c", "").replace("\u200d", "")
    )
    if (
        "urgent_action" not in matched
        and any(
            phrase.casefold().replace("\u200c", "").replace("\u200d", "")
            in normalized_for_multilingual
            for phrase in MULTILINGUAL_URGENT_PHRASES
        )
    ):
        score += 12
        matched.append("urgent_action")

    if (
        "payment_or_sensitive_data" not in matched
        and any(
            phrase.casefold().replace("\u200c", "").replace("\u200d", "")
            in normalized.replace("\u200c", "").replace("\u200d", "")
            for phrase in MULTILINGUAL_FINANCIAL_PHRASES
        )
    ):
        score += 30
        matched.append("payment_or_sensitive_data")

    def add_link_finding(name: str, weight: int):
        nonlocal score
        if name not in link_findings:
            link_findings.append(name)
            matched.append(name)
            score += weight

    if any(_host(url) in SHORTENERS for url in urls):
        add_link_finding("URL shortener present", 8)
    if any(_is_ip(_host(url)) for url in urls):
        add_link_finding("URL uses a raw IP address", 15)
    if any(
        host.startswith("xn--")
        or ".xn--" in host
        or any(ord(char) > 127 for char in host)
        for host in domains
    ):
        add_link_finding("Unicode or punycode hostname", 12)
    if any(
        re.search(r"(?i)(?:%[0-9a-f]{2}|\\x[0-9a-f]{2}|@[^/\s]+/)", url)
        for url in urls
    ):
        add_link_finding("URL encoding or user-info obfuscation", 8)
    if mismatch_count:
        add_link_finding(
            "Visible link text differs from destination",
            min(20, 12 + 2 * (mismatch_count - 1)),
        )
    if parser.hidden_link_count:
        add_link_finding("Hidden HTML link(s)", 12)
    if parser.image_count and not re.sub(r"(?is)<[^>]+>", " ", body).strip():
        add_link_finding("Image-heavy or image-only email", 5)
    if QR_CONTEXT_RE.search(normalized):
        add_link_finding("QR-code sign-in/payment wording", 8)
    if INVISIBLE_RE.search(body):
        add_link_finding("Invisible or direction-control characters", 8)

    score = max(0, min(100, int(score)))

    # HIGH requires multiple/strong signals; CRITICAL requires a very high
    # combined score. A single alarming phrase cannot automatically make an
    # email CRITICAL.
    if score >= 80:
        risk, label = "CRITICAL", "High-risk suspicious email"
    elif score >= 60:
        risk, label = "HIGH", "Potential phishing / suspicious email"
    elif score >= 30:
        risk, label = "MEDIUM", "Review required — possible false positive"
    else:
        risk = "LOW"
        label = (
            "No configured threat indicators detected"
             if score == 0
             else "Low-risk email with indicators requiring review"
        )

    marketing = bool(BENIGN_MARKETING.search(normalized))
    if marketing and score < 30:
        risk, label = "LOW", "Likely promotional / low risk"

    confidence = min(95, 50 + score // 2) if score else 60
    language = _detect_language(subject + " " + body)

    explanations = [
        "Detected indicators: " + ", ".join(matched)
        if matched
        else "No configured phishing-language or suspicious-link indicators were found."
    ]
    if marketing:
        explanations.append("Promotional wording alone is not treated as phishing.")
    if language == "unknown":
        explanations.append(
            "Language detection is unavailable or inconclusive; multilingual detection is not guaranteed."
        )
    explanations.append(
        "The score is a heuristic assessment, not a probability or proof of maliciousness."
    )

    auth_text = " ".join(
        str(value)
        for key, value in headers.items()
        if str(key).lower() in {
            "authentication-results",
            "arc-authentication-results",
        }
    )
    auth = {}
    for method in ("SPF", "DKIM", "DMARC"):
        match = re.search(
            rf"\b{method.lower()}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b",
            auth_text,
            re.I,
        )
        auth[method] = (
            match.group(1).lower()
            if match
            else ("not stated" if auth_text else "not provided")
        )

    return {
        "threat_type": label,
        "risk_level": risk,
        "risk_score": score,
        "confidence": confidence,
        "matched_indicators": matched,
        "urls": urls,
        "domains": domains,
        "language": language,
        "explanation": " ".join(explanations),
        "method": "contextual-rule-v3",
        "link_findings": link_findings,
        "header_authentication": auth,
        "html_link_count": len(parser.links),
        "hidden_link_count": parser.hidden_link_count,
        "link_text_mismatch_count": mismatch_count,
        "qr_context_detected": bool(QR_CONTEXT_RE.search(normalized)),
        "evidence_limitations": [
            "URLs were inspected as text only; no link was opened and no redirect chain was fetched.",
            "A risk score is heuristic and does not establish that a message is malicious.",
            "Authentication results are unknown unless relevant headers are supplied by the caller.",
        ],
    }
