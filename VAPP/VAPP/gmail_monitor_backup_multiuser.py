import base64
import html
import os
import hashlib
import re
import sqlite3
import threading
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
from html.parser import HTMLParser

from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
SENDER_SCOPES = ["https://www.googleapis.com/auth/gmail.send"]
SENDER_ACCOUNT = "lumivalestudios@gmail.com"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TOKEN_FILE = os.path.join(BASE_DIR, "token.json")
SENDER_TOKEN_FILE = os.path.join(BASE_DIR, "token_sender.json")
CREDENTIALS_FILE = os.path.join(BASE_DIR, "credentials.json")

_monitor_thread = None
_stop_event = threading.Event()


def get_gmail_service():
    """Load Gmail OAuth credentials, refreshing or re-authorizing if needed."""
    creds = None

    print(f"[VAPP-GMAIL] Token file: {TOKEN_FILE}")
    print(f"[VAPP-GMAIL] OAuth credentials file: {CREDENTIALS_FILE}")

    if os.path.exists(TOKEN_FILE):
        try:
            creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

            if creds and creds.expired and creds.refresh_token:
                print("[VAPP-GMAIL] Existing token expired; attempting refresh...")
                creds.refresh(Request())

        except (RefreshError, ValueError, OSError, KeyError) as exc:
            print(f"[VAPP-GMAIL] Saved token is invalid or revoked: {exc}")
            creds = None
            try:
                os.remove(TOKEN_FILE)
                print("[VAPP-GMAIL] Removed the invalid token. Fresh sign-in is required.")
            except FileNotFoundError:
                pass

    if not creds or not creds.valid:
        if not os.path.exists(CREDENTIALS_FILE):
            raise FileNotFoundError(
                "credentials.json not found in the VAPP folder. "
                "Place your Google OAuth Desktop-app credentials.json beside app.py."
            )

        print("[VAPP-GMAIL] Opening Google sign-in for fresh authorization...")
        flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
        creds = flow.run_local_server(port=0, prompt="consent")

    with open(TOKEN_FILE, "w", encoding="utf-8") as f:
        f.write(creds.to_json())

    print("[VAPP-GMAIL] Gmail OAuth authorization is ready.")
    return build("gmail", "v1", credentials=creds, cache_discovery=False)



def get_gmail_sender_service():
    """Authorize the separate VAPP alert-sending Gmail account."""
    creds = None
    print(f"[VAPP-ALERT] Sender account: {SENDER_ACCOUNT}")
    print(f"[VAPP-ALERT] Sender token file: {SENDER_TOKEN_FILE}")

    if os.path.exists(SENDER_TOKEN_FILE):
        try:
            creds = Credentials.from_authorized_user_file(
                SENDER_TOKEN_FILE, SENDER_SCOPES
            )
            if creds and creds.expired and creds.refresh_token:
                print("[VAPP-ALERT] Existing sender token expired; refreshing...")
                creds.refresh(Request())
            if creds and not creds.has_scopes(SENDER_SCOPES):
                print("[VAPP-ALERT] Sender token lacks Gmail send permission; reauthorization required.")
                creds = None
        except (RefreshError, ValueError, OSError, KeyError) as exc:
            print(f"[VAPP-ALERT] Saved sender token is invalid or revoked: {exc}")
            creds = None
            try:
                os.remove(SENDER_TOKEN_FILE)
            except FileNotFoundError:
                pass

    if not creds or not creds.valid:
        if not os.path.exists(CREDENTIALS_FILE):
            raise FileNotFoundError(
                "credentials.json not found beside app.py; required for sender OAuth."
            )
        print("[VAPP-ALERT] Opening Google sign-in for the VAPP sender account...")
        flow = InstalledAppFlow.from_client_secrets_file(
            CREDENTIALS_FILE, SENDER_SCOPES
        )
        creds = flow.run_local_server(
            port=0,
            prompt="consent",
            login_hint=SENDER_ACCOUNT,
        )

    with open(SENDER_TOKEN_FILE, "w", encoding="utf-8") as f:
        f.write(creds.to_json())

    service = build("gmail", "v1", credentials=creds, cache_discovery=False)
    profile = service.users().getProfile(userId="me").execute()
    actual_sender = (profile.get("emailAddress") or "").lower()
    if actual_sender != SENDER_ACCOUNT.lower():
        raise RuntimeError(
            "The authorized sender account is " + (actual_sender or "unknown") +
            ", but VAPP is configured for " + SENDER_ACCOUNT +
            ". Sign in to the correct Google account and authorize again."
        )
    print(f"[VAPP-ALERT] Sender authorization ready: {actual_sender}")
    return service, actual_sender


def _decode_part(part):
    """Decode a Gmail API MIME body part without crashing on malformed data."""
    data = part.get("body", {}).get("data")
    if not data:
        return ""
    try:
        decoded = base64.urlsafe_b64decode(data.encode("utf-8"))
        charset = "utf-8"
        for parameter in part.get("mimeType", "").split(";")[1:]:
            # Gmail normally returns mimeType without charset parameters, so
            # UTF-8 with replacement is a safe fallback.
            if parameter.strip().lower().startswith("charset="):
                charset = parameter.split("=", 1)[1].strip().strip('"\'')
        try:
            return decoded.decode(charset, errors="replace")
        except LookupError:
            return decoded.decode("utf-8", errors="replace")
    except Exception:
        return ""


class _HTMLTextExtractor(HTMLParser):
    """Convert HTML to readable text while retaining basic spacing."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []

    def handle_data(self, data):
        if data:
            self.parts.append(data)

    def handle_starttag(self, tag, attrs):
        if tag.lower() in {"br", "p", "div", "li", "tr", "h1", "h2", "h3"}:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag.lower() in {"p", "div", "li", "tr"}:
            self.parts.append("\n")


def html_to_text(raw_html):
    parser = _HTMLTextExtractor()
    try:
        parser.feed(raw_html or "")
        return html.unescape(" ".join(parser.parts)).strip()
    except Exception:
        return html.unescape(re.sub(r"<[^>]*>", " ", raw_html or "")).strip()


def calculate_sha256(file_bytes):
    """Return the SHA-256 hash of attachment bytes."""
    return hashlib.sha256(file_bytes).hexdigest()


def get_attachment_hashes(service, message_id, attachments,
                          max_size_bytes=5 * 1024 * 1024):
    """
    Calculate SHA-256 hashes for small Gmail attachments.
    Does not execute or open files as programs.
    """
    results = []

    for attachment in attachments:
        item = {
            "filename": attachment.get("filename", "(unnamed attachment)"),
            "mime_type": attachment.get("mime_type", "unknown"),
            "size_bytes": attachment.get("size_bytes", 0),
            "sha256": None,
            "status": "not_processed",
            "qr_payloads": [],
        }

        attachment_id = attachment.get("attachment_id")
        size = item["size_bytes"]

        if not attachment_id:
            item["status"] = "no_attachment_id"
        elif not isinstance(size, int) or size < 0:
            item["status"] = "invalid_size"
        elif size > max_size_bytes:
            item["status"] = "skipped_size_limit"
        else:
            try:
                response = service.users().messages().attachments().get(
                    userId="me",
                    messageId=message_id,
                    id=attachment_id,
                ).execute()

                encoded_data = response.get("data", "")
                file_bytes = base64.urlsafe_b64decode(
                    encoded_data + "=" * (-len(encoded_data) % 4)
                )

                if len(file_bytes) != size:
                    item["status"] = "size_mismatch"
                else:
                    item["sha256"] = calculate_sha256(file_bytes)
                    item["status"] = "hashed"

                    # Decode QR codes from image attachments only.
                    if item["mime_type"].lower().startswith("image/"):
                        try:
                            from qr_email_decoder import decode_qr_image
                            item["qr_payloads"] = decode_qr_image(file_bytes)
                        except Exception as exc:
                            print(f"[VAPP-GMAIL] QR decode skipped: {exc}")

            except Exception as exc:
                item["status"] = "retrieval_failed"
                print(
                    f"[VAPP-GMAIL] Attachment hashing failed for "
                    f"{item['filename']}: {exc}"
                )

        results.append(item)

    return results


def extract_message_content(payload):
    """
    Extract readable text, raw HTML, and attachment metadata.
    Does not download, open, or execute attachment contents.
    """
    plain_parts = []
    html_parts = []
    attachments = []

    def walk(part):
        mime = (part.get("mimeType") or "").lower()
        filename = (part.get("filename") or "").strip()
        body_data = part.get("body") or {}
        children = part.get("parts") or []

        # Record attachment metadata only; do not fetch file contents.
        if filename or body_data.get("attachmentId"):
            attachments.append({
                "filename": filename or "(unnamed attachment)",
                "mime_type": mime or "unknown",
                "size_bytes": body_data.get("size", 0),
                "attachment_id": body_data.get("attachmentId"),
            })

        if mime == "text/plain" and not filename:
            text = _decode_part(part)
            if text.strip():
                plain_parts.append(text)

        elif mime == "text/html" and not filename:
            raw = _decode_part(part)
            if raw.strip():
                html_parts.append(raw)

        for child in children:
            walk(child)

    walk(payload)

    raw_html = "\n\n".join(html_parts)
    plain_text = "\n\n".join(plain_parts)

    if not plain_text and raw_html:
        plain_text = html_to_text(raw_html)

    analysis_body = plain_text
    if raw_html:
        analysis_body += (
            "\n\n[VAPP_RAW_HTML_FOR_OFFLINE_ANALYSIS]\n" + raw_html
        )

    return {
        "text_body": plain_text[:20000],
        "html_body": raw_html[:30000],
        "analysis_body": (
            analysis_body or "(No readable message body)"
        )[:50000],
        "attachments": attachments,
    }


def extract_body(payload):
    """Backward-compatible helper used by any existing imports."""
    return extract_message_content(payload)["analysis_body"]


def header_value(headers, name):
    wanted = name.lower()
    for h in headers or []:
        if h.get("name", "").lower() == wanted:
            return h.get("value", "")
    return ""


def headers_to_dict(headers):
    """Return selected useful headers without discarding duplicate Received headers."""
    wanted = {
        "from", "to", "reply-to", "return-path", "subject", "date",
        "message-id", "received", "authentication-results",
        "arc-authentication-results", "received-spf", "mime-version",
        "content-type", "content-transfer-encoding",
    }
    result = {}
    for item in headers or []:
        name = (item.get("name") or "").strip()
        value = (item.get("value") or "").strip()
        if name.lower() not in wanted:
            continue
        key = name.lower()
        if key in result:
            if isinstance(result[key], list):
                result[key].append(value)
            else:
                result[key] = [result[key], value]
        else:
            result[key] = value
    return result


def ensure_tables():
    db = os.path.join(BASE_DIR, "vapp.db")
    with sqlite3.connect(db, timeout=10) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS processed_gmail_messages (
                message_id TEXT PRIMARY KEY,
                processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)


def already_processed(message_id):
    db = os.path.join(BASE_DIR, "vapp.db")
    with sqlite3.connect(db, timeout=10) as con:
        row = con.execute(
            "SELECT 1 FROM processed_gmail_messages WHERE message_id = ?",
            (message_id,)
        ).fetchone()
    return row is not None


def mark_processed(message_id):
    db = os.path.join(BASE_DIR, "vapp.db")
    with sqlite3.connect(db, timeout=10) as con:
        con.execute(
            "INSERT OR IGNORE INTO processed_gmail_messages(message_id) VALUES (?)",
            (message_id,)
        )


def _build_forensic_report(result):
    """Build a readable forensic summary from the analyzer's recorded result."""
    def value(key, default="Not available"):
        item = result.get(key, default)
        if item is None or item == "":
            return default
        if isinstance(item, (dict, list, tuple)):
            return str(item)
        return str(item)

    indicators = result.get("matched_indicators") or []
    urls = result.get("urls") or []
    domains = result.get("domains") or []
    attachments = result.get("attachment_analysis") or result.get("attachments") or []
    auth = result.get("header_authentication") or {}

    lines = [
        "VISIONARY AI PROTECTION PLATFORM (VAPP)",
        "EMAIL SECURITY FORENSIC SUMMARY",
        "=" * 58,
        "",
        f"Event ID: {value('event_id')}",
        f"Generated (local system time): {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"Risk level: {value('risk_level')}",
        f"Risk score: {value('risk_score')} / 100",
        f"Confidence: {value('confidence')}%",
        f"Threat classification: {value('threat_type')}",
        "",
        "MESSAGE DETAILS",
        "-" * 58,
        f"Sender: {value('sender')}",
        f"Subject: {value('subject')}",
        f"Received message ID: {value('gmail_message_id')}",
        "",
        "DETECTION EVIDENCE",
        "-" * 58,
        "Matched indicators:",
        *([f"  - {x}" for x in indicators] or ["  - None recorded"]),
        "",
        f"Explanation: {value('explanation')}",
        f"Recommendation: {value('recommendation', 'Review the message carefully; do not open suspicious links or attachments.')}",
        "",
        "URL / DOMAIN OBSERVATIONS",
        "-" * 58,
        "URLs:",
        *([f"  - {x}" for x in urls] or ["  - None detected"]),
        "Domains:",
        *([f"  - {x}" for x in domains] or ["  - None extracted"]),
        "",
        "EMAIL AUTHENTICATION",
        "-" * 58,
        *([f"{k}: {v}" for k, v in auth.items()] or ["No authentication results recorded."]),
        "",
        "ATTACHMENT ANALYSIS",
        "-" * 58,
    ]
    if attachments:
        for item in attachments:
            if isinstance(item, dict):
                lines.append(
                    f"File: {item.get('filename', 'Unknown')} | "
                    f"Type: {item.get('mime_type', 'Unknown')} | "
                    f"Status: {item.get('status', 'metadata only')} | "
                    f"SHA-256: {item.get('sha256') or 'Not calculated'}"
                )
                for qr in item.get("qr_payloads", []) or []:
                    lines.append(f"  QR payload (decoded text): {qr}")
            else:
                lines.append(f"- {item}")
    else:
        lines.append("No attachment analysis details recorded.")

    lines += [
        "",
        "SCOPE AND LIMITATIONS",
        "-" * 58,
        "This report summarizes VAPP's automated heuristic analysis. A risk score is not proof of maliciousness.",
        "URLs are inspected as text only; VAPP does not visit them or follow redirects during this analysis.",
        "Unknown or missing email authentication data is not treated as a pass or fail.",
        "Review the original message and corroborate findings before taking action.",
        "",
        "Generated automatically by VAPP Gmail monitoring.",
    ]
    return "\n".join(lines)


def send_alert(sender_service, sender_email, recipient, result):
    """Send a Gmail alert from the separately authorized VAPP sender account."""
    risk = result.get("risk_level", "UNKNOWN")
    threat = result.get("threat_type", "Email Threat")
    subject = f"[VAPP ALERT] {risk} - {threat}"
    body = (
        "VAPP Security Alert\n\n"
        f"Threat: {threat}\n"
        f"Risk Level: {risk}\n"
        f"Risk Score: {result.get('risk_score', 'N/A')} / 100\n"
        f"Confidence: {result.get('confidence', 'N/A')}%\n"
        f"Sender: {result.get('sender', 'Unknown')}\n"
        f"Subject: {result.get('subject', 'Unknown')}\n"
        f"Event ID: {result.get('event_id', 'N/A')}\n\n"
        f"Indicators: {', '.join(result.get('matched_indicators', [])) or 'None'}\n\n"
        f"Explanation: {result.get('explanation', 'No explanation provided')}\n\n"
        "The VAPP forensic summary is attached. Do not open suspicious links or attachments from the original email.\n"
    )

    message = MIMEMultipart()
    message["From"] = formataddr(("VAPP Security Alerts", sender_email))
    message["to"] = recipient
    message["subject"] = subject
    message.attach(MIMEText(body, "plain", "utf-8"))

    report_text = _build_forensic_report(result)
    report = MIMEText(report_text, "plain", "utf-8")
    report.add_header(
        "Content-Disposition",
        "attachment",
        filename=f"VAPP_Forensic_Report_Event_{result.get('event_id', 'unknown')}.txt",
    )
    message.attach(report)

    raw = base64.urlsafe_b64encode(message.as_bytes()).decode("utf-8")
    sender_service.users().messages().send(userId="me", body={"raw": raw}).execute()


def _mark_read(service, message_id):
    try:
        service.users().messages().modify(
            userId="me",
            id=message_id,
            body={"removeLabelIds": ["UNREAD"]}
        ).execute()
    except Exception as exc:
        print(f"[VAPP-GMAIL] Could not mark message read: {exc}")


def monitor_loop(process_callback, user_id, interval=5):
    ensure_tables()
    print(f"[VAPP-GMAIL] Monitor started. Checking Gmail every {interval} seconds...")

    try:
        service = get_gmail_service()
        profile = service.users().getProfile(userId="me").execute()
        monitored_email = profile.get("emailAddress", "")
        print(f"[VAPP-GMAIL] Monitoring mailbox: {monitored_email}")

        sender_service = None
        sender_email = None
        try:
            sender_service, sender_email = get_gmail_sender_service()
        except Exception as sender_exc:
            print(f"[VAPP-ALERT] Sender authorization unavailable: {sender_exc}")
            print("[VAPP-ALERT] Gmail monitoring will continue, but alerts cannot be sent until sender OAuth is completed.")

        # Baseline existing messages so old mail is not treated as newly received.
        baseline = service.users().messages().list(
            userId="me", q="in:anywhere newer_than:7d", maxResults=100
        ).execute()
        baseline_count = 0
        for item in baseline.get("messages", []):
            if not already_processed(item["id"]):
                mark_processed(item["id"])
                baseline_count += 1

        print(
            f"[VAPP-GMAIL] Baseline complete: {baseline_count} existing message(s) ignored. "
            "Only NEW emails will be analyzed."
        )
    except Exception as exc:
        print(f"[VAPP-GMAIL] Startup error: {exc}")
        return

    while not _stop_event.is_set():
        try:
            response = service.users().messages().list(
                userId="me", q="in:anywhere newer_than:7d", maxResults=20
            ).execute()

            for item in response.get("messages", []):
                if _stop_event.is_set():
                    break

                message_id = item["id"]
                if already_processed(message_id):
                    continue

                try:
                    msg = service.users().messages().get(
                        userId="me", id=message_id, format="full"
                    ).execute()
                    payload = msg.get("payload", {})
                    raw_headers = payload.get("headers", [])
                    sender = header_value(raw_headers, "From") or "Unknown sender"
                    subject = header_value(raw_headers, "Subject") or "(No subject)"
                    content = extract_message_content(payload)
                    print("[VAPP-DEBUG] Attachment metadata:", content["attachments"])
                    attachment_results = get_attachment_hashes(
                        service,
                        message_id,
                        content["attachments"],
                    )

                    # Include decoded QR text in offline email analysis.
                    qr_payloads = list(dict.fromkeys(
                        payload
                        for attachment in attachment_results
                        for payload in attachment.get("qr_payloads", [])
                    ))
                    if qr_payloads:
                        content["analysis_body"] += (
                            "\n\n[VAPP_QR_PAYLOADS_FROM_IMAGE_ATTACHMENTS]\n"
                            + "\n".join(qr_payloads)
                        )

                    # Avoid recursively analyzing VAPP's own generated alerts.
                    if subject.startswith("[VAPP ALERT]"):
                        mark_processed(message_id)
                        _mark_read(service, message_id)
                        continue

                    data = {
                        "sender": sender,
                        "subject": subject,
                        # Existing process_callback implementations can continue
                        # using data["body"]; it now includes raw HTML for analysis.
                        "body": content["analysis_body"],
                        "text_body": content["text_body"],
                        "html_body": content["html_body"],
                        "attachments": content["attachments"],
                        "attachment_analysis": attachment_results,
                        "headers": headers_to_dict(raw_headers),
                        "gmail_message_id": message_id,
                        "gmail_thread_id": msg.get("threadId", ""),
                        "internal_date": msg.get("internalDate", ""),
                        "label_ids": msg.get("labelIds", []),
                        # This is a source marker, not a sender IP address.
                        "source_ip": "GMAIL-MONITORED",
                    }

                    result = process_callback(data, user_id)
                    if isinstance(result, tuple):
                        result = result[0]

                    if result and result.get("success"):
                        mark_processed(message_id)
                        _mark_read(service, message_id)

                        if result.get("risk_level") in ("HIGH", "CRITICAL"):
                            try:
                                if not sender_service or not sender_email:
                                    raise RuntimeError(
                                        "VAPP sender account is not authorized. Restart app.py and complete sender Google sign-in."
                                    )
                                send_alert(sender_service, sender_email, monitored_email, result)
                                print(
                                    f"[VAPP-GMAIL] ALERT SENT from {sender_email} "
                                    f"to {monitored_email} for event #{result.get('event_id', 'N/A')}"
                                )
                            except Exception as exc:
                                print(f"[VAPP-GMAIL] Alert email failed: {exc}")

                        print(
                            f"[VAPP-GMAIL] DETECTED #{result.get('event_id', 'N/A')} | "
                            f"{result.get('threat_type', 'Unknown')} | "
                            f"{result.get('risk_level', 'Unknown')} | "
                            f"score={result.get('risk_score', 'N/A')}"
                        )
                    else:
                        print(
                            f"[VAPP-GMAIL] Processing did not report success for "
                            f"{message_id}; it will be retried."
                        )

                except Exception as exc:
                    print(f"[VAPP-GMAIL] Could not process message {message_id}: {exc}")

        except Exception as exc:
            print(f"[VAPP-GMAIL] Monitor error: {exc}")

        _stop_event.wait(max(1, int(interval)))


def start_gmail_monitor(process_callback, user_id):
    global _monitor_thread
    if _monitor_thread and _monitor_thread.is_alive():
        return
    _stop_event.clear()
    _monitor_thread = threading.Thread(
        target=monitor_loop,
        args=(process_callback, user_id),
        daemon=True,
        name="VAPP-Gmail-Monitor",
    )
    _monitor_thread.start()


def stop_gmail_monitor():
    """Signal the background monitor to stop."""
    _stop_event.set()
