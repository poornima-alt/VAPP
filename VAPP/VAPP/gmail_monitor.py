import base64
import html
import os
import hashlib
import json
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
from cryptography.fernet import Fernet, InvalidToken
from googleapiclient.discovery import build
from database import get_connection

SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
SENDER_SCOPES = ["https://www.googleapis.com/auth/gmail.send"]
SENDER_ACCOUNT = "lumivalestudios@gmail.com"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SENDER_TOKEN_FILE = os.path.join(BASE_DIR, "token_sender.json")

_monitor_threads = {}
_stop_events = {}
_monitor_lock = threading.RLock()


def _credential_cipher():
    key = os.environ.get("VAPP_TOKEN_ENCRYPTION_KEY", "").strip()
    if not key:
        raise RuntimeError(
            "VAPP_TOKEN_ENCRYPTION_KEY is not configured. Set a persistent Fernet key before connecting Gmail."
        )
    try:
        return Fernet(key.encode("ascii"))
    except Exception as exc:
        raise RuntimeError("VAPP_TOKEN_ENCRYPTION_KEY is invalid; generate a Fernet key.") from exc


def save_user_credentials(user_id, credentials, gmail_email):
    """Encrypt and upsert one user's Google OAuth credentials in SQLite."""
    encrypted = _credential_cipher().encrypt(credentials.to_json().encode("utf-8")).decode("ascii")
    connection = get_connection()
    try:
        connection.execute("""
            INSERT INTO gmail_oauth_tokens (user_id, gmail_email, encrypted_credentials, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id) DO UPDATE SET
                gmail_email=excluded.gmail_email,
                encrypted_credentials=excluded.encrypted_credentials,
                updated_at=CURRENT_TIMESTAMP
        """, (int(user_id), str(gmail_email).strip().lower(), encrypted))
        connection.execute("""
            INSERT INTO user_integrations (user_id, provider, external_account, status, credential_ref, updated_at)
            VALUES (?, 'gmail', ?, 'connected', 'gmail_oauth_tokens', CURRENT_TIMESTAMP)
            ON CONFLICT(user_id, provider) DO UPDATE SET
                external_account=excluded.external_account,
                status='connected', credential_ref='gmail_oauth_tokens', updated_at=CURRENT_TIMESTAMP
        """, (int(user_id), str(gmail_email).strip().lower()))
        connection.commit()
    finally:
        connection.close()


def load_user_credentials(user_id):
    """Decrypt only the OAuth credential row belonging to the requested user."""
    connection = get_connection()
    try:
        row = connection.execute(
            "SELECT encrypted_credentials FROM gmail_oauth_tokens WHERE user_id = ?",
            (int(user_id),)
        ).fetchone()
    finally:
        connection.close()
    if not row:
        return None
    try:
        raw = _credential_cipher().decrypt(row["encrypted_credentials"].encode("ascii"))
        info = json.loads(raw.decode("utf-8"))
        credentials = Credentials.from_authorized_user_info(info, SCOPES)
    except (InvalidToken, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Stored Gmail credentials could not be decrypted or parsed. Reconnect Gmail.") from exc
    return credentials


def delete_user_credentials(user_id):
    connection = get_connection()
    try:
        connection.execute("DELETE FROM gmail_oauth_tokens WHERE user_id = ?", (int(user_id),))
        connection.execute("""
            INSERT INTO user_integrations (user_id, provider, external_account, status, credential_ref, updated_at)
            VALUES (?, 'gmail', NULL, 'disconnected', NULL, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id, provider) DO UPDATE SET
                external_account=NULL, status='disconnected', credential_ref=NULL, updated_at=CURRENT_TIMESTAMP
        """, (int(user_id),))
        connection.commit()
    finally:
        connection.close()


def get_user_gmail_status(user_id):
    connection = get_connection()
    try:
        row = connection.execute(
            "SELECT gmail_email FROM gmail_oauth_tokens WHERE user_id = ?", (int(user_id),)
        ).fetchone()
    finally:
        connection.close()
    with _monitor_lock:
        thread = _monitor_threads.get(int(user_id))
        running = bool(thread and thread.is_alive())
    return {"connected": bool(row), "email": row["gmail_email"] if row else None, "monitoring": running}


def get_gmail_service(user_id):
    """Build a Gmail API service from the authenticated user's encrypted token."""
    credentials = load_user_credentials(user_id)
    if credentials is None:
        raise RuntimeError("This VAPP user has not connected a Gmail account.")
    if credentials.expired and credentials.refresh_token:
        credentials.refresh(Request())
        connection = get_connection()
        try:
            encrypted = _credential_cipher().encrypt(credentials.to_json().encode("utf-8")).decode("ascii")
            connection.execute("""
                UPDATE gmail_oauth_tokens SET encrypted_credentials=?, updated_at=CURRENT_TIMESTAMP
                WHERE user_id=?
            """, (encrypted, int(user_id)))
            connection.commit()
        finally:
            connection.close()
    if not credentials.valid:
        raise RuntimeError("Gmail authorization has expired or been revoked. Reconnect Gmail.")
    if not credentials.has_scopes(SCOPES):
        raise RuntimeError("Gmail authorization is missing the required permission. Reconnect Gmail.")
    return build("gmail", "v1", credentials=credentials, cache_discovery=False)


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
        raise RuntimeError(
            "The optional VAPP alert-sender token is not available. "
            "Configure the sender token separately or use the SMTP alert fallback."
        )

    # Persist refreshed sender credentials without ever starting an interactive
    # desktop OAuth flow inside the Flask web server or monitor thread.
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
    connection = get_connection()
    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS processed_gmail_messages (
                user_id INTEGER NOT NULL,
                message_id TEXT NOT NULL,
                processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, message_id),
                FOREIGN KEY (user_id) REFERENCES users(id)
                    ON DELETE CASCADE
            )
        """)
        connection.commit()
    finally:
        connection.close()


def already_processed(message_id, user_id):
    connection = get_connection()
    try:
        row = connection.execute(
            """
            SELECT 1
            FROM processed_gmail_messages
            WHERE user_id = ? AND message_id = ?
            """,
            (user_id, message_id)
        ).fetchone()
        return row is not None
    finally:
        connection.close()


def mark_processed(message_id, user_id):
    connection = get_connection()
    try:
        connection.execute(
            """
            INSERT OR IGNORE INTO processed_gmail_messages
            (user_id, message_id)
            VALUES (?, ?)
            """,
            (user_id, message_id)
        )
        connection.commit()
    finally:
        connection.close()

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


def monitor_loop(process_callback, user_id, stop_event, interval=5):
    """Monitor one user's Gmail mailbox using that user's own OAuth token."""
    ensure_tables()
    user_id = int(user_id)
    print(f"[VAPP-GMAIL] User {user_id}: monitor starting (interval={interval}s).")

    try:
        service = get_gmail_service(user_id)
        profile = service.users().getProfile(userId="me").execute()
        monitored_email = (profile.get("emailAddress") or "").strip().lower()
        if not monitored_email:
            raise RuntimeError("Google did not return the connected Gmail address.")
        print(f"[VAPP-GMAIL] User {user_id}: monitoring {monitored_email}.")
    except Exception as exc:
        print(f"[VAPP-GMAIL] User {user_id}: startup failed: {exc}")
        return

    sender_service = None
    sender_email = None
    try:
        sender_service, sender_email = get_gmail_sender_service()
    except Exception as sender_exc:
        print(f"[VAPP-ALERT] Dedicated sender unavailable; configured SMTP fallback may be used: {sender_exc}")

    try:
        baseline = service.users().messages().list(
            userId="me", q="in:anywhere newer_than:7d", maxResults=100
        ).execute()
        baseline_count = 0
        for item in baseline.get("messages", []):
            if not already_processed(item["id"], user_id):
                mark_processed(item["id"], user_id)
                baseline_count += 1
        print(f"[VAPP-GMAIL] User {user_id}: baseline complete; {baseline_count} existing messages ignored.")
    except Exception as exc:
        print(f"[VAPP-GMAIL] User {user_id}: baseline failed: {exc}")
        return

    while not stop_event.is_set():
        try:
            response = service.users().messages().list(
                userId="me", q="in:anywhere newer_than:7d", maxResults=20
            ).execute()
            for item in response.get("messages", []):
                if stop_event.is_set():
                    break
                message_id = item.get("id")
                if not message_id or already_processed(message_id, user_id):
                    continue
                try:
                    msg = service.users().messages().get(
                        userId="me", id=message_id, format="full"
                    ).execute()

                    # Retrieve original RFC822 message bytes for authentication checks.
                    raw_email_bytes = None
                    try:
                        raw_msg = service.users().messages().get(
                            userId="me", id=message_id, format="raw"
                        ).execute()
                        raw_encoded = raw_msg.get("raw", "")
                        if raw_encoded:
                            raw_email_bytes = base64.urlsafe_b64decode(
                                raw_encoded + "=" * (-len(raw_encoded) % 4)
                            )
                    except Exception as raw_error:
                        print(
                            f"[VAPP-GMAIL] Raw message unavailable for "
                            f"{message_id}: {type(raw_error).__name__}"
                        )

                    payload = msg.get("payload", {})
                    raw_headers = payload.get("headers", [])
                    sender = header_value(raw_headers, "From") or "Unknown sender"
                    subject = header_value(raw_headers, "Subject") or "(No subject)"
                    content = extract_message_content(payload)
                    attachment_results = get_attachment_hashes(service, message_id, content["attachments"])
                    qr_payloads = list(dict.fromkeys(
                        qr for attachment in attachment_results
                        for qr in attachment.get("qr_payloads", [])
                    ))
                    if qr_payloads:
                        content["analysis_body"] += (
                            "\n\n[VAPP_QR_PAYLOADS_FROM_IMAGE_ATTACHMENTS]\n" + "\n".join(qr_payloads)
                        )
                    if subject.startswith("[VAPP ALERT]"):
                        mark_processed(message_id, user_id)
                        _mark_read(service, message_id)
                        continue
                    data = {
                        "sender": sender,
                        "subject": subject,
                        "body": content["analysis_body"],
                        "text_body": content["text_body"],
                        "html_body": content["html_body"],
                        "attachments": content["attachments"],
                        "attachment_analysis": attachment_results,
                        "headers": headers_to_dict(raw_headers),
                        "raw_email_bytes": raw_email_bytes,
                        "gmail_message_id": message_id,
                        "gmail_thread_id": msg.get("threadId", ""),
                        "internal_date": msg.get("internalDate", ""),
                        "label_ids": msg.get("labelIds", []),
                        "source_ip": "GMAIL-MONITORED",
                        # If the dedicated sender works, send one alert through it;
                        # otherwise let the app's configured SMTP fallback handle it.
                        "suppress_smtp_alert": bool(sender_service and sender_email),
                    }
                    result = process_callback(data, user_id)
                    if isinstance(result, tuple):
                        result = result[0]
                    if result and result.get("success"):
                        mark_processed(message_id, user_id)
                        _mark_read(service, message_id)
                        if result.get("risk_level") in ("HIGH", "CRITICAL") and sender_service and sender_email:
                            try:
                                send_alert(sender_service, sender_email, monitored_email, result)
                                print(f"[VAPP-GMAIL] User {user_id}: alert sent for event #{result.get('event_id', 'N/A')}.")
                            except Exception as exc:
                                print(f"[VAPP-ALERT] User {user_id}: delivery failed: {exc}")
                        print(
                            f"[VAPP-GMAIL] User {user_id}: event #{result.get('event_id', 'N/A')} "
                            f"| {result.get('threat_type', 'Unknown')} | {result.get('risk_level', 'Unknown')}"
                        )
                    else:
                        print(f"[VAPP-GMAIL] User {user_id}: message {message_id} was not saved; it will retry.")
                except Exception as exc:
                    print(f"[VAPP-GMAIL] User {user_id}: message processing failed: {exc}")
        except Exception as exc:
            print(f"[VAPP-GMAIL] User {user_id}: polling error: {exc}")
        stop_event.wait(max(2, int(interval)))


def _monitor_worker(process_callback, user_id, stop_event, interval):
    try:
        monitor_loop(process_callback, user_id, stop_event, interval)
    finally:
        with _monitor_lock:
            current = _monitor_threads.get(int(user_id))
            if current is threading.current_thread():
                _monitor_threads.pop(int(user_id), None)
                _stop_events.pop(int(user_id), None)


def start_gmail_monitor(process_callback, user_id, interval=5):
    """Start an independent monitor for one VAPP user; idempotent per user."""
    user_id = int(user_id)
    with _monitor_lock:
        existing = _monitor_threads.get(user_id)
        if existing and existing.is_alive():
            return {"started": False, "already_running": True}
        stop_event = threading.Event()
        thread = threading.Thread(
            target=_monitor_worker,
            args=(process_callback, user_id, stop_event, interval),
            daemon=True,
            name=f"VAPP-Gmail-Monitor-{user_id}",
        )
        _stop_events[user_id] = stop_event
        _monitor_threads[user_id] = thread
        thread.start()
        return {"started": True, "already_running": False}


def stop_gmail_monitor(user_id, join_timeout=3):
    """Stop only the requested user's monitor, never another user's thread."""
    user_id = int(user_id)
    with _monitor_lock:
        stop_event = _stop_events.get(user_id)
        thread = _monitor_threads.get(user_id)
        if not stop_event:
            return {"stopped": False, "not_running": True}
        stop_event.set()
    if thread and thread is not threading.current_thread():
        thread.join(timeout=max(0.1, float(join_timeout)))
    return {"stopped": True, "still_stopping": bool(thread and thread.is_alive())}
