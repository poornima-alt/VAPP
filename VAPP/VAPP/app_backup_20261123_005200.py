from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify, Response, send_file
)
from database import get_connection, initialize_database, create_demo_user, generate_registration_code
from detector import detector
from risk_engine import calculate_risk, generate_explanation, generate_recommendation
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import csv
import io
import hmac
import hashlib
import secrets
import ipaddress
import os
import re
import smtplib
import ssl
from email.message import EmailMessage
from html import escape
from urllib.parse import urlsplit
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from email_analyzer import analyze_email
from url_intelligence import inspect_urls
from qr_threat_analyzer import analyze_qr_payload
from email_authentication import verify_email_authentication
from sms_analyzer import analyze_sms
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from gmail_monitor import (
    SCOPES as GMAIL_SCOPES,
    save_user_credentials,
    delete_user_credentials,
    get_user_gmail_status,
    start_gmail_monitor,
    stop_gmail_monitor,
)

app = Flask(__name__)
app.secret_key = os.environ.get("VAPP_SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("VAPP_HTTPS_ONLY", "0") == "1",
)

initialize_database()
create_demo_user()


def login_required():
    return "user_id" in session


def get_user_events(user_id, limit=None):
    connection = get_connection()
    params = [user_id]
    where = "WHERE se.user_id = ?"

    sql = f"""
        SELECT
            se.id,
            se.user_id,
            se.timestamp,
            se.source_ip,
            se.destination_ip,
            se.protocol,
            se.port,
            se.event_type,
            se.description,
            se.severity,
            ar.threat_type,
            ar.confidence,
            ar.risk_score,
            ar.risk_level,
            ar.explanation,
            ar.recommendation,
            u.name AS user_name,
            u.email AS user_email
        FROM security_events se
        LEFT JOIN analysis_results ar
            ON ar.id = (
                SELECT ar2.id
                FROM analysis_results ar2
                WHERE ar2.event_id = se.id
                ORDER BY ar2.analysed_at DESC, ar2.id DESC
                LIMIT 1
            )
        LEFT JOIN users u ON se.user_id = u.id
        {where}
        ORDER BY se.id DESC
    """
    if limit:
        sql += " LIMIT ?"
        params.append(limit)

    rows = connection.execute(sql, tuple(params)).fetchall()
    connection.close()
    return [dict(row) for row in rows]


def dashboard_stats(events):
    """Calculate dashboard totals from one latest analysis row per event."""
    def risk_level(event):
        return str(event.get("risk_level") or event.get("severity") or "").upper()

    def is_threat(event):
        threat = str(event.get("threat_type") or "").strip()
        level = risk_level(event)
        return (bool(threat) and threat.casefold() != "normal") or level in {
            "MEDIUM", "HIGH", "CRITICAL"
        }

    threats = [event for event in events if is_threat(event)]
    high = [
        event for event in events
        if risk_level(event) in ("HIGH", "CRITICAL")
    ]
    medium = [event for event in events if risk_level(event) == "MEDIUM"]
    low = [event for event in events if risk_level(event) == "LOW"]

    categories = {}
    for event in threats:
        name = str(event.get("threat_type") or "Unclassified threat").strip()
        if not name or name.casefold() == "normal":
            name = "Unclassified threat"
        categories[name] = categories.get(name, 0) + 1

    return {
        "total": len(events),
        "threats": len(threats),
        "high": len(high),
        "medium": len(medium),
        "low": len(low),
        "categories": categories,
    }




def save_analysis_event(user_id, event, threat_type, confidence,
                        risk_score, risk_level, explanation, recommendation):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO security_events
        (user_id, source_ip, destination_ip, protocol, port,
         event_type, description, severity)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        event["source_ip"],
        event["destination_ip"],
        event["protocol"],
        event["port"],
        event["event_type"],
        event["description"],
        event["severity"],
    ))

    event_id = cursor.lastrowid

    cursor.execute("""
        INSERT INTO analysis_results
        (event_id, threat_type, confidence, risk_score, risk_level,
         explanation, recommendation)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        event_id,
        threat_type,
        confidence,
        risk_score,
        risk_level,
        explanation,
        recommendation,
    ))

    connection.commit()
    connection.close()
    return event_id


@app.route("/")
def home():
    return redirect(url_for("dashboard" if login_required() else "login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not name or not email or not password or not confirm_password:
            flash("Please complete every field.")
            return render_template("signup.html", name=name, email=email), 400

        if len(name) > 100:
            flash("Name must be 100 characters or fewer.")
            return render_template("signup.html", name=name, email=email), 400

        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            flash("Please enter a valid email address.")
            return render_template("signup.html", name=name, email=email), 400

        if len(password) < 8:
            flash("Password must contain at least 8 characters.")
            return render_template("signup.html", name=name, email=email), 400

        if password != confirm_password:
            flash("The passwords do not match. Please check both fields.")
            return render_template("signup.html", name=name, email=email), 400

        connection = get_connection()
        try:
            existing = connection.execute(
                "SELECT id FROM users WHERE email = ?", (email,)
            ).fetchone()
            if existing:
                flash("An account with this email already exists. Please log in.")
                return render_template("signup.html", name=name, email=email), 409

            # The unique index is the final collision guard; retry if a code ever collides.
            for _ in range(10):
                registration_code = generate_registration_code()
                try:
                    connection.execute(
                        "INSERT INTO users (name, email, password_hash, registration_code) "
                        "VALUES (?, ?, ?, ?)",
                        (name, email, generate_password_hash(password), registration_code)
                    )
                    connection.commit()
                    break
                except Exception as exc:
                    if "registration_code" in str(exc).lower() and "unique" in str(exc).lower():
                        connection.rollback()
                        continue
                    raise
            else:
                flash("We couldn't generate your registration code. Please try again.")
                return render_template("signup.html", name=name, email=email), 500
        finally:
            connection.close()

        return render_template(
            "registration_success.html",
            name=name,
            email=email,
            registration_code=registration_code,
        )

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        connection = get_connection()
        user = connection.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()
        connection.close()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.")

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if not login_required():
        return redirect(url_for("login"))

    events = get_user_events(session["user_id"])
    stats = dashboard_stats(events)

    return render_template(
        "dashboard.html",
        user_name=session["user_name"],
        total_events=stats["total"],
        total_threats=stats["threats"],
        high_risk=stats["high"],
        recent_events=events[:10],
    )
 
@app.route("/simulate/<attack_type>", methods=["POST"])
def simulate_attack(attack_type):
    if not login_required():
        return jsonify({"success": False, "message": "Login required."}), 401

    events = {
        "normal": {
            "source_ip": "10.0.0.20",
            "destination_ip": "10.0.0.10",
            "protocol": "HTTPS",
            "port": 443,
            "event_type": "Normal Activity",
            "description": "Normal authenticated web request.",
            "severity": "LOW",
            "failed_attempts": 0, "unique_ports": 1,
            "event_rate": 1, "suspicious_keyword": 0, "unusual_port": 0,
        },
        "suspicious": {
            "source_ip": "10.0.0.25",
            "destination_ip": "10.0.0.10",
            "protocol": "TCP",
            "port": 8080,
            "event_type": "Suspicious Activity",
            "description": "Unusual connection behavior detected.",
            "severity": "MEDIUM",
            "failed_attempts": 3, "unique_ports": 2,
            "event_rate": 7, "suspicious_keyword": 1, "unusual_port": 0,
        },
        "port_scan": {
            "source_ip": "10.0.0.15",
            "destination_ip": "10.0.0.10",
            "protocol": "TCP",
            "port": 0,
            "event_type": "Port Scan",
            "description": "Multiple destination ports contacted in a short period.",
            "severity": "HIGH",
            "failed_attempts": 0, "unique_ports": 10,
            "event_rate": 20, "suspicious_keyword": 1, "unusual_port": 0,
        },
        "brute_force": {
            "source_ip": "10.0.0.30",
            "destination_ip": "10.0.0.10",
            "protocol": "SSH",
            "port": 22,
            "event_type": "Authentication Attack",
            "description": "Repeated failed SSH authentication attempts detected.",
            "severity": "HIGH",
            "failed_attempts": 10, "unique_ports": 1,
            "event_rate": 15, "suspicious_keyword": 1, "unusual_port": 22,
        },
    }

    if attack_type not in events:
        return jsonify({"success": False, "message": "Unknown simulation type."}), 400

    event = events[attack_type]
    detection = detector.analyze(event)
    threat_type = detection["threat_type"]
    confidence = detection["confidence"]

    risk = calculate_risk(event, threat_type, confidence)
    risk_score = risk["risk_score"]
    risk_level = risk["risk_level"]

    explanation = generate_explanation(event, threat_type, risk_level)
    recommendation = generate_recommendation(threat_type, risk_level)

    event_id = save_analysis_event(
        session["user_id"], event, threat_type, confidence,
        risk_score, risk_level, explanation, recommendation
    )

    return jsonify({
        "success": True,
        "event_id": event_id,
        "threat_type": threat_type,
        "confidence": confidence,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "explanation": explanation,
        "recommendation": recommendation,
        "source_ip": event["source_ip"],
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })


def send_vapp_email_alert(event_id, sender, subject, threat_type, risk_level, risk_score, timestamp):
    """Send a minimal Gmail alert for a HIGH/CRITICAL email event.

    Credentials are read only from environment variables. Notification errors
    are intentionally isolated so event storage and analysis remain successful.
    """
    gmail_address = os.environ.get("VAPP_GMAIL_ADDRESS", "").strip()
    app_password = os.environ.get("VAPP_GMAIL_APP_PASSWORD", "").replace(" ", "").strip()
    alert_to = os.environ.get("VAPP_ALERT_TO", "").strip() or gmail_address

    if not gmail_address or not app_password or not alert_to:
        app.logger.warning("VAPP email alert skipped: Gmail environment settings are incomplete.")
        return False

    message = EmailMessage()
    message["Subject"] = f"[VAPP {risk_level}] Email security alert â€” Event #{event_id}"
    message["From"] = gmail_address
    message["To"] = alert_to
    message.set_content(
        "VAPP detected a high-risk incoming email event.\n\n"
        f"Event ID: #{event_id}\n"
        f"Risk level: {risk_level}\n"
        f"Risk score: {risk_score}/100\n"
        f"Threat classification: {threat_type}\n"
        f"Observed sender: {sender}\n"
        f"Email subject: {subject}\n"
        f"Detected at: {timestamp}\n\n"
        "Do not reply to the suspicious message or open its links/attachments. "
        "Review the event in the VAPP dashboard."
    )

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=20) as smtp:
            smtp.ehlo()
            smtp.starttls(context=context)
            smtp.ehlo()
            smtp.login(gmail_address, app_password)
            smtp.send_message(message)
        return True
    except Exception:
        # Never log credentials or message contents.
        app.logger.exception("VAPP Gmail alert delivery failed for event #%s.", event_id)
        return False


def process_incoming_email(data, user_id):
    """
    Analyze an incoming email with the dedicated email analyzer, then save it
    using the existing VAPP event/database schema. The analyzer performs
    offline inspection only; it does not open or fetch URLs.
    """
    sender = str(data.get("sender", "")).strip()
    subject = str(data.get("subject", "")).strip()
    body = str(data.get("body", "")).strip()
    headers = data.get("headers") or {}

    supplied_ip = str(data.get("source_ip", "")).strip()
    remote_ip = str(data.get("remote_ip", "GMAIL-MONITORED")).strip() or "GMAIL-MONITORED"
    # Gmail monitoring uses a source marker, not a claimed originating IP.
    source_ip = remote_ip if not supplied_ip or supplied_ip.upper() == "AUTO" else supplied_ip

    if not sender or not subject or not body:
        return {"success": False, "message": "Sender, subject and body are required."}, 400

    # This is the dedicated email analyzer. It receives the selected Gmail
    # headers so SPF/DKIM/DMARC results can be reported when present.
    analysis = analyze_email(sender, subject, body, headers=headers)
    url_intelligence_results = inspect_urls(analysis.get("urls", []))

    # Independently verify authentication using the original RFC822 message.
    # Do not infer the sender's client IP from Gmail's source marker or headers.
    raw_email_bytes = data.get("raw_email_bytes")
    try:
        independent_authentication = verify_email_authentication(raw_email_bytes)
    except Exception as auth_error:
        reason = f"Independent verification unavailable: {type(auth_error).__name__}"
        independent_authentication = {
            "from_domain": None,
            "spf": {"status": "UNKNOWN", "reason": reason},
            "dkim": {"status": "UNKNOWN", "reason": reason},
            "dmarc": {"status": "UNKNOWN", "reason": reason},
        }

    threat_type = analysis.get("threat_type", "Email Needs Review")
    risk_level = analysis.get("risk_level", "LOW")
    risk_score = max(0, min(100, int(analysis.get("risk_score", 0))))
    confidence = max(0, min(100, int(analysis.get("confidence", 0))))
    matched = analysis.get("matched_indicators", [])
    if not isinstance(matched, list):
        matched = [str(matched)]

    event = {
        "source_ip": source_ip,
        "destination_ip": "VAPP-USER",
        "protocol": "EMAIL",
        "port": 0,
        "event_type": "Incoming Email",
        "description": (
            f"Sender: {sender} | Subject: {subject} | "
            f"Message: {body[:500]}"
        ),
        "severity": risk_level,
        "failed_attempts": 0,
        "unique_ports": 1,
        "event_rate": 5 if risk_level in ("HIGH", "CRITICAL") else (2 if risk_level == "MEDIUM" else 1),
        "suspicious_keyword": 1 if matched else 0,
        "unusual_port": 0,
    }

   
    link_findings = analysis.get("link_findings", [])
    attachment_analysis = data.get("attachment_analysis", [])

    if not isinstance(attachment_analysis, list):
        attachment_analysis = []

    auth = analysis.get("header_authentication", {})

    detail_parts = [
        "VAPP analyzed the incoming email using contextual rule-based analysis.",
        f"Risk score: {risk_score}/100 ({risk_level}).",
        "Matched indicators: " + (
            ", ".join(str(x) for x in matched)
            if matched else "none detected"
        ) + ".",
    ]

    if url_intelligence_results:
        unique_url_summaries = []
        seen_url_summaries = set()

        for item in url_intelligence_results:
            hostname = item.get("hostname") or item.get("url") or "Unknown host"
            status = item.get("status", "UNKNOWN")
            findings = item.get("findings", [])
            findings = findings if isinstance(findings, list) else [str(findings)]

            summary_key = (hostname, status, tuple(findings))
            if summary_key in seen_url_summaries:
                continue

            seen_url_summaries.add(summary_key)
            unique_url_summaries.append(
                f"{hostname}: {status} ({', '.join(findings)})"
            )

        detail_parts.append(
            f"Passive URL intelligence: {len(url_intelligence_results)} URL(s) inspected; "
            + "; ".join(unique_url_summaries[:20])
            + (f"; {len(unique_url_summaries) - 20} additional unique result(s) omitted from this summary"
               if len(unique_url_summaries) > 20 else "")
            + "."
        )

    if link_findings:
        detail_parts.append(
            "Link findings: "
            + "; ".join(str(x) for x in link_findings[:10]) + "."
        )

    if attachment_analysis:
        attachment_summaries = []

        for attachment in attachment_analysis[:20]:
            filename = str(
                attachment.get("filename", "(unnamed attachment)")
            )
            mime_type = str(attachment.get("mime_type", "unknown"))
            size_bytes = attachment.get("size_bytes", 0)
            hash_status = str(
                attachment.get("status", "not_processed")
            )
            sha256 = attachment.get("sha256")

            summary = (
                f"{filename} | MIME: {mime_type} | "
                f"Size: {size_bytes} bytes | Hash status: {hash_status}"
            )

            if sha256:
                summary += f" | SHA-256: {sha256}"

            attachment_summaries.append(summary)

        detail_parts.append(
            "Attachment analysis: "
            + "; ".join(attachment_summaries) + "."
        )

    if auth:
        detail_parts.append(
            "Authentication results from available headers: "
            + ", ".join(
                f"{key}={value}" for key, value in auth.items()
            ) + "."
        )

    detail_parts.append("Independent email authentication verification:")
    for mechanism in ("spf", "dkim", "dmarc"):
        result = independent_authentication.get(mechanism, {})
        status = result.get("status", "UNKNOWN")
        reason = result.get("reason", "No verification details available.")
        detail_parts.append(
            f"{mechanism.upper()}: {status} ? {reason}"
        )

    dkim_details = independent_authentication.get("dkim", {})
    for signature in dkim_details.get("signatures", []):
        signature_number = signature.get("signature_index", -1) + 1
        signature_status = signature.get("status", "UNKNOWN")
        signature_domain = signature.get("domain")
        signature_error = signature.get("error")
        signature_reason = signature.get("reason")

        diagnostic = (
            f"DKIM signature {signature_number}: {signature_status}"
        )
        if signature_domain:
            diagnostic += f"; domain={signature_domain}"
        if signature_error:
            diagnostic += f"; error={signature_error}"
        if signature_reason:
            diagnostic += f"; details={signature_reason}"

        detail_parts.append(diagnostic)
    if analysis.get("evidence_limitations"):
        detail_parts.append("Limitations: " + " ".join(str(x) for x in analysis["evidence_limitations"]))
    detail_parts.append(str(analysis.get("explanation", "")))
    explanation = " ".join(part for part in detail_parts if part)

    recommendation = generate_recommendation(threat_type, risk_level)
    if risk_level == "MEDIUM":
        recommendation = (
            "Review the sender and link destinations carefully. Do not enter credentials "
            "or open attachments until the message is verified. This score may include false positives. "
            + str(recommendation)
        )
    elif risk_level in ("HIGH", "CRITICAL"):
        recommendation = (
            "Do not click links or open attachments. Verify the request through a separate trusted channel "
            "and report the message to the security administrator. " + str(recommendation)
        )

    event_id = save_analysis_event(
        user_id, event, threat_type, confidence,
        risk_score, risk_level, explanation, recommendation
    )

    # Email alerts are sent only for analyzer-assigned HIGH/CRITICAL email events.
    alert_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert_email_sent = False
    if risk_level in ("HIGH", "CRITICAL") and not data.get("suppress_smtp_alert"):
        alert_email_sent = send_vapp_email_alert(
            event_id, sender, subject, threat_type, risk_level,
            risk_score, alert_timestamp
        )

    return {
        "success": True,
        "event_id": event_id,
        "sender": sender,
        "subject": subject,
        "source_ip": source_ip,
        "threat_type": threat_type,
        "confidence": confidence,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "alert_email_sent": alert_email_sent,
        "matched_indicators": matched,
        "urls": analysis.get("urls", []),
        "url_intelligence": url_intelligence_results,
        "domains": analysis.get("domains", []),
        "link_findings": link_findings,
        "attachment_analysis": attachment_analysis,
        "header_authentication": auth,
        "independent_authentication": independent_authentication,
        "html_link_count": analysis.get("html_link_count", 0),
        "hidden_link_count": analysis.get("hidden_link_count", 0),
        "link_text_mismatch_count": analysis.get("link_text_mismatch_count", 0),
        "qr_context_detected": analysis.get("qr_context_detected", False),
        "language": analysis.get("language", "unknown"),
        "analysis_method": analysis.get("method", "contextual-rule"),
        "explanation": explanation,
        "recommendation": recommendation,
        "status": "REVIEW / INVESTIGATE" if risk_level == "MEDIUM" else (
            "URGENT INVESTIGATION" if risk_level in ("HIGH", "CRITICAL") else "LOW RISK / MONITOR"
        ),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }, 200


def _gmail_oauth_client_file():
    configured = os.environ.get("VAPP_GOOGLE_CLIENT_SECRET_FILE", "credentials_web.json")
    return configured if os.path.isabs(configured) else os.path.join(os.path.dirname(os.path.abspath(__file__)), configured)


def _gmail_oauth_redirect_uri():
    # Must exactly match the redirect URI registered in Google Cloud Console.
    return os.environ.get("VAPP_GOOGLE_REDIRECT_URI", "http://localhost:5000/auth/google/callback").strip()


def _gmail_oauth_flow(state=None):
    client_file = _gmail_oauth_client_file()
    if not os.path.isfile(client_file):
        raise FileNotFoundError("Google Web OAuth client file was not found. Configure VAPP_GOOGLE_CLIENT_SECRET_FILE.")
    flow = Flow.from_client_secrets_file(client_file, scopes=GMAIL_SCOPES, state=state)
    flow.redirect_uri = _gmail_oauth_redirect_uri()
    return flow


def _same_origin_post():
    origin = request.headers.get("Origin", "")
    if not origin:
        return False
    try:
        parsed_origin = urlsplit(origin)
        parsed_request = urlsplit(request.host_url)
        return (
            parsed_origin.scheme.lower() == parsed_request.scheme.lower()
            and parsed_origin.netloc.lower() == parsed_request.netloc.lower()
            and parsed_origin.path == ""
            and not parsed_origin.query
            and not parsed_origin.fragment
        )
    except ValueError:
        return False


@app.route("/auth/google/connect")
def gmail_oauth_connect():
    if not login_required():
        return redirect(url_for("login"))
    try:
        state = secrets.token_urlsafe(32)
        session["gmail_oauth_state"] = state
        flow = _gmail_oauth_flow(state=state)
        authorization_url, returned_state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent",
        )
        session["gmail_oauth_code_verifier"] = flow.code_verifier
        if not hmac.compare_digest(state, returned_state):
            session.pop("gmail_oauth_state", None)
            return "OAuth state validation failed.", 400
        return redirect(authorization_url)
    except Exception:
        app.logger.exception("Could not start Gmail OAuth for the current user.")
        flash("Gmail connection could not be started. Check the Web OAuth configuration.")
        return redirect(url_for("dashboard"))


@app.route("/auth/google/callback")
def gmail_oauth_callback():
    if not login_required():
        return redirect(url_for("login"))
    expected_state = session.pop("gmail_oauth_state", None)
    supplied_state = request.args.get("state", "")
    if not expected_state or not supplied_state or not hmac.compare_digest(expected_state, supplied_state):
        app.logger.warning(
            "Gmail OAuth callback rejected: state validation failed (expected_present=%s, supplied_present=%s).",
            bool(expected_state), bool(supplied_state)
        )
        flash("Google sign-in could not be verified. Please connect Gmail again.")
        return redirect(url_for("dashboard"))
    if request.args.get("error"):
        app.logger.warning("Gmail OAuth callback received a Google authorization error.")
        flash("Google Gmail authorization was cancelled or denied.")
        return redirect(url_for("dashboard"))
    try:
        flow = _gmail_oauth_flow(state=supplied_state)
        code_verifier = session.pop("gmail_oauth_code_verifier", None)
        if not code_verifier:
            raise RuntimeError("OAuth PKCE code verifier is missing from the session.")
        flow.code_verifier = code_verifier
        flow.fetch_token(code=request.args.get("code", ""))
        credentials = flow.credentials
        if not credentials or not credentials.valid or not credentials.has_scopes(GMAIL_SCOPES):
            raise RuntimeError("Google authorization did not grant the required Gmail permission.")
        service = build("gmail", "v1", credentials=credentials, cache_discovery=False)
        profile = service.users().getProfile(userId="me").execute()
        gmail_email = (profile.get("emailAddress") or "").strip().lower()
        if not gmail_email or "@" not in gmail_email:
            raise RuntimeError("Google did not return a valid Gmail account address.")
        user_id = int(session["user_id"])
        stop_gmail_monitor(user_id)
        save_user_credentials(user_id, credentials, gmail_email)
        app.logger.info("Gmail OAuth credentials saved successfully for VAPP user_id=%s.", user_id)
        flash("Gmail connected successfully: " + gmail_email)
    except Exception:
        app.logger.exception("Gmail OAuth callback failed for the current VAPP user.")
        flash("Gmail could not be connected. Check the OAuth configuration and encryption key, then try again.")
    return redirect(url_for("dashboard"))


@app.route("/api/gmail-status")
def gmail_status():
    if not login_required():
        return jsonify({"success": False, "message": "Login required."}), 401
    try:
        status = get_user_gmail_status(session["user_id"])
        return jsonify({"success": True, **status})
    except Exception:
        app.logger.exception("Could not read Gmail status for current user.")
        return jsonify({"success": False, "message": "Gmail status is temporarily unavailable."}), 500


@app.route("/api/gmail/start", methods=["POST"])
def gmail_monitor_start_route():
    if not login_required():
        return jsonify({"success": False, "message": "Login required."}), 401
    if not _same_origin_post():
        return jsonify({"success": False, "message": "Request origin could not be verified."}), 403
    try:
        status = get_user_gmail_status(session["user_id"])
        if not status["connected"]:
            return jsonify({"success": False, "message": "Connect a Gmail account first."}), 400
        result = start_gmail_monitor(process_incoming_email, session["user_id"])
        return jsonify({"success": True, **result, "message": "Gmail monitoring start requested."})
    except Exception:
        app.logger.exception("Could not start Gmail monitoring for current user.")
        return jsonify({"success": False, "message": "Gmail monitoring could not be started."}), 500


@app.route("/api/gmail/stop", methods=["POST"])
def gmail_monitor_stop_route():
    if not login_required():
        return jsonify({"success": False, "message": "Login required."}), 401
    if not _same_origin_post():
        return jsonify({"success": False, "message": "Request origin could not be verified."}), 403
    result = stop_gmail_monitor(session["user_id"])
    return jsonify({"success": True, **result, "message": "Gmail monitoring stop requested."})


@app.route("/api/gmail/disconnect", methods=["POST"])
def gmail_disconnect_route():
    if not login_required():
        return jsonify({"success": False, "message": "Login required."}), 401
    if not _same_origin_post():
        return jsonify({"success": False, "message": "Request origin could not be verified."}), 403
    user_id = int(session["user_id"])
    stop_gmail_monitor(user_id)
    try:
        delete_user_credentials(user_id)
        return jsonify({"success": True, "message": "Gmail credentials removed from VAPP. You can also revoke access in your Google Account security settings."})
    except Exception:
        app.logger.exception("Could not disconnect Gmail for current user.")
        return jsonify({"success": False, "message": "Gmail could not be disconnected."}), 500


@app.route("/api/email-event", methods=["POST"])
def email_event():
    if not login_required():
        return jsonify({"success": False, "message": "Login required."}), 401

    data = request.get_json(silent=True) or {}
    data["remote_ip"] = request.remote_addr or "UNKNOWN"
    result, status = process_incoming_email(data, session["user_id"])
    return jsonify(result), status


@app.route("/sender")
def sender_page():
    return render_template("sender.html")


@app.route("/api/incoming-email", methods=["POST"])
def incoming_email():
    if not login_required():
        return jsonify({
            "success": False,
            "message": "Login required."
        }), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "message": "A JSON object is required."
        }), 400

    data["remote_ip"] = request.remote_addr or "UNKNOWN"

    result, status = process_incoming_email(
        data,
        session["user_id"]
    )

    return jsonify(result), status

@app.route("/api/sms-import", methods=["POST"])
def sms_import():
    """Import a CSV of SMS messages, analyze them, and save each event."""
    if not login_required():
        return jsonify({"success": False, "message": "Please log in first."}), 401

    uploaded_file = request.files.get("file")
    if not uploaded_file or not uploaded_file.filename:
        return jsonify({"success": False, "message": "Please select a CSV file."}), 400
    if not uploaded_file.filename.lower().endswith(".csv"):
        return jsonify({"success": False, "message": "Please upload a .csv file."}), 400

    # Keep uploads bounded so a very large file cannot stall the demo server.
    max_bytes = 1_000_000
    raw = uploaded_file.stream.read(max_bytes + 1)
    if len(raw) > max_bytes:
        return jsonify({"success": False, "message": "CSV must be smaller than 1 MB."}), 413
    if not raw.strip():
        return jsonify({"success": False, "message": "The CSV file is empty."}), 400

    try:
        decoded = raw.decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(decoded, newline=""))
        if not reader.fieldnames:
            return jsonify({"success": False, "message": "CSV must include a header row."}), 400

        columns = {name.strip().lower(): name for name in reader.fieldnames if name}
        message_column = next(
            (columns[key] for key in ("message", "body", "text", "sms") if key in columns),
            None,
        )
        sender_column = next(
            (columns[key] for key in ("sender", "from", "phone", "number") if key in columns),
            None,
        )
        if not message_column:
            return jsonify({
                "success": False,
                "message": "CSV needs a message column named message, body, text, or sms.",
            }), 400

        results = []
        skipped = 0
        max_rows = 500
        for row_number, row in enumerate(reader, start=2):
            if len(results) + skipped >= max_rows:
                return jsonify({
                    "success": False,
                    "message": f"CSV contains more than {max_rows} rows. Please split it into smaller files.",
                }), 400

            message = str(row.get(message_column) or "").strip()
            sender = str(row.get(sender_column) or "Unknown SMS sender").strip() if sender_column else "Unknown SMS sender"
            if not message:
                skipped += 1
                continue

            analysis = analyze_sms(sender, message)
            risk_level = analysis.get("risk_level", "LOW")
            threat_type = analysis.get("threat_type", "Needs Review")
            event = {
                "source_ip": sender[:100],
                "destination_ip": "VAPP-USER",
                "protocol": "SMS",
                "port": 0,
                "event_type": "Incoming SMS",
                "description": f"Sender: {sender[:100]} | Message: {message[:1000]}",
                "severity": risk_level,
                "failed_attempts": 0,
                "unique_ports": 1,
                "event_rate": 1,
                "suspicious_keyword": int(bool(analysis.get("matched_indicators"))),
                "unusual_port": 0,
            }
            event_id = save_analysis_event(
                session["user_id"], event, threat_type,
                analysis.get("confidence", 0), analysis.get("risk_score", 0),
                risk_level, analysis.get("explanation", "SMS analyzed."),
                analysis.get("recommendation", "Review the message carefully."),
            )
            results.append({
                "event_id": event_id,
                "sender": sender,
                "message": message,
                "threat_type": threat_type,
                "risk_level": risk_level,
                "risk_score": analysis.get("risk_score", 0),
                "confidence": analysis.get("confidence", 0),
                "matched_indicators": analysis.get("matched_indicators", []),
                "explanation": analysis.get("explanation", ""),
                "recommendation": analysis.get("recommendation", ""),
            })

    except (UnicodeDecodeError, csv.Error) as exc:
        return jsonify({"success": False, "message": f"Could not read CSV: {exc}"}), 400
    except Exception:
        app.logger.exception("SMS CSV import failed")
        return jsonify({"success": False, "message": "SMS import failed. Check the server log."}), 500

    return jsonify({
        "success": True,
        "processed": len(results),
        "skipped": skipped,
        "results": results,
        "message": f"Analyzed and saved {len(results)} SMS message(s).",
    })


@app.route("/api/device-pairing/csrf", methods=["GET"])
def device_pairing_csrf():
    if not login_required():
        return jsonify({"success": False, "message": "Login required."}), 401

    if "device_pairing_csrf" not in session:
        session["device_pairing_csrf"] = secrets.token_urlsafe(32)

    return jsonify({
        "success": True,
        "csrf_token": session["device_pairing_csrf"]
    })


@app.route("/api/devices/pair", methods=["POST"])
def pair_android_device():
    if not login_required():
        return jsonify({"success": False, "message": "Login required."}), 401

    expected_csrf = session.get("device_pairing_csrf", "")
    supplied_csrf = request.headers.get("X-CSRF-Token", "")

    if (
        not expected_csrf
        or not supplied_csrf
        or not hmac.compare_digest(expected_csrf, supplied_csrf)
    ):
        return jsonify({"success": False, "message": "Invalid CSRF token."}), 403

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "message": "JSON object required."}), 400

    device_name = str(data.get("device_name", "")).strip()

    if not device_name or len(device_name) > 80:
        return jsonify({
            "success": False,
            "message": "Device name must contain 1â€“80 characters."
        }), 400

    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    connection = get_connection()
    try:
        cursor = connection.execute("""
            INSERT INTO user_devices
            (user_id, device_name, token_hash)
            VALUES (?, ?, ?)
        """, (
            session["user_id"],
            device_name,
            token_hash
        ))
        device_id = cursor.lastrowid
        connection.commit()
    except Exception:
        connection.rollback()
        app.logger.exception("Android device pairing failed.")
        return jsonify({
            "success": False,
            "message": "Device pairing failed."
        }), 500
    finally:
        connection.close()

    # Return the raw token once. Only its SHA-256 hash is stored.
    return jsonify({
        "success": True,
        "device_id": device_id,
        "device_name": device_name,
        "device_token": raw_token,
        "message": "Device paired. Save this token securely; it cannot be retrieved again."
    }), 201



@app.route("/api/mobile/device/status", methods=["GET"])
def mobile_device_status():
    """Verify that an Android device token belongs to an active paired device."""
    auth_header = request.headers.get("Authorization", "")
    supplied_token = (
        auth_header[7:].strip()
        if auth_header.startswith("Bearer ")
        else ""
    )

    if not supplied_token or len(supplied_token) > 512:
        return jsonify({
            "success": False,
            "message": "Unauthorized device."
        }), 401

    token_hash = hashlib.sha256(
        supplied_token.encode("utf-8")
    ).hexdigest()

    connection = get_connection()
    try:
        device = connection.execute("""
            SELECT id
            FROM user_devices
            WHERE token_hash = ? AND is_active = 1
        """, (token_hash,)).fetchone()

        if device is None:
            return jsonify({
                "success": False,
                "message": "Unauthorized or inactive device."
            }), 401

        return jsonify({
            "success": True,
            "message": "Device connected successfully.",
            "device_id": device["id"]
        }), 200
    finally:
        connection.close()

@app.route("/api/mobile/sms", methods=["POST"])
def mobile_sms_ingest():
    """Receive an opted-in SMS from an individually paired Android device."""

    auth_header = request.headers.get("Authorization", "")
    supplied_token = (
        auth_header[7:].strip()
        if auth_header.startswith("Bearer ")
        else ""
    )

    if not supplied_token or len(supplied_token) > 512:
        return jsonify({
            "success": False,
            "message": "Unauthorized device."
        }), 401

    token_hash = hashlib.sha256(
        supplied_token.encode("utf-8")
    ).hexdigest()

    connection = get_connection()
    try:
        device = connection.execute("""
            SELECT id, user_id
            FROM user_devices
            WHERE token_hash = ? AND is_active = 1
        """, (token_hash,)).fetchone()

        if device is None:
            return jsonify({
                "success": False,
                "message": "Unauthorized or inactive device."
            }), 401

        # Account ownership comes exclusively from the paired device record.
        owner_user_id = device["user_id"]
        device_id = device["id"]

        connection.execute("""
            UPDATE user_devices
            SET last_seen = CURRENT_TIMESTAMP
            WHERE id = ? AND user_id = ?
        """, (device_id, owner_user_id))

        connection.commit()

    finally:
        connection.close()

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "message": "A JSON object is required."
        }), 400

    sender = str(
        data.get("sender", "Unknown SMS sender")
    ).strip()[:100]

    message = str(data.get("message", "")).strip()

    if not message:
        return jsonify({
            "success": False,
            "message": "SMS message is required."
        }), 400

    if len(message) > 4000:
        return jsonify({
            "success": False,
            "message": "SMS message exceeds the 4000-character limit."
        }), 413

    try:
        analysis = analyze_sms(sender, message)

        risk_level = analysis.get("risk_level", "LOW")
        threat_type = analysis.get("threat_type", "SMS Needs Review")

        event = {
            "source_ip": sender or "Unknown SMS sender",
            "destination_ip": "VAPP-USER",
            "protocol": "SMS",
            "port": 0,
            "event_type": "Incoming SMS (Android)",
            "description": f"Sender: {sender} | Message: {message[:1000]}",
            "severity": risk_level,
            "failed_attempts": 0,
            "unique_ports": 1,
            "event_rate": 1,
            "suspicious_keyword": int(
                bool(analysis.get("matched_indicators"))
            ),
            "unusual_port": 0,
        }

        event_id = save_analysis_event(
            owner_user_id,
            event,
            threat_type,
            analysis.get("confidence", 0),
            analysis.get("risk_score", 0),
            risk_level,
            analysis.get("explanation", "SMS analyzed."),
            analysis.get("recommendation", "Review the message carefully."),
        )

    except Exception:
        app.logger.exception("Android SMS analysis failed.")
        return jsonify({
            "success": False,
            "message": "SMS analysis failed on the VAPP server."
        }), 500

    return jsonify({
        "success": True,
        "event_id": event_id,
        "device_id": device_id,
        "threat_type": threat_type,
        "risk_level": risk_level,
        "risk_score": analysis.get("risk_score", 0),
        "confidence": analysis.get("confidence", 0),
        "message": "SMS analyzed and saved to the paired user's dashboard."
    }), 200


@app.route("/api/mobile/sms/metadata", methods=["POST"])
def mobile_sms_metadata_ingest():
    """Store privacy-preserving SMS threat metadata from a paired device."""

    # 1. Validate the paired-device token.
    auth_header = request.headers.get("Authorization", "")
    supplied_token = (
        auth_header[7:].strip()
        if auth_header.startswith("Bearer ")
        else ""
    )

    if not supplied_token or len(supplied_token) > 512:
        return jsonify({"success": False, "message": "Unauthorized device."}), 401

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "message": "A JSON object is required."}), 400

    # 2. Validate the Android event UUID.
    local_event_id = str(data.get("local_event_id", "")).strip()

    if not re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
        local_event_id
    ):
        return jsonify({"success": False, "message": "Invalid event ID."}), 400

    # 3. Validate risk score and map Android levels to backend levels.
    score = data.get("risk_score")
    if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
        return jsonify({"success": False, "message": "Invalid risk score."}), 400

    level = str(data.get("risk_level", "")).strip().upper()
    level_map = {
        "LOW RISK": "LOW",
        "SUSPICIOUS": "MEDIUM",
        "HIGH RISK": "HIGH",
    }

    if level not in level_map:
        return jsonify({"success": False, "message": "Invalid risk level."}), 400

    # Reject inconsistent score/level combinations.
    expected_level = (
        "HIGH" if score >= 60
        else "MEDIUM" if score >= 30
        else "LOW"
    )
    if level_map[level] != expected_level:
        return jsonify({"success": False, "message": "Risk score and level do not match."}), 400

    # 4. Validate metadata lists.
    reasons = data.get("reasons")
    domains = data.get("detected_urls")
    sender_type = str(data.get("sender_type", "")).strip()

    if (
        not isinstance(reasons, list)
        or len(reasons) > 20
        or not all(isinstance(x, str) and 0 < len(x.strip()) <= 200 for x in reasons)
    ):
        return jsonify({"success": False, "message": "Invalid reasons list."}), 400

    if (
        not isinstance(domains, list)
        or len(domains) > 20
        or not all(isinstance(x, str) and 0 < len(x.strip()) <= 253 for x in domains)
    ):
        return jsonify({"success": False, "message": "Invalid detected domains."}), 400

    allowed_sender_types = {
        "Mobile number",
        "Alphanumeric sender",
        "Unknown sender format",
    }
    if sender_type not in allowed_sender_types:
        return jsonify({"success": False, "message": "Invalid sender type."}), 400

    # Android timestamps are milliseconds since Unix epoch.
    timestamp_ms = data.get("timestamp")
    if (
        isinstance(timestamp_ms, bool)
        or not isinstance(timestamp_ms, int)
        or timestamp_ms < 946684800000
        or timestamp_ms > int(datetime.now().timestamp() * 1000) + 300000
    ):
        return jsonify({"success": False, "message": "Invalid event timestamp."}), 400

    safe_reasons = [x.strip() for x in reasons]
    safe_domains = [x.strip() for x in domains]

    # Do not accept full URLs or message content as domain metadata.
    for domain in safe_domains:
        if domain == "Unparsed link":
            continue
        if (
            "://" in domain
            or "/" in domain
            or "?" in domain
            or "#" in domain
            or "@" in domain
            or any(ch.isspace() for ch in domain)
        ):
            return jsonify({"success": False, "message": "Only domain indicators are accepted."}), 400

    event_time = datetime.fromtimestamp(timestamp_ms / 1000).strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    backend_level = level_map[level]
    explanation = "; ".join(safe_reasons) or "No configured suspicious indicators detected."
    domain_text = ", ".join(safe_domains) if safe_domains else "None"
    description = (
        f"Android SMS threat metadata | "
        f"Risk score: {score} | "
        f"Sender type: {sender_type} | "
        f"Domains: {domain_text} | "
        f"Reasons: {explanation}"
    )[:2000]

    threat_type = (
        "High-Risk SMS"
        if backend_level == "HIGH"
        else "Suspicious SMS"
        if backend_level == "MEDIUM"
        else "SMS - No Configured Threat Indicators"
    )

    recommendation = (
        "Do not interact with the message. Verify the sender through an official channel."
        if backend_level in ("HIGH", "MEDIUM")
        else "No configured suspicious indicators detected. Continue exercising caution."
    )

    token_hash = hashlib.sha256(
        supplied_token.encode("utf-8")
    ).hexdigest()

    connection = get_connection()

    try:
        # Serialize writes so simultaneous retries cannot create duplicates.
        connection.execute("BEGIN IMMEDIATE")

        device = connection.execute("""
            SELECT id, user_id
            FROM user_devices
            WHERE token_hash = ? AND is_active = 1
        """, (token_hash,)).fetchone()

        if device is None:
            connection.rollback()
            return jsonify({
                "success": False,
                "message": "Unauthorized or inactive device."
            }), 401

        device_id = device["id"]
        owner_user_id = device["user_id"]

        existing = connection.execute("""
            SELECT security_event_id
            FROM sms_sync_events
            WHERE device_id = ? AND local_event_id = ?
        """, (device_id, local_event_id)).fetchone()

        connection.execute("""
            UPDATE user_devices
            SET last_seen = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (device_id,))

        # An acknowledged retry returns the original dashboard event.
        if existing is not None:
            connection.commit()
            return jsonify({
                "success": True,
                "duplicate": True,
                "event_id": existing["security_event_id"],
                "local_event_id": local_event_id,
                "message": "Event was already synchronized."
            }), 200

        # 5. Insert the dashboard event.
        cursor = connection.execute("""
            INSERT INTO security_events
            (user_id, timestamp, source_ip, destination_ip, protocol,
             port, event_type, description, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            owner_user_id,
            event_time,
            "Android device",
            "VAPP-USER",
            "SMS",
            0,
            "Incoming SMS (Android metadata)",
            description,
            backend_level,
        ))

        event_id = cursor.lastrowid

        # 6. Insert its analysis result.
        connection.execute("""
            INSERT INTO analysis_results
            (event_id, threat_type, confidence, risk_score, risk_level,
             explanation, recommendation)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            event_id,
            threat_type,
            score / 100.0,
            score,
            backend_level,
            explanation,
            recommendation,
        ))

        # 7. Record the UUID mapping in the same transaction.
        connection.execute("""
            INSERT INTO sms_sync_events
            (device_id, local_event_id, security_event_id)
            VALUES (?, ?, ?)
        """, (device_id, local_event_id, event_id))

        connection.commit()

        return jsonify({
            "success": True,
            "duplicate": False,
            "event_id": event_id,
            "local_event_id": local_event_id,
            "message": "SMS threat metadata synchronized successfully."
        }), 201

    except Exception:
        connection.rollback()
        app.logger.exception("Android SMS metadata synchronization failed.")
        return jsonify({
            "success": False,
            "message": "SMS metadata synchronization failed."
        }), 500

    finally:
        connection.close()

@app.route("/api/events")
def api_events():
    if not login_required():
        return jsonify({"success": False, "message": "Login required."}), 401

    events = get_user_events(session["user_id"])
    return jsonify({"success": True, "events": events})


@app.route("/api/all-events")
def all_events():
    if not login_required():
        return jsonify({"success": False, "message": "Login required."}), 401

    return jsonify({
        "success": True,
        "events": get_user_events(session["user_id"])
    })


@app.route("/report/forensic/<int:event_id>")
def forensic_pdf_report(event_id):
    if not login_required():
        return jsonify({"success": False, "message": "Login required."}), 401

    connection = get_connection()
    try:
        event = connection.execute("""
            SELECT
                se.id, se.user_id, se.timestamp, se.source_ip,
                se.destination_ip, se.protocol, se.port,
                se.event_type, se.description, se.severity,
                ar.threat_type, ar.confidence, ar.risk_score,
                ar.risk_level, ar.explanation, ar.recommendation,
                ar.analysed_at, u.name AS user_name, u.email AS user_email
            FROM security_events se
            LEFT JOIN analysis_results ar
                ON ar.id = (
                    SELECT ar2.id
                    FROM analysis_results ar2
                    WHERE ar2.event_id = se.id
                    ORDER BY ar2.analysed_at DESC, ar2.id DESC
                    LIMIT 1
                )
            LEFT JOIN users u ON u.id = se.user_id
            WHERE se.id = ? AND se.user_id = ?
        """, (event_id, session["user_id"])).fetchone()
    finally:
        connection.close()

    if event is None:
        return jsonify({
            "success": False,
            "message": "Event not found or access denied."
        }), 404

    event = dict(event)

    def display(value):
        if value is None or str(value).strip() == "":
            return "Not recorded"
        return str(value)

    def safe_paragraph(value):
        text = escape(display(value)).replace("\r\n", "\n").replace("\r", "\n")
        return text.replace("\n", "<br/>")

    description = display(event.get("description"))
    urls = re.findall(r'https?://[^\s<>"\']+', description, flags=re.IGNORECASE)
    observed_urls = []
    observed_domains = []

    for url in urls:
        url = url.rstrip(".,;:!?)]")
        if url and url not in observed_urls:
            observed_urls.append(url)
            try:
                hostname = urlsplit(url).hostname
            except ValueError:
                hostname = None
            if hostname and hostname not in observed_domains:
                observed_domains.append(hostname)

    buffer = io.BytesIO()
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitleVAPP",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=19,
        leading=24,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#12304A"),
        spaceAfter=6
    ))
    styles.add(ParagraphStyle(
        name="ReportSubtitleVAPP",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#526578"),
        spaceAfter=16
    ))
    styles.add(ParagraphStyle(
        name="ReportSectionVAPP",
        parent=styles["Heading2"],
        fontSize=12,
        leading=15,
        textColor=colors.HexColor("#087E8B"),
        spaceBefore=12,
        spaceAfter=6
    ))
    styles.add(ParagraphStyle(
        name="ReportCellVAPP",
        parent=styles["BodyText"],
        fontSize=8.5,
        leading=11,
        wordWrap="CJK"
    ))

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=17 * mm,
        bottomMargin=17 * mm,
        title="VAPP Forensic Event Report",
        author="VAPP Automated Analysis"
    )

    story = [
        Paragraph("VAPP FORENSIC EVENT REPORT", styles["ReportTitleVAPP"]),
        Paragraph(
            "Automated security-event triage | Report reference: VAPP-FOR-%s"
            % event_id,
            styles["ReportSubtitleVAPP"]
        ),
        Paragraph("1. Report Information", styles["ReportSectionVAPP"])
    ]

    report_info = [
        ["Report reference", "VAPP-FOR-%s" % event_id],
        ["Generated at (UTC)", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")],
        ["Event ID", display(event.get("id"))],
        ["Event timestamp", display(event.get("timestamp"))],
        ["Associated account", display(event.get("user_email"))],
        ["Analysis timestamp", display(event.get("analysed_at"))]
    ]

    def add_table(rows, widths):
        formatted_rows = []
        for row in rows:
            formatted_rows.append([
                Paragraph(safe_paragraph(cell), styles["ReportCellVAPP"])
                for cell in row
            ])
        table = Table(formatted_rows, colWidths=widths, repeatRows=0, hAlign="LEFT")
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EAF2F8")),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#172B3A")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#C9D5DF")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6)
        ]))
        story.append(table)

    add_table(report_info, [48 * mm, 120 * mm])

    story.append(Paragraph("2. Event and Network Evidence", styles["ReportSectionVAPP"]))
    evidence = [
        ["Field", "Recorded value"],
        ["Event type", display(event.get("event_type"))],
        ["Severity", display(event.get("severity"))],
        ["Source IP", display(event.get("source_ip"))],
        ["Destination IP", display(event.get("destination_ip"))],
        ["Protocol", display(event.get("protocol"))],
        ["Port", display(event.get("port"))],
        ["URL(s) in stored description", "\n".join(observed_urls) if observed_urls else "Not recorded"],
        ["Domain(s) in stored description", "\n".join(observed_domains) if observed_domains else "Not recorded"],
        ["Stored event description", description]
    ]
    add_table(evidence, [48 * mm, 120 * mm])

    story.append(Paragraph("3. Threat Analysis", styles["ReportSectionVAPP"]))
    analysis = [
        ["Field", "Recorded value"],
        ["Threat classification", display(event.get("threat_type"))],
        ["Risk level", display(event.get("risk_level"))],
        ["Risk score", display(event.get("risk_score"))],
        ["Confidence", f"{float(event.get('confidence')) * 100:g}%" if event.get("confidence") is not None and str(event.get("confidence")).strip() != "" else "Not recorded"],
        ["Analysis explanation", display(event.get("explanation"))],
        ["Recommended action", display(event.get("recommendation"))]
    ]
    add_table(analysis, [48 * mm, 120 * mm])

    story.append(Paragraph("4. Findings and Limitations", styles["ReportSectionVAPP"]))
    story.append(Paragraph(
        "This report summarizes the selected event and the analysis fields stored in "
        "the VAPP database at generation time. URLs and domains are listed only when "
        "a URL is explicitly present in the stored event description. They have not "
        "been independently visited or verified by this report.",
        styles["BodyText"]
    ))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "A field marked 'Not recorded' was not available in the retrieved event or "
        "analysis record. Missing information must not be interpreted as evidence "
        "that an indicator is safe or absent.",
        styles["BodyText"]
    ))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "This is an automatically generated triage report, not a definitive attribution "
        "or a substitute for analyst validation. Preserve the original logs and other "
        "evidence, and verify findings before taking consequential action.",
        styles["BodyText"]
    ))

    def draw_footer(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#C9D5DF"))
        canvas.line(18 * mm, 13 * mm, A4[0] - 18 * mm, 13 * mm)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#526578"))
        canvas.drawString(18 * mm, 8 * mm, "VAPP | Confidential security event report")
        canvas.drawRightString(A4[0] - 18 * mm, 8 * mm, "Page %d" % doc.page)
        canvas.restoreState()

    document.build(story, onFirstPage=draw_footer, onLaterPages=draw_footer)
    buffer.seek(0)

    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="VAPP_Forensic_Event_%s.pdf" % event_id
    )


@app.route("/api/report.csv")
def report_csv():
    if not login_required():
        return jsonify({"success": False, "message": "Login required."}), 401

    channel = str(request.args.get("channel", "all")).strip().lower()
    if channel not in ("all", "email", "sms"):
        return jsonify({"success": False, "message": "Channel must be all, email, or sms."}), 400

    events = get_user_events(session["user_id"])

    def event_channel(event):
        protocol = str(event.get("protocol") or "").strip().upper()
        event_type = str(event.get("event_type") or "").strip().lower()
        if protocol == "EMAIL" or "email" in event_type:
            return "email"
        if protocol == "SMS" or "sms" in event_type:
            return "sms"
        return "other"

    if channel in ("email", "sms"):
        events = [event for event in events if event_channel(event) == channel]

    def safe_csv_cell(value):
        """Neutralize formula-like text before exporting it to spreadsheet CSV."""
        if value is None:
            return ""

        text = str(value)

        # Detect formula markers even when preceded by whitespace/control characters.
        if re.match(r"^[\s\x00-\x1f\ufeff]*[=+\-@]", text):
            return "'" + text

        return text

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Timestamp", "Channel", "Source", "Event", "Threat",
        "Confidence", "Risk Score", "Risk Level", "Description"
    ])

    for e in events:
        writer.writerow([
            e["id"],
            safe_csv_cell(e["timestamp"]),
            safe_csv_cell(event_channel(e).upper()),
            safe_csv_cell(e["source_ip"]),
            safe_csv_cell(e["event_type"]),
            safe_csv_cell(e["threat_type"]),
            e["confidence"],
            e["risk_score"],
            safe_csv_cell(e["risk_level"]),
            safe_csv_cell(e["description"])
        ])

    filename = f"VAPP_{channel.capitalize()}_Communications_Report.csv" if channel != "all" else "VAPP_All_Communications_Report.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )



@app.route("/qr-scanner")
def qr_scanner_page():
    if not login_required():
        return redirect(url_for("login"))
    return render_template("qr_scanner.html")


@app.route("/api/qr-scan", methods=["POST"])
def qr_scan():
    if not login_required():
        return jsonify({"success": False, "message": "Please log in."}), 401

    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        return jsonify({"success": False, "message": "Choose a QR image."}), 400

    raw = uploaded.stream.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        return jsonify({"success": False, "message": "Image must be 2 MB or smaller."}), 413

    import numpy as np
    import cv2

    image_array = np.frombuffer(raw, dtype=np.uint8)
    image = cv2.imdecode(image_array, cv2.IMREAD_COLOR)
    if image is None:
        return jsonify({"success": False, "message": "File is not a supported image."}), 400

    detector = cv2.QRCodeDetector()
    payload, points, _ = detector.detectAndDecode(image)
    if points is None or not payload:
        return jsonify({
            "success": False,
            "message": "No readable QR code found. Try a clearer image with a white border."
        }), 422

    urls = re.findall(r'(?i)\b(?:https?://|www\.)[^\s<>"\']+', payload)
    domains = []
    for item in urls:
        candidate = item if item.lower().startswith(("http://", "https://")) else "https://" + item
        try:
            host = urlsplit(candidate).hostname
            if host:
                domains.append(host.lower().rstrip("."))
        except ValueError:
            pass

    unique_urls = list(dict.fromkeys(urls))
    url_intelligence_results = inspect_urls(unique_urls)

    threat_analysis = analyze_qr_payload(payload)
    return jsonify({
        "success": True,
        "payload": payload,
        "urls": unique_urls,
        "domains": list(dict.fromkeys(domains)),
        "url_intelligence": url_intelligence_results,
        "threat_analysis": threat_analysis,
        "message": "QR payload extracted and URLs passively inspected. DNS and structural findings are evidence, not a safety verdict. No links were opened."
    })


@app.route("/admin")
def admin_dashboard():
    if not login_required():
        return redirect(url_for("login"))

    events = get_user_events(session["user_id"])
    stats = dashboard_stats(events)

    return render_template(
        "admin.html",
        user_name=session["user_name"],
        events=events,
        stats=stats
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)




