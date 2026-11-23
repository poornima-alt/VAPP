from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify, Response, send_file
)
from database import get_connection, initialize_database, create_demo_user
from detector import detector
from risk_engine import calculate_risk, generate_explanation, generate_recommendation
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import csv
import io
import hmac
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
from gmail_monitor import start_gmail_monitor
from email_analyzer import analyze_email
from sms_analyzer import analyze_sms

app = Flask(__name__)
app.secret_key = "vapp-review3-secret-key"

initialize_database()
create_demo_user()


def login_required():
    return "user_id" in session


def get_user_events(user_id=None, limit=None):
    connection = get_connection()
    params = []
    where = ""

    if user_id is not None:
        where = "WHERE se.user_id = ?"
        params.append(user_id)

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


def get_demo_user_id():
    connection = get_connection()
    row = connection.execute(
        "SELECT id FROM users WHERE email = ?",
        ("avaishnavi239@gmail.com",)
    ).fetchone()
    connection.close()
    return row["id"] if row else None


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

        if not name or not email or not password:
            flash("All fields are required.")
            return redirect(url_for("signup"))

        connection = get_connection()
        existing = connection.execute(
            "SELECT id FROM users WHERE email = ?", (email,)
        ).fetchone()

        if existing:
            connection.close()
            flash("An account with this email already exists.")
            return redirect(url_for("signup"))

        connection.execute(
            "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
            (name, email, generate_password_hash(password))
        )
        connection.commit()
        connection.close()

        flash("Account created successfully. Please login.")
        return redirect(url_for("login"))

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
    message["Subject"] = f"[VAPP {risk_level}] Email security alert — Event #{event_id}"
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
    if risk_level in ("HIGH", "CRITICAL"):
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
        "domains": analysis.get("domains", []),
        "link_findings": link_findings,
        "attachment_analysis": attachment_analysis,
        "header_authentication": auth,
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


@app.route("/api/gmail-status")
def gmail_status():
    return jsonify({"success": True, "configured": os.path.exists("credentials.json") and os.path.exists("token.json")})


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
    # External sender page intentionally uses the demo user so a reviewer
    # can send an event without logging into the sender device.
    demo_user_id = get_demo_user_id()
    if not demo_user_id:
        return jsonify({"success": False, "message": "Demo user not found."}), 500

    data = request.get_json(silent=True) or {}
    data["remote_ip"] = request.remote_addr or "UNKNOWN"
    result, status = process_incoming_email(data, demo_user_id)
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


@app.route("/api/mobile/sms", methods=["POST"])
def mobile_sms_ingest():
    """Receive an opted-in Android SMS using a shared device token.

    The token is supplied through the VAPP_SMS_DEVICE_TOKEN environment
    variable and is never stored in the source code or printed to logs.
    This endpoint is intended for a trusted private-LAN prototype only.
    """
    configured_token = os.environ.get("VAPP_SMS_DEVICE_TOKEN", "")
    auth_header = request.headers.get("Authorization", "")
    supplied_token = auth_header[7:].strip() if auth_header.startswith("Bearer ") else ""

    if not configured_token:
        return jsonify({"success": False, "message": "Mobile SMS endpoint is not configured on the server."}), 503
    if not supplied_token or not hmac.compare_digest(supplied_token, configured_token):
        return jsonify({"success": False, "message": "Unauthorized device."}), 401

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "message": "A JSON object is required."}), 400

    sender = str(data.get("sender", "Unknown SMS sender")).strip()[:100]
    message = str(data.get("message", "")).strip()
    if not message:
        return jsonify({"success": False, "message": "SMS message is required."}), 400
    if len(message) > 4000:
        return jsonify({"success": False, "message": "SMS message exceeds the 4000-character limit."}), 413

    # Associate the device with the existing VAPP account; never fall back to
    # the demo account or trust an account ID supplied by the phone.
    connection = get_connection()
    try:
        account = connection.execute(
            "SELECT id FROM users WHERE email = ?",
            ("avaishnavi239@gmail.com",)
        ).fetchone()
    finally:
        connection.close()

    if account is None:
        return jsonify({
            "success": False,
            "message": "The configured VAPP account was not found. Sign in to that account on the VAPP website first."
        }), 404

    try:
        analysis = analyze_sms(sender, message)
        risk_level = analysis.get("risk_level", "LOW")
        threat_type = analysis.get("threat_type", "SMS Needs Review")
        event = {
            # This field contains the SMS sender identifier, NOT an IP address.
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
            "suspicious_keyword": int(bool(analysis.get("matched_indicators"))),
            "unusual_port": 0,
        }
        event_id = save_analysis_event(
            account["id"], event, threat_type,
            analysis.get("confidence", 0), analysis.get("risk_score", 0),
            risk_level, analysis.get("explanation", "SMS analyzed."),
            analysis.get("recommendation", "Review the message carefully."),
        )
    except Exception:
        app.logger.exception("Android SMS analysis failed")
        return jsonify({"success": False, "message": "SMS analysis failed on the VAPP server."}), 500

    return jsonify({
        "success": True,
        "event_id": event_id,
        "threat_type": threat_type,
        "risk_level": risk_level,
        "risk_score": analysis.get("risk_score", 0),
        "confidence": analysis.get("confidence", 0),
        "message": "SMS analyzed and saved to the VAPP dashboard."
    }), 200


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
        ["Confidence", display(event.get("confidence")) + "%" if event.get("confidence") is not None and str(event.get("confidence")).strip() != "" else "Not recorded"],
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

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Timestamp", "Channel", "Source", "Event", "Threat",
        "Confidence", "Risk Score", "Risk Level", "Description"
    ])

    for e in events:
        writer.writerow([
            e["id"], e["timestamp"], event_channel(e).upper(), e["source_ip"],
            e["event_type"], e["threat_type"], e["confidence"], e["risk_score"],
            e["risk_level"], e["description"]
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

    return jsonify({
        "success": True,
        "payload": payload,
        "urls": list(dict.fromkeys(urls)),
        "domains": list(dict.fromkeys(domains)),
        "message": "QR payload extracted. Any links remain unverified; this is not a safety verdict."
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
    start_gmail_monitor(process_incoming_email, get_demo_user_id())
    app.run(host="0.0.0.0", port=5000, debug=False)
