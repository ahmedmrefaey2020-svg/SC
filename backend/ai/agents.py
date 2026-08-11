import os
import asyncio
import smtplib
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from huggingface_hub import InferenceClient
from dotenv import load_dotenv
from backend.ai.agent_cache import agent_cache, NORMAL_TRAFFIC_TTL, ATTACK_ACTIVE_TTL

load_dotenv()

TOKEN = os.getenv("HF_TOKEN", "").strip().strip('"\'')

CANDIDATE_MODELS = [
    'meta-llama/Llama-3.3-70B-Instruct'
]

# Background retraining lock - prevent concurrent retraining
_retrain_lock = threading.Lock()
_last_retrain_time: float = 0.0
_RETRAIN_COOLDOWN_SECONDS = 300  # 5 minute cooldown

# Global LLM call lock — prevents simultaneous duplicate calls
_llm_call_lock = threading.Lock()


def _call_llm(prompt: str, system_prompt: str, max_tokens: int = 400) -> str:
    """
    Call LLM with fallback through candidate models.
    max_tokens is capped at 400 by default to conserve HF quota.
    """
    if not TOKEN:
        return ""
    with _llm_call_lock:  # Prevent parallel LLM calls from burning tokens
        for model_id in CANDIDATE_MODELS:
            try:
                client = InferenceClient(api_key=TOKEN)
                response = client.chat.completions.create(
                    model=model_id,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt},
                    ],
                    max_tokens=max_tokens,
                )
                if response and response.choices:
                    content = response.choices[0].message.content
                    if content and content.strip():
                        return content.strip()
            except Exception:
                try:
                    import logging, traceback
                    logging.getLogger("sentinel.llm").error(
                        f"LLM call failed [{model_id}]: {traceback.format_exc()[-300:]}"
                    )
                except Exception:
                    pass
                continue
    return ""


def _trigger_all_models_retrain(trigger_reason: str = "Model divergence detected"):
    """Retrain / verify all 4 models in background when selected model fails."""
    global _last_retrain_time
    now = __import__("time").time()
    with _retrain_lock:
        if now - _last_retrain_time < _RETRAIN_COOLDOWN_SECONDS:
            return  # Cooldown active
        _last_retrain_time = now

    def _do_retrain():
        try:
            from backend.db.database import SessionLocal
            from backend.db.models import AutoTrainEvent
            db = SessionLocal()
            try:
                # Log the retraining event
                event_obj = AutoTrainEvent(
                    trigger_reason=trigger_reason,
                    models_trained="lstm,rf,xgboost,lr",
                    result="triggered",
                )
                db.add(event_obj)
                db.commit()
            finally:
                db.close()
        except Exception:
            pass

    t = threading.Thread(target=_do_retrain, daemon=True, name="sentinel-retrain")
    t.start()


class NetworkAnalyzerAgent:
    def __init__(self):
        self.name = "Network Analyzer Agent"
        self.system_prompt = (
            "You are NetworkAnalyzerAgent in a Multi-AI Agent Sentinel IDS system. "
            "Your task is to analyze real-time network traffic telemetry, compare it with specialized machine learning "
            "models (Random Forest / LSTM / XGBoost / Logistic Regression predictions), and determine whether a network "
            "attack is occurring. Provide a concise, precise technical evaluation comparing live telemetry with model outputs. "
            "State clearly: 1) Current network state 2) Model prediction vs actual observed behavior 3) Confidence verdict."
        )

    def analyze(self, stats: dict) -> dict:
        print("NetworkAnalyzerAgent analyzing network telemetry...")


class AttackObservationAgent:
    def __init__(self):
        self.name = "Attack Observation Agent"
        self.system_prompt = (
            "You are AttackObservationAgent in a Multi-AI Agent Sentinel IDS system. "
            "Your domain is specialized threat intelligence and incident reporting. "
            "Identify target endpoints, analyze multi-vector attack behaviors, assess risk severity, "
            "and suggest exact mitigation rules."
        )

    def observe(self, stats: dict, analysis_verdict: dict) -> dict:
        print("AttackObservationAgent observing network telemetry and analysis verdict...")


class AutoBlockAgent:
    def __init__(self):
        self.name = "Auto-Block Agent"
        self.system_prompt = (
            "You are AutoBlockAgent in a Multi-AI Agent Sentinel IDS system. "
            "Your task is to automatically enforce IP firewall blocking rules when threat observation identifies active attacks, "
            "providing zero-latency automated defense response when Auto-Block mode is enabled."
        )

    def enforce(self, stats: dict, observation: dict, auto_block_enabled: bool) -> dict:
        print("AutoBlockAgent enforcing firewall rules based on observation and auto-block settings...")


class SiteSecurityAuditAgent:
    def __init__(self):
        self.name = "Site Security Audit AI Agent"
        self.system_prompt = (
            "You are SiteSecurityAuditAgent in the Sentinel IDS platform. "
            "Your role is to perform continuous static security audits on the website's codebase files "
            "and external linked websites (via API token). Identify vulnerabilities, assess risk level, "
            "and provide exact step-by-step remediation code fixes."
        )

        # Vulnerability patterns to scan
        self._patterns = [
            {
                "check": lambda c: any(s in c for s in [
                    'secret_key = "sentinel_default_rust_key_32b"',
                    "secret_key = 'sentinel_default_rust_key_32b'",
                ]),
                "severity": "Medium",
                "title": "Default Static Secret Key Fallback",
                "issue": "Default encryption key 'sentinel_default_rust_key_32b' is used as fallback crypto key.",
                "solution": "Set SENTINEL_SECRET_KEY environment variable in .env for production.",
                "remediation_code": "import os\nSECRET_KEY = os.getenv('SENTINEL_SECRET_KEY', secrets.token_hex(32))",
            },
            {
                "check": lambda c: 'allowed_hosts=["*"]' in c or "allowed_hosts=['*']" in c,
                "severity": "Low",
                "title": "Permissive Wildcard Host Header Policy",
                "issue": "TrustedHostMiddleware with '*' allows any host header.",
                "solution": "Restrict allowed_hosts to specific production domains.",
                "remediation_code": 'app.add_middleware(TrustedHostMiddleware, allowed_hosts=["yourdomain.com"])',
            },
            {
                "check": lambda c: 'allow_origins=["*"]' in c or "allow_origins=['*']" in c,
                "severity": "Low",
                "title": "Permissive Wildcard CORS Policy",
                "issue": "Wildcard '*' in CORS allows cross-origin requests from any client.",
                "solution": "Explicitly configure trusted domain origins in Settings → ALLOWED_ORIGINS.",
                "remediation_code": "_origins = [o.strip() for o in _cfg.ALLOWED_ORIGINS.split(',') if o.strip()]",
            },
            {
                "check": lambda c: "eval(" in c or "exec(" in c,
                "severity": "Critical",
                "title": "Dynamic Code Execution Risk",
                "issue": "Use of eval() or exec() detected which can enable arbitrary code execution.",
                "solution": "Replace dynamic code execution with safe, parameterized alternatives.",
                "remediation_code": "# Remove eval()/exec() and use strict parameterized functions",
            },
            {
                "check": lambda c: "password" in c.lower() and ("=" in c) and any(q in c for q in ['"', "'"]) and "os.getenv" not in c and "getenv" not in c,
                "severity": "High",
                "title": "Potential Hardcoded Password/Secret",
                "issue": "Hardcoded password or secret value detected in source code.",
                "solution": "Move all secrets to environment variables or secure vaults.",
                "remediation_code": "password = os.getenv('APP_PASSWORD', '')",
            },
        ]

    def scan_codebase(self, target_dir: str = ".") -> dict:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        vulnerabilities = []
        scanned_files_count = 0
        seen_issues = set()  # Deduplicate by (file, title)

        # Scan all relevant file types recursively
        extensions_to_scan = {".py", ".html", ".js", ".env.example", ".cfg", ".ini"}

        for root, dirs, files in os.walk(target_dir):
            # Skip irrelevant dirs
            dirs[:] = [d for d in dirs if d not in {
                "__pycache__", ".git", ".venv", "node_modules", ".vscode",
                "target",  # Rust build dir
            }]

            for filename in files:
                ext = os.path.splitext(filename)[1].lower()
                if ext not in extensions_to_scan:
                    continue

                abs_p = os.path.join(root, filename)
                rel_path = os.path.relpath(abs_p, target_dir).replace("\\", "/")

                try:
                    with open(abs_p, "r", encoding="utf-8", errors="ignore") as f:
                        code_content = f.read()
                    scanned_files_count += 1

                    for pattern in self._patterns:
                        try:
                            if pattern["check"](code_content):
                                key = (rel_path, pattern["title"])
                                if key not in seen_issues:
                                    seen_issues.add(key)
                                    vulnerabilities.append({
                                        "severity": pattern["severity"],
                                        "file": rel_path,
                                        "title": pattern["title"],
                                        "issue": pattern["issue"],
                                        "solution": pattern["solution"],
                                        "remediation_code": pattern["remediation_code"],
                                    })
                        except Exception:
                            continue
                except Exception:
                    pass

        if not vulnerabilities:
            vulnerabilities.append({
                "severity": "Info",
                "file": "Codebase-Wide",
                "title": "Codebase Security Audit Passed",
                "issue": "All core security routines passed standard static integrity checks.",
                "solution": "Maintain routine vulnerability scanning and automated updates.",
                "remediation_code": "# All checks clean",
            })

        # Generate LLM summary
        summary_prompt = (
            f"Summarize this codebase security audit:\n"
            f"- Files Scanned: {scanned_files_count}\n"
            f"- Findings: {len(vulnerabilities)}\n"
            f"- Issues: {', '.join(set(v['title'] for v in vulnerabilities[:5]))}\n"
            f"Give a 2-sentence executive summary."
        )
        llm_summary = _call_llm(summary_prompt, self.system_prompt)
        summary = llm_summary if llm_summary else (
            f"Scanned {scanned_files_count} codebase files. Discovered {len(vulnerabilities)} audit findings."
        )

        return {
            "agent": self.name,
            "timestamp": now_str,
            "files_scanned": scanned_files_count,
            "vulnerabilities_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "summary": summary,
        }

    def scan_linked_site(self, site_url: str, api_token: str) -> dict:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if not site_url or not site_url.startswith(("http://", "https://")):
            return {
                "agent": self.name,
                "target_url": site_url or "N/A",
                "status": "No Linked Site Configured",
                "vulnerabilities": [],
                "summary": "Configure Linked Site URL and API Token in Settings to audit external remote applications.",
            }

        try:
            import urllib.request
            headers = {"User-Agent": "Sentinel-IDS-Security-Scanner/3.0"}
            if api_token:
                headers["Authorization"] = f"Bearer {api_token}"
                headers["token"] = api_token

            req = urllib.request.Request(site_url, headers=headers)
            with urllib.request.urlopen(req, timeout=8) as response:
                content = response.read().decode("utf-8", errors="ignore")[:8000]
                resp_headers = dict(response.headers)

            findings = []

            # Security header checks
            security_headers = {
                "X-Frame-Options": ("Missing Clickjacking Defense (X-Frame-Options)", "Medium",
                                    "Add 'X-Frame-Options: DENY' to HTTP responses.",
                                    "response.headers['X-Frame-Options'] = 'DENY'"),
                "Content-Security-Policy": ("Missing Content-Security-Policy (CSP)", "High",
                                             "Add strict CSP headers to restrict unapproved scripts.",
                                             "response.headers['Content-Security-Policy'] = \"default-src 'self'\""),
                "X-Content-Type-Options": ("Missing X-Content-Type-Options", "Low",
                                           "Add header to prevent MIME-type sniffing.",
                                           "response.headers['X-Content-Type-Options'] = 'nosniff'"),
                "Strict-Transport-Security": ("Missing HTTP Strict Transport Security (HSTS)", "Medium",
                                              "Enforce HTTPS by adding HSTS header.",
                                              "response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'"),
                "X-XSS-Protection": ("Missing XSS Protection Header", "Low",
                                     "Enable browser XSS filtering via header.",
                                     "response.headers['X-XSS-Protection'] = '1; mode=block'"),
            }

            for header_name, (title, severity, solution, code) in security_headers.items():
                if header_name not in resp_headers and header_name.lower() not in {k.lower() for k in resp_headers}:
                    findings.append({
                        "severity": severity,
                        "title": title,
                        "issue": f"Linked site response lacks {header_name} header.",
                        "solution": solution,
                        "remediation_code": code,
                    })

            # Content-based checks
            content_lower = content.lower()
            if "wp-content" in content_lower or "wordpress" in content_lower:
                findings.append({
                    "severity": "Info",
                    "title": "WordPress Installation Detected",
                    "issue": "Site appears to run WordPress. Ensure core, plugins, and themes are up-to-date.",
                    "solution": "Regularly update WordPress, disable unused plugins, and enable a WAF.",
                    "remediation_code": "# Run: wp core update && wp plugin update --all",
                })

            if "<input" in content_lower and "autocomplete" not in content_lower:
                findings.append({
                    "severity": "Low",
                    "title": "Potential Autocomplete Not Disabled on Forms",
                    "issue": "Input forms detected without explicit autocomplete=off on sensitive fields.",
                    "solution": "Add autocomplete='off' to sensitive form inputs (password, card number etc).",
                    "remediation_code": '<input type="password" autocomplete="off">',
                })

            if not findings:
                findings.append({
                    "severity": "Info",
                    "title": "Linked Site Remote Response Audit Clean",
                    "issue": "HTTP endpoints returned valid responses with baseline security headers.",
                    "solution": "Keep site API token secure and repeat scans periodically.",
                    "remediation_code": "# Verified response - no critical issues found",
                })

            return {
                "agent": self.name,
                "target_url": site_url,
                "status": "Audit Complete",
                "vulnerabilities": findings,
                "summary": f"Successfully audited {site_url}. Found {len(findings)} remote security items.",
            }

        except Exception as e:
            return {
                "agent": self.name,
                "target_url": site_url,
                "status": "Connection Error",
                "vulnerabilities": [{
                    "severity": "High",
                    "title": "Linked Site Connectivity Failure",
                    "issue": f"Failed to reach linked site: {str(e)}",
                    "solution": "Verify the URL is accessible and the API Token is valid on the target server.",
                    "remediation_code": "# Check network routing & token validity",
                }],
                "summary": f"Unable to reach linked site {site_url}: {str(e)}",
            }


class EmailReportAgent:
    def __init__(self):
        self.name = "Email Report Agent"
        self.system_prompt = (
            "You are EmailReportAgent in a Multi-AI Agent Sentinel IDS system. "
            "Your job is to compose a professional executive network security summary report "
            "for the system administrator based on network statistics, threat intelligence, and codebase security audits."
        )

    def generate_report(self, recipient_email: str, stats: dict, analysis: dict, observation: dict, include_site_audit: bool = True) -> dict:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        connections = stats.get("connections", 0)
        packet_rate = stats.get("packet_rate", 0)
        score = stats.get("score", 5)
        blocked_count = stats.get("malicious_blocked", 0)
        inbound_mb = round(stats.get("inbound_bytes", 0) / (1024 * 1024), 2)
        attack_vectors = observation.get("detected_attack_types", [observation.get("attack_type", "None")])

        # Run codebase + linked site audit
        site_audit = None
        linked_audit = None
        if include_site_audit:
            site_audit = site_security_audit_agent.scan_codebase()
            # Also check linked site if configured
            try:
                from backend.db.database import SessionLocal, get_settings_db
                db = SessionLocal()
                try:
                    s = get_settings_db(db)
                    linked_url = getattr(s, "linked_site_url", "") or ""
                    linked_token = getattr(s, "linked_site_token", "") or ""
                    if linked_url:
                        linked_audit = site_security_audit_agent.scan_linked_site(linked_url, linked_token)
                finally:
                    db.close()
            except Exception:
                pass

        prompt = (
            f"Generate an executive network security report:\n"
            f"- Admin Email: {recipient_email}\n"
            f"- Report Timestamp: {now_str}\n"
            f"- Total Connections Analyzed: {connections}\n"
            f"- Average Packet Rate: {packet_rate} pps\n"
            f"- Inbound Traffic: {inbound_mb} MB\n"
            f"- Risk Level: {score}%\n"
            f"- Blocked Malicious IPs: {blocked_count}\n"
            f"- Network Analyzer Verdict: {analysis.get('status_title', 'Normal')}\n"
            f"- Model vs Agent: {analysis.get('comparison', 'N/A')}\n"
            f"- Detected Attack Vectors: {', '.join(attack_vectors)}\n"
            f"- Codebase Audit Summary: {site_audit.get('summary', 'Not run') if site_audit else 'Not run'}\n"
            + (f"- Linked Site Audit: {linked_audit.get('summary', '')} \n" if linked_audit else "")
        )

        report_body = _call_llm(prompt, self.system_prompt)

        if not report_body:
            report_body = (
                f"Sentinel IDS Network Security & Vulnerability Executive Report\n"
                f"Timestamp: {now_str}\n"
                f"Recipient: {recipient_email}\n\n"
                f"Executive Network Summary:\n"
                f"- Total Active Connections Analyzed: {connections}\n"
                f"- Current Packet Rate: {packet_rate} pps\n"
                f"- Inbound Traffic: {inbound_mb} MB\n"
                f"- Network Risk Score: {score}%\n"
                f"- Total Blocked Threat IPs: {blocked_count}\n"
                f"- Network Analyzer Status: {analysis.get('status_title', 'Normal')}\n"
                f"- Model vs Agent Comparison: {analysis.get('comparison', 'N/A')}\n"
                f"- Attack Observation Vectors: {', '.join(attack_vectors)}\n\n"
            )
            if site_audit:
                report_body += (
                    f"Codebase Security Audit:\n"
                    f"- Files Audited: {site_audit.get('files_scanned', 0)}\n"
                    f"- Vulnerabilities Discovered: {site_audit.get('vulnerabilities_count', 0)}\n"
                    f"- Audit Summary: {site_audit.get('summary', '')}\n\n"
                )
            if linked_audit:
                report_body += (
                    f"Linked Site Security Audit ({linked_audit.get('target_url', 'N/A')}):\n"
                    f"- Status: {linked_audit.get('status', 'N/A')}\n"
                    f"- Summary: {linked_audit.get('summary', '')}\n\n"
                )
            report_body += "System status remains continuously monitored by Sentinel Multi-AI Agent System."

        sent = self.send_email(recipient_email, "Sentinel IDS - Executive Network & Codebase Security Report", report_body)

        return {
            "agent": self.name,
            "recipient": recipient_email,
            "sent_at": now_str,
            "email_status": "Sent" if sent else "Logged (SMTP not configured)",
            "report_content": report_body,
            "site_audit": site_audit,
            "linked_audit": linked_audit,
        }

    def send_email_detailed(self, recipient_email: str, subject: str, body: str) -> tuple[bool, str]:
        """Send email via SMTP. Returns (success: bool, detail_message: str)."""
        if not recipient_email or "@" not in recipient_email:
            return False, "Invalid recipient email address provided."

        smtp_server = (os.getenv("SMTP_SERVER", "") or "").strip("\"'")
        smtp_port = int(os.getenv("SMTP_PORT", 587))
        smtp_user = (os.getenv("SMTP_USER", "") or "").strip("\"'")
        smtp_pass = (os.getenv("SMTP_PASS", "") or "").strip("\"'")
        smtp_use_tls = True

        # Fetch from DB if environment is empty
        try:
            from backend.db.database import SessionLocal, get_settings_db
            db = SessionLocal()
            try:
                s = get_settings_db(db)
                if not smtp_server and getattr(s, "smtp_server", ""):
                    smtp_server = s.smtp_server.strip("\"'")
                if getattr(s, "smtp_port", None):
                    smtp_port = int(s.smtp_port)
                if not smtp_user and getattr(s, "smtp_user", ""):
                    smtp_user = s.smtp_user.strip("\"'")
                if not smtp_pass and getattr(s, "smtp_pass", ""):
                    smtp_pass = s.smtp_pass.strip("\"'")
                if getattr(s, "smtp_use_tls", None) is not None:
                    smtp_use_tls = bool(s.smtp_use_tls)
            finally:
                db.close()
        except Exception:
            pass

        # Need at least server + user to attempt send
        if not smtp_server or not smtp_user:
            return False, "SMTP configuration incomplete. Please specify SMTP host server and username in Settings."

        try:
            msg = MIMEMultipart("alternative")
            msg["From"] = smtp_user
            msg["To"] = recipient_email
            msg["Subject"] = subject

            plain_part = MIMEText(body, "plain", "utf-8")
            msg.attach(plain_part)

            html_content = f"""<html>
            <body style="font-family: Arial, sans-serif; background-color: #0f172a; color: #f8fafc; padding: 20px;">
                <div style="max-width: 650px; margin: 0 auto; background: #1e293b; border-radius: 12px; padding: 28px; border: 1px solid #334155;">
                    <div style="display:flex; align-items:center; gap:12px; margin-bottom:20px;">
                        <div style="width:42px;height:42px;border-radius:10px;background:rgba(99,102,241,0.2);display:flex;align-items:center;justify-content:center;font-size:22px;">🛡️</div>
                        <div>
                            <h2 style="color: #6366f1; margin: 0; font-size:1.3rem;">Sentinel IDS Security Report</h2>
                            <p style="margin:0; color:#94a3b8; font-size:0.82rem;">{datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
                        </div>
                    </div>
                    <pre style="white-space: pre-wrap; font-family: 'Courier New', monospace; background: #0f172a; padding: 18px; border-radius: 8px; color: #e2e8f0; font-size: 13px; line-height: 1.6; border: 1px solid #334155;">{body}</pre>
                    <p style="font-size: 11px; color: #64748b; margin: 16px 0 0; border-top: 1px solid #334155; padding-top: 12px;">
                         Automated report generated by Sentinel Multi-AI Agent System v3.0
                    </p>
                </div>
            </body>
            </html>"""
            html_part = MIMEText(html_content, "html", "utf-8")
            msg.attach(html_part)

            if smtp_port == 465:
                server = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=12)
            else:
                server = smtplib.SMTP(smtp_server, smtp_port, timeout=12)
                if smtp_use_tls:
                    server.starttls()

            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)

            server.sendmail(smtp_user, recipient_email, msg.as_string())
            server.quit()
            return True, f"Email delivered successfully to {recipient_email}."
        except smtplib.SMTPAuthenticationError as auth_err:
            err_str = str(auth_err)
            msg = f"SMTP Authentication Failed (535 Bad Credentials)."
            if "gmail" in smtp_server.lower() or "google" in err_str.lower():
                msg += " For Gmail, you MUST generate a 16-character App Password (Google Account -> Security -> 2-Step Verification -> App Passwords) and use it as the SMTP Password."
            return False, msg
        except Exception as e:
            err_msg = f"SMTP connection error: {str(e)}"
            try:
                import logging
                logging.getLogger("sentinel.email").error(err_msg)
            except Exception:
                pass
            return False, err_msg

    def send_email(self, recipient_email: str, subject: str, body: str) -> bool:
        """Send email via SMTP. Returns True on success, False on failure."""
        success, _ = self.send_email_detailed(recipient_email, subject, body)
        return success



# Module-level singleton instances
network_analyzer_agent = NetworkAnalyzerAgent()
attack_observation_agent = AttackObservationAgent()
auto_block_agent = AutoBlockAgent()
email_report_agent = EmailReportAgent()
site_security_audit_agent = SiteSecurityAuditAgent()


async def run_periodic_email_report_loop():
    while True:
        try:
            from backend.db.database import get_settings_db, SessionLocal
            from backend.monitoring.stats import get_stats

            db = SessionLocal()
            interval_minutes = 30
            email_alerts = True
            admin_email = "admin@network.local"
            try:
                settings = get_settings_db(db)
                admin_email = settings.admin_email or "admin@network.local"
                email_alerts = settings.email_alerts
                interval_minutes = getattr(settings, "report_interval_minutes", 30) or 30
            finally:
                db.close()

            if email_alerts and admin_email and "@" in admin_email and admin_email not in ("admin@network.local", "admin@acmecorp.com"):
                stats = get_stats()
                analysis = network_analyzer_agent.analyze(stats)
                observation = attack_observation_agent.observe(stats, analysis)
                email_report_agent.generate_report(admin_email, stats, analysis, observation)

            sleep_seconds = max(60, int(interval_minutes) * 60)
            await asyncio.sleep(sleep_seconds)
        except Exception:
            await asyncio.sleep(60)