import os
from datetime import datetime
import hashlib

import pandas as pd
import requests
import streamlit as st
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from werkzeug.security import generate_password_hash, check_password_hash

from models import db, User, MonitoredEmail, Breach, Organization, OrgEmail, OrgBreach
from brain import fetch_email_breaches as fetch_live_email_breaches, pwned_password_count
from risk_engine import calculate_risk
from pdf_service import generate_breach_report
from scheduler import simulate_breach_check
from alert_service import send_combined_alert


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)
DEFAULT_DB_PATH = os.path.join(INSTANCE_DIR, "darkweb_monitor.db")
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH}")


LANDING_CSS = """
<style>
/* Global dark cyber theme */
[data-testid="stAppViewContainer"], body, .main {
  background: radial-gradient(circle at top, #0b1020 0, #050816 45%, #020309 100%) !important;
  color: #f9fafb;
  font-family: 'JetBrains Mono', 'Fira Code', 'Source Code Pro', monospace;
}

[data-testid="stSidebar"] {
  background: linear-gradient(180deg, #050816 0, #020309 100%) !important;
  border-right: 1px solid rgba(15,23,42,0.9);
}

[data-testid="stHeader"] {
  background: transparent !important;
}

/* Generic cards/containers */
.stTabs [data-baseweb="tab-list"] {
  gap: 1.2rem;
}

.stTabs [data-baseweb="tab"] {
  padding: 0.4rem 0.2rem;
}

/* Form inputs */
input, textarea, select {
  background-color: rgba(15,23,42,0.95) !important;
  color: #e5e7eb !important;
  border-radius: 8px !important;
  border: 1px solid rgba(148,163,184,0.5) !important;
}

input:focus, textarea:focus, select:focus {
  outline: none !important;
  border-color: rgba(56,189,248,0.9) !important;
  box-shadow: 0 0 0 1px rgba(56,189,248,0.6) !important;
}

label {
  color: #e5e7eb !important;
}

h1, h2, h3, h4, h5, h6 {
  color: #e5e7eb !important;
}

/* Ensure all inline text in main content is light (fixes radio labels too) */
.block-container span {
  color: #e5e7eb !important;
}



/* Alerts */
[data-testid="stAlert"] {
  background-color: rgba(15,23,42,0.98) !important;
  border-radius: 10px !important;
  border: 1px solid rgba(248,250,252,0.12) !important;
}

/* Main app buttons (all visible buttons) */
button, .stButton > button {
  border-radius: 999px !important;
  background: linear-gradient(120deg, #06b6d4, #22c55e) !important;
  border: 1px solid rgba(34,197,94,0.9) !important;
  color: #020617 !important;
  font-weight: 600 !important;
  letter-spacing: 0.08em !important;
  text-transform: uppercase !important;
  box-shadow:
    0 0 10px rgba(34,197,94,0.7),
    0 0 20px rgba(8,145,178,0.9);
}

.stButton > button:hover, button:hover {
  filter: brightness(1.12);
}

.stButton > button:disabled {
  background: linear-gradient(120deg, #06b6d4, #22c55e) !important;
  border: 1px solid rgba(34,197,94,0.7) !important;
  color: #ffffff !important;
  opacity: 0.65 !important;
  box-shadow:
    0 0 8px rgba(34,197,94,0.4),
    0 0 14px rgba(8,145,178,0.6) !important;
}

/* Explicit styling for radio button labels (Individual / Enterprise selector) */
.stRadio label {
  color: #ffffff !important;
  opacity: 1 !important;
}

.stRadio div[role="radiogroup"] * {
  color: #ffffff !important;
  opacity: 1 !important;
}

/* Metrics */
[data-testid="stMetricLabel"] {
  color: #9ca3c7 !important;
  text-transform: uppercase;
  letter-spacing: 0.18em;
  font-size: 0.7rem;
}

[data-testid="stMetricValue"] {
  font-size: 1.5rem;
  color: #e5e7eb !important;
}

/* Tables / dataframes */
.stDataFrame, [data-testid="stTable"] {
  background-color: rgba(15,23,42,0.95) !important;
  border-radius: 10px;
  border: 1px solid rgba(30,64,175,0.7);
  box-shadow: 0 0 18px rgba(15,23,42,0.9);
}

/* Progress bar tweaks */
.stProgress > div > div {
  background: linear-gradient(90deg, #22c55e, #eab308, #f97316, #ef4444);
}

/* Top navigation */
.dw-nav {
  position: sticky;
  top: 0;
  z-index: 999;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.6rem 1.2rem;
  background: linear-gradient(90deg, rgba(15,23,42,0.98), rgba(15,23,42,0.9));
  border-bottom: 1px solid rgba(31,41,55,0.9);
  box-shadow: 0 8px 20px rgba(0,0,0,0.7);
}

.dw-nav-left {
  font-size: 0.85rem;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  color: #9ca3c7;
}

.dw-nav-brand {
  color: #00ffcc;
  font-weight: 600;
}

.dw-nav-right {
  display: flex;
  align-items: center;
  gap: 1.4rem;
  font-size: 0.8rem;
}

.dw-nav-link {
  color: #e5e7eb;
  text-decoration: none;
  text-transform: uppercase;
  letter-spacing: 0.18em;
  font-size: 0.7rem;
  position: relative;
}

.dw-nav-link::after {
  content: "";
  position: absolute;
  left: 0;
  bottom: -4px;
  width: 0;
  height: 2px;
  background: linear-gradient(90deg, #06b6d4, #22c55e);
  transition: width 0.18s ease-out;
}

.dw-nav-link:hover::after {
  width: 100%;
}

/* Hero landing layout */
.dw-hero-wrap {
  padding-top: 2.5rem;
  padding-bottom: 1.5rem;
}

.dw-hero-title {
  font-size: 3rem;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  color: #00ffcc;
  text-shadow:
    0 0 12px rgba(0,255,204,0.7),
    0 0 24px rgba(0,255,204,0.5);
}

.dw-hero-subtitle {
  font-size: 1.1rem;
  color: #a5b4fc;
  margin-top: 0.4rem;
}

.dw-hero-tagline {
  font-size: 0.85rem;
  letter-spacing: 0.22em;
  text-transform: uppercase;
  color: #9ca3c7;
  margin-top: 1.2rem;
}

.dw-hero-badge {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.18rem 0.7rem;
  border-radius: 999px;
  border: 1px solid rgba(0,255,204,0.55);
  background: rgba(15,23,42,0.8);
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.16em;
}

.dw-dot-live {
  width: 7px;
  height: 7px;
  border-radius: 999px;
  background: #ff0033;
  box-shadow: 0 0 10px rgba(255,0,51,0.9);
  animation: dw-pulse 1s ease-in-out infinite;
}

.dw-hero-metric-label {
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.18em;
  color: #9ca3c7;
}

.dw-hero-metric-value {
  font-size: 1.4rem;
  font-weight: 600;
}

.dw-glass {
  /* Hero right card wrapper – now transparent so box is not visible */
  background: transparent;
  border-radius: 0;
  border: none;
  box-shadow: none;
  padding: 0;
}

.dw-glass:hover {
  border-color: rgba(0,255,204,0.7);
  box-shadow:
    0 0 18px rgba(0,255,204,0.5),
    0 0 32px rgba(0,255,204,0.35);
  transform: translateY(-1px);
  transition: all 0.18s ease-out;
}

.dw-attack-list li {
  margin-bottom: 0.35rem;
}

.dw-login-heading {
  font-size: 0.9rem;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: #9ca3c7;
  margin-bottom: 0.5rem;
}

@keyframes dw-pulse {
  0% { transform: scale(0.9); opacity: 0.8; }
  50% { transform: scale(1.25); opacity: 1; }
  100% { transform: scale(0.9); opacity: 0.8; }
}
</style>
"""


@st.cache_resource
def get_engine_and_session():
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
    SessionLocal = sessionmaker(bind=engine)
    return engine, SessionLocal


def init_db():
    from flask import Flask

    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)
    with app.app_context():
        db.create_all()


def ensure_default_state():
    if "user_id" not in st.session_state:
        st.session_state.user_id = None
    if "last_manual_scan" not in st.session_state:
        st.session_state.last_manual_scan = None
    if "auto_scan_enabled" not in st.session_state:
        st.session_state.auto_scan_enabled = True
    if "last_auto_scan" not in st.session_state:
        st.session_state.last_auto_scan = None
    if "show_register" not in st.session_state:
        st.session_state.show_register = False
    if "mode" not in st.session_state:
        st.session_state.mode = "Individual"
    if "active_org_id" not in st.session_state:
        st.session_state.active_org_id = None


def enterprise_score_for_email(breaches: list[OrgBreach], email: str) -> tuple[int, str]:
    """
    Enterprise scoring using advanced 5-factor risk engine.
    Returns (score, level)
    """
    if not breaches:
        return 0, "SAFE"
    
    # Convert OrgBreach to Breach for risk engine compatibility
    breach_objects = []
    for b in breaches:
        breach_obj = Breach(
            email=b.email,
            breach_name=b.breach_name,
            breach_date=b.breach_date,
            data_exposed=b.data_exposed,
            severity=b.severity,
        )
        breach_objects.append(breach_obj)
    
    score, level, _ = calculate_risk(breach_objects, email=email)
    return score, level


def check_password_pwned(password: str) -> tuple[bool, int]:
    """
    Check if a password has appeared in known breaches using
    the Have I Been Pwned Pwned Passwords API (k-anonymity).
    - We only send the first 5 chars of the SHA-1 hash.
    - We never store the password or full hash.
    """
    if not password:
        return False, 0

    count = pwned_password_count(password)
    if count is None:
        return False, 0
    return (count > 0), count


def _parse_breach_date(date_str: str | None):
    if not date_str:
        return datetime.utcnow()
    try:
        if len(date_str) == 7 and date_str[4] == "-":
            return datetime.strptime(date_str, "%Y-%m")
        if len(date_str) == 10 and date_str[4] == "-" and date_str[7] == "-":
            return datetime.strptime(date_str, "%Y-%m-%d")
    except Exception:
        return datetime.utcnow()
    return datetime.utcnow()


def _live_breach_dicts_for_email(email: str):
    raw = fetch_live_email_breaches(email)
    if raw is None:
        return None
    results = []
    for b in raw:
        breach_name = b.get("Name", "Unknown")
        breach_date = _parse_breach_date(b.get("BreachDate"))
        data_exposed = ", ".join(b.get("DataClasses", []) or ["Email"])
        severity = "MEDIUM"
        if "password" in data_exposed.lower():
            severity = "HIGH"
        results.append(
            {
                "breach_name": str(breach_name),
                "breach_date": breach_date,
                "data_exposed": str(data_exposed),
                "severity": severity,
            }
        )
    return results


def _should_run_auto_scan() -> bool:
    if not st.session_state.get("auto_scan_enabled", True):
        return False
    last = st.session_state.get("last_auto_scan")
    if last is None:
        return True
    return (datetime.utcnow() - last).total_seconds() >= 300


def _run_auto_scan_individual(db_sess, user: User, monitored_emails: list[MonitoredEmail]):
    if not monitored_emails:
        return
    if not _should_run_auto_scan():
        return

    any_new = False
    with st.spinner("Auto-scanning monitored emails..."):
        for m in monitored_emails:
            live = _live_breach_dicts_for_email(m.email)
            if live is None:
                continue
            for sb in live:
                existing = (
                    db_sess.query(Breach)
                    .filter(
                        Breach.email == m.email,
                        Breach.breach_name == sb["breach_name"],
                    )
                    .first()
                )
                if existing:
                    continue
                db_sess.add(
                    Breach(
                        email=m.email,
                        breach_name=sb["breach_name"],
                        breach_date=sb["breach_date"],
                        data_exposed=sb["data_exposed"],
                        severity=sb["severity"],
                    )
                )
                any_new = True
            m.last_checked = datetime.utcnow()

    if any_new:
        user.has_unseen_breaches = True
    db_sess.commit()
    st.session_state.last_auto_scan = datetime.utcnow()


def _run_auto_scan_enterprise(db_sess, active_org: Organization, employees: list[OrgEmail]):
    if not employees:
        return
    if not _should_run_auto_scan():
        return

    any_new = False
    with st.spinner("Auto-scanning organization emails..."):
        for e in employees:
            live = _live_breach_dicts_for_email(e.email)
            if live is None:
                continue
            for sb in live:
                existing = (
                    db_sess.query(OrgBreach)
                    .filter(
                        OrgBreach.org_id == active_org.id,
                        OrgBreach.email == e.email,
                        OrgBreach.breach_name == sb["breach_name"],
                    )
                    .first()
                )
                if existing:
                    continue
                db_sess.add(
                    OrgBreach(
                        org_id=active_org.id,
                        email=e.email,
                        breach_name=sb["breach_name"],
                        breach_date=sb["breach_date"],
                        data_exposed=sb["data_exposed"],
                        severity=sb["severity"],
                    )
                )
                any_new = True
            e.last_checked = datetime.utcnow()

    if any_new:
        active_org.has_unseen_breaches = True
    db_sess.commit()
    st.session_state.last_auto_scan = datetime.utcnow()


def register_form(SessionLocal):
    st.subheader("Register")
    with st.form("register_form"):
        email = st.text_input("Email", key="reg_email")
        password = st.text_input("Password", type="password", key="reg_password")
        submitted = st.form_submit_button("Create account")
        if submitted:
            email_clean = (email or "").strip().lower()
            password_clean = (password or "").strip()
            if not email_clean or not password_clean:
                st.error("Email and password are required.")
                return
            db_sess = SessionLocal()
            try:
                existing = db_sess.execute(
                    select(User).where(User.email == email_clean)
                ).scalar_one_or_none()
                if existing:
                    st.error("Account already exists for this email.")
                    return
                user = User(
                    email=email_clean,
                    password_hash=generate_password_hash(password_clean),
                )
                db_sess.add(user)
                db_sess.commit()
                st.success("Registration successful. Please log in.")
                st.session_state.show_register = False
                st.session_state.login_email = email_clean
                st.session_state.login_password = ""
                st.rerun()
            finally:
                db_sess.close()


def login_form(SessionLocal):
    st.subheader("Login")
    with st.form("login_form"):
        email = st.text_input("Email", key="login_email")
        password = st.text_input("Password", type="password", key="login_password")
        access_mode = st.radio(
            "Login as",
            ["Individual", "Enterprise"],
            index=0,
            horizontal=True,
            key="login_mode_choice",
        )
        submitted = st.form_submit_button("Login")

    if submitted:
        email_clean = (email or "").strip().lower()
        password_clean = (password or "").strip()
        if not email_clean or not password_clean:
            st.error("Email and password are required.")
            return
        db_sess = SessionLocal()
        try:
            user = db_sess.execute(
                select(User).where(User.email == email_clean)
            ).scalar_one_or_none()
            if not user or not check_password_hash(user.password_hash, password_clean):
                st.error("Invalid email or password.")
                return
            st.session_state.user_id = user.id
            st.session_state.mode = "Individual" if access_mode == "Individual" else "Enterprise"
            st.rerun()
        finally:
            db_sess.close()


def logout_button():
    if st.button("Logout"):
        st.session_state.user_id = None
        st.rerun()


def render_dashboard(SessionLocal):
    db_sess = SessionLocal()
    try:
        user = db_sess.get(User, st.session_state.user_id)
        if not user:
            st.session_state.user_id = None
            st.rerun()
            return

        with st.sidebar:
            st.subheader("Access Mode")
            st.markdown(
                f"**{st.session_state.mode}**",
                unsafe_allow_html=True,
            )
            st.divider()
            st.subheader("Live scanning")
            st.session_state.auto_scan_enabled = st.toggle(
                "Auto-scan monitored emails",
                value=st.session_state.auto_scan_enabled,
            )
            if st.session_state.last_auto_scan:
                st.caption(
                    "Last auto scan: "
                    + st.session_state.last_auto_scan.strftime("%Y-%m-%d %H:%M UTC")
                )
            st.divider()
            st.caption(f"Signed in: {user.email}")
            logout_button()

        if st.session_state.mode == "Enterprise":
            return render_enterprise_dashboard(SessionLocal, user)

        st.title("Dark Web Breach Monitor (Individual)")
        st.caption("Personal monitoring for your own emails.")

        monitored_emails = (
            db_sess.query(MonitoredEmail)
            .filter(MonitoredEmail.user_id == user.id)
            .all()
        )

        _run_auto_scan_individual(db_sess, user, monitored_emails)
        email_list = [m.email for m in monitored_emails] or ["__none__"]

        breaches = (
            db_sess.query(Breach)
            .filter(Breach.email.in_(email_list))
            .order_by(Breach.detected_at.desc())
            .all()
        )

        total_breaches = len(breaches)
        last_checked = None
        if monitored_emails:
            last_checked = max(
                [m.last_checked for m in monitored_emails if m.last_checked] or [None],
                default=None,
            )

        # Get first monitored email for risk calculation
        primary_email = monitored_emails[0].email if monitored_emails else None
        score, risk_level, risk_percentage = calculate_risk(breaches, email=primary_email)

        # Trigger alerts for HIGH (60+) or CRITICAL (85+) risk
        if score >= 60 and primary_email:
            # Prepare breach data for alert
            breaches_data = [
                {
                    'breach_name': b.breach_name,
                    'breach_date': b.breach_date.strftime('%Y-%m-%d'),
                    'data_exposed': b.data_exposed
                }
                for b in breaches[:10]  # Send top 10 breaches
            ]
            
            # Extract clean risk level (remove emoji and extra text)
            clean_risk_level = risk_level.split("—")[0].strip()
            
            # Send combined SMS + Email alert
            try:
                alert_results = send_combined_alert(
                    risk_level=clean_risk_level,
                    score=score,
                    email=primary_email,
                    breach_count=total_breaches,
                    breaches_list=breaches_data
                )
                
                # Show alert status in sidebar
                if alert_results.get('sms_sent') or alert_results.get('email_sent'):
                    with st.sidebar:
                        st.success("🔔 Alert sent!")
                        if alert_results.get('sms_sent'):
                            st.caption("✓ SMS sent")
                        if alert_results.get('email_sent'):
                            st.caption("✓ Email sent to shreyaburra17@gmail.com")
            except Exception as e:
                print(f"Alert service error: {e}")

        # Color coding for risk levels
        risk_colors = {
            "SAFE": "🟢",
            "LOW": "🟢",
            "MEDIUM": "🟡",
            "HIGH": "🟠",
            "CRITICAL": "🔴",
        }
        risk_emoji = risk_colors.get(risk_level.split("—")[0].strip(), "⚪")

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Breaches", total_breaches)
        with col2:
            st.metric("Risk Level", f"{risk_emoji} {risk_level}", delta=f"Score {score}")
        with col3:
            st.write("Risk Meter")
            st.progress(risk_percentage / 100)
        with col4:
            if last_checked:
                st.metric(
                    "Last Scanned",
                    last_checked.strftime("%Y-%m-%d"),
                    last_checked.strftime("%H:%M UTC"),
                )
            else:
                st.metric("Last Scanned", "Never")

        st.markdown("---")

        # Action Triggers based on risk level
        if score >= 85:
            st.error(
                "🚨 **CRITICAL RISK DETECTED** — Immediate action required:\n"
                "- Force password reset for all monitored accounts\n"
                "- Enable account isolation/blocking\n"
                "- Alert security team immediately\n"
                "- Review all recent account activity"
            )
        elif score >= 60:
            st.warning(
                "⚠️ **HIGH RISK** — Urgent action recommended:\n"
                "- Send Slack/email alert to user\n"
                "- Require MFA setup if not enabled\n"
                "- Flag account for security review\n"
                "- Monitor for suspicious activity"
            )
        elif score >= 35:
            st.info(
                "ℹ️ **MEDIUM RISK** — Advisory actions:\n"
                "- Prompt user to enable MFA\n"
                "- Send advisory email about breach\n"
                "- Recommend password change\n"
                "- Monitor account status"
            )
        elif score >= 1:
            st.success(
                "✅ **LOW RISK** — Monitoring only:\n"
                "- Continue regular monitoring\n"
                "- No immediate action required\n"
                "- Account status: Green"
            )

        st.markdown("---")

        left, right = st.columns([1, 2])

        with left:
            st.subheader("Monitored Emails")
            st.image(
                "https://images.pexels.com/photos/5380642/pexels-photo-5380642.jpeg?auto=compress&cs=tinysrgb&w=800",
                caption="Identity monitoring across leaked credential clusters.",
            )
            if monitored_emails:
                for i, m in enumerate(monitored_emails):
                    label = m.email
                    if m.last_checked:
                        label += f" (last: {m.last_checked.strftime('%Y-%m-%d %H:%M')})"
                    col1, col2 = st.columns([4, 1])
                    with col1:
                        st.write("- " + label)
                    with col2:
                        if st.button("🗑️", key=f"delete_email_{m.id}"):
                            db_sess.delete(m)
                            db_sess.commit()
                            st.success(f"Removed {m.email} from monitoring.")
                            st.rerun()
            else:
                st.info("No emails monitored yet.")

            with st.form("add_email_form"):
                new_email = st.text_input("Add email to monitor")
                submitted = st.form_submit_button("Add")
                if submitted:
                    email_clean = (new_email or "").strip().lower()
                    if not email_clean:
                        st.error("Email is required.")
                    else:
                        exists = (
                            db_sess.query(MonitoredEmail)
                            .filter(
                                MonitoredEmail.user_id == user.id,
                                MonitoredEmail.email == email_clean,
                            )
                            .first()
                        )
                        if exists:
                            st.warning("You are already monitoring this email.")
                        else:
                            m = MonitoredEmail(
                                email=email_clean, user_id=user.id, last_checked=None
                            )
                            db_sess.add(m)
                            db_sess.commit()
                            st.success("Email added.")
                            st.rerun()

            st.markdown("---")
            st.subheader("Password Monitor")
            with st.form("password_monitor_form"):
                pwd = st.text_input(
                    "Check if a password has been seen in public breaches",
                    type="password",
                    help="Password is checked securely against the Have I Been Pwned Pwned Passwords API using SHA-1 k-anonymity. It is never stored.",
                )
                submitted_pwd = st.form_submit_button("Check password")
                if submitted_pwd:
                    pwned, count = check_password_pwned(pwd)
                    if pwned:
                        st.error(
                            f"This password has appeared in {count} known breach entries. "
                            "You should NOT use it."
                        )
                    else:
                        st.success("Good news — this password was not found in the breach database snapshot.")

            st.subheader("Email Monitor")
            with st.form("quick_email_check_form"):
                quick_email = st.text_input(
                    "Check if an email was found in breaches",
                    help="This performs an instant lookup using the backend email breach function (LeakCheck).",
                )
                submitted_email = st.form_submit_button("Check email")
                if submitted_email:
                    email_clean = (quick_email or "").strip().lower()
                    if not email_clean:
                        st.error("Email is required.")
                    else:
                        with st.spinner("Checking breaches..."):
                            raw_breaches = fetch_live_email_breaches(email_clean)

                        if raw_breaches is None:
                            st.error("Email check failed (network/API issue). Try again.")
                        elif len(raw_breaches) == 0:
                            st.success("✅ No breaches found for this email.")
                        else:
                            st.warning(f"⚠️ Found in {len(raw_breaches)} breach sources.")
                            preview = raw_breaches[:10]
                            st.dataframe(
                                pd.DataFrame(
                                    [
                                        {
                                            "Breach": b.get("Name", "Unknown"),
                                            "Date": b.get("BreachDate", "Unknown"),
                                            "Source": b.get("Source", "Unknown"),
                                        }
                                        for b in preview
                                    ]
                                ),
                                use_container_width=True,
                                hide_index=True,
                            )

            st.markdown("---")

            if st.button("Download Breach Report (PDF)"):
                buffer = generate_breach_report(user, breaches, risk_level)
                st.download_button(
                    label="Download PDF",
                    data=buffer,
                    file_name=f"breach_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf",
                )

            if st.button("Run Manual Scan Now"):
                for m in monitored_emails:
                    live = _live_breach_dicts_for_email(m.email)
                    breach_dicts = live if live is not None else simulate_breach_check(m.email)
                    for sb in breach_dicts:
                        existing = (
                            db_sess.query(Breach)
                            .filter(
                                Breach.email == m.email,
                                Breach.breach_name == sb["breach_name"],
                            )
                            .first()
                        )
                        if existing:
                            continue
                        new_breach = Breach(
                            email=m.email,
                            breach_name=sb["breach_name"],
                            breach_date=sb["breach_date"],
                            data_exposed=sb["data_exposed"],
                            severity=sb["severity"],
                        )
                        db_sess.add(new_breach)
                    m.last_checked = datetime.utcnow()
                db_sess.commit()
                st.session_state.last_manual_scan = datetime.utcnow()
                st.success("Scan completed. Refreshing data...")
                st.rerun()

        with right:
            st.subheader("Breach History & Analytics")
            if breaches:
                df = pd.DataFrame(
                    [
                        {
                            "Date": b.breach_date.strftime("%Y-%m-%d"),
                            "Email": b.email,
                            "Breach": b.breach_name,
                            "Data Exposed": b.data_exposed,
                            "Severity": b.severity,
                            "Detected At": b.detected_at.strftime(
                                "%Y-%m-%d %H:%M:%S"
                            ),
                        }
                        for b in breaches
                    ]
                )
                st.dataframe(df, use_container_width=True, hide_index=True)

                severity_counts = df["Severity"].value_counts().reset_index()
                severity_counts.columns = ["Severity", "Count"]
                st.bar_chart(
                    severity_counts.set_index("Severity"),
                    use_container_width=True,
                )
            else:
                st.info("No breach data yet.")

        if user.has_unseen_breaches:
            st.warning(
                "New dark web breach detected for your monitored accounts. "
                "Review the breach history for details.",
                icon="⚠️",
            )
            user.has_unseen_breaches = False
            db_sess.commit()
    finally:
        db_sess.close()


def render_enterprise_dashboard(SessionLocal, user: User):
    db_sess = SessionLocal()
    try:
        st.title("Dark Web Breach Monitor (Enterprise)")
        st.caption("Monitor many employee emails and compute one combined organization risk score.")

        orgs = (
            db_sess.query(Organization)
            .filter(Organization.admin_user_id == user.id)
            .order_by(Organization.created_at.desc())
            .all()
        )

        with st.expander("Create organization", expanded=(len(orgs) == 0)):
            with st.form("create_org_form"):
                org_name = st.text_input("Organization name", placeholder="DemoCorp")
                submitted = st.form_submit_button("Create")
                if submitted:
                    name_clean = (org_name or "").strip()
                    if not name_clean:
                        st.error("Organization name is required.")
                    else:
                        org = Organization(name=name_clean, admin_user_id=user.id)
                        db_sess.add(org)
                        db_sess.commit()
                        st.success("Organization created.")
                        st.session_state.active_org_id = org.id
                        st.rerun()

        if not orgs:
            st.info("Create an organization to start monitoring employee emails.")
            return

        org_options = {f"{o.name} (id={o.id})": o.id for o in orgs}
        default_label = next(iter(org_options.keys()))
        selected_label = st.selectbox("Organization", list(org_options.keys()), index=0)
        st.session_state.active_org_id = org_options.get(selected_label)

        active_org = db_sess.get(Organization, st.session_state.active_org_id)
        if not active_org:
            st.session_state.active_org_id = None
            st.rerun()
            return

        employees = (
            db_sess.query(OrgEmail)
            .filter(OrgEmail.org_id == active_org.id)
            .order_by(OrgEmail.email.asc())
            .all()
        )

        _run_auto_scan_enterprise(db_sess, active_org, employees)
        employee_emails = [e.email for e in employees] or ["__none__"]

        org_breaches = (
            db_sess.query(OrgBreach)
            .filter(OrgBreach.org_id == active_org.id, OrgBreach.email.in_(employee_emails))
            .order_by(OrgBreach.detected_at.desc())
            .all()
        )

        per_email_scores = {}
        per_email_levels = {}
        for e in employees:
            b_list = [b for b in org_breaches if b.email == e.email]
            score, level = enterprise_score_for_email(b_list, e.email)
            per_email_scores[e.email] = score
            per_email_levels[e.email] = level

        monitored_count = len(employees)
        exposed_count = sum(1 for e in employees if per_email_scores.get(e.email, 0) > 0)
        high_risk_count = sum(1 for e in employees if per_email_scores.get(e.email, 0) >= 85)

        org_score = 0
        if monitored_count > 0:
            org_score = int(round(sum(per_email_scores.values()) / monitored_count))
        
        # Map org score to level using same thresholds
        if org_score >= 85:
            org_level = "CRITICAL"
        elif org_score >= 60:
            org_level = "HIGH"
        elif org_score >= 35:
            org_level = "MEDIUM"
        elif org_score >= 1:
            org_level = "LOW"
        else:
            org_level = "SAFE"

        # Trigger alerts for HIGH (60+) or CRITICAL (85+) organization risk
        if org_score >= 60 and employees:
            # Find highest risk employee email for alert context
            highest_risk_email = max(per_email_scores.items(), key=lambda x: x[1])[0] if per_email_scores else None
            
            if highest_risk_email:
                # Prepare breach data for alert
                employee_breaches = [b for b in org_breaches if b.email == highest_risk_email]
                breaches_data = [
                    {
                        'breach_name': b.breach_name,
                        'breach_date': b.breach_date.strftime('%Y-%m-%d'),
                        'data_exposed': b.data_exposed
                    }
                    for b in employee_breaches[:10]  # Send top 10 breaches
                ]
                
                # Send combined SMS + Email alert
                try:
                    alert_results = send_combined_alert(
                        risk_level=org_level,
                        score=org_score,
                        email=f"{active_org.name} (highest risk: {highest_risk_email})",
                        breach_count=len(org_breaches),
                        breaches_list=breaches_data
                    )
                    
                    # Show alert status in sidebar
                    if alert_results.get('sms_sent') or alert_results.get('email_sent'):
                        with st.sidebar:
                            st.success("🔔 Enterprise Alert sent!")
                            if alert_results.get('sms_sent'):
                                st.caption("✓ SMS sent")
                            if alert_results.get('email_sent'):
                                st.caption("✓ Email sent to shreyaburra18@gmail.com")
                except Exception as e:
                    print(f"Alert service error: {e}")

        # Color coding
        risk_colors = {
            "SAFE": "🟢",
            "LOW": "🟢",
            "MEDIUM": "🟡",
            "HIGH": "🟠",
            "CRITICAL": "🔴",
        }
        org_emoji = risk_colors.get(org_level, "⚪")

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Employees Monitored", monitored_count)
        with col2:
            st.metric("Employees Exposed", exposed_count)
        with col3:
            st.metric("High Risk Accounts", high_risk_count)
        with col4:
            st.metric("Organization Risk Score", f"{org_emoji} {org_score}/100", delta=org_level)

        st.markdown("---")

        left, right = st.columns([1, 2])
        with left:
            st.subheader("Employee Emails")
            if employees:
                for e in employees:
                    score = per_email_scores.get(e.email, 0)
                    lvl = per_email_levels.get(e.email, "SAFE")
                    emoji = risk_colors.get(lvl, "⚪")
                    col1, col2 = st.columns([4, 1])
                    with col1:
                        st.write(f"- {emoji} {e.email} — {score}/100 ({lvl})")
                    with col2:
                        if st.button("🗑️", key=f"delete_employee_{e.id}"):
                            db_sess.delete(e)
                            db_sess.commit()
                            st.success(f"Removed {e.email} from organization.")
                            st.rerun()
            else:
                st.info("No employee emails yet.")

            if active_org:
                with st.form("add_employee_email_form"):
                    new_email = st.text_input("Add employee email", placeholder="admin@democorp.com")
                    submitted = st.form_submit_button("Add")
                    if submitted:
                        email_clean = (new_email or "").strip().lower()
                        if not email_clean:
                            st.error("Email is required.")
                        else:
                            exists = (
                                db_sess.query(OrgEmail)
                                .filter(OrgEmail.org_id == active_org.id, OrgEmail.email == email_clean)
                                .first()
                            )
                            if exists:
                                st.warning("This email is already in the organization list.")
                            else:
                                db_sess.add(OrgEmail(org_id=active_org.id, email=email_clean))
                                db_sess.commit()
                                st.success("Employee email added.")
                                st.rerun()
            else:
                st.error("Organization not selected or invalid. Please select an organization.")

            if st.button("Run Enterprise Scan Now"):
                new_breach_found = False
                for e in employees:
                    live = _live_breach_dicts_for_email(e.email)
                    breach_dicts = live if live is not None else simulate_breach_check(e.email)
                    for sb in breach_dicts:
                        existing = (
                            db_sess.query(OrgBreach)
                            .filter(
                                OrgBreach.org_id == active_org.id,
                                OrgBreach.email == e.email,
                                OrgBreach.breach_name == sb["breach_name"],
                            )
                            .first()
                        )
                        if existing:
                            continue
                        db_sess.add(
                            OrgBreach(
                                org_id=active_org.id,
                                email=e.email,
                                breach_name=sb["breach_name"],
                                breach_date=sb["breach_date"],
                                data_exposed=sb["data_exposed"],
                                severity=sb["severity"],
                            )
                        )
                        new_breach_found = True
                    e.last_checked = datetime.utcnow()

                if new_breach_found:
                    active_org.has_unseen_breaches = True

                db_sess.commit()
                st.success("Enterprise scan completed.")
                st.rerun()

            # Debug: Force live scan and show results
            with st.expander("Debug: Force live breach check (no persistence)"):
                if st.button("Check first employee email now"):
                    if employees:
                        test_email = employees[0].email
                        with st.spinner(f"Checking {test_email} via backend..."):
                            result = fetch_live_email_breaches(test_email)
                        if result is None:
                            st.error("Backend returned None (network/API error)")
                        elif len(result) == 0:
                            st.success("No breaches found for this email via backend.")
                        else:
                            st.warning(f"Found {len(result)} breach entries via backend.")
                            st.json(result[:5])  # Show first 5 entries
                    else:
                        st.info("No employee emails to test.")

        with right:
            st.subheader("Organization Breach History")
            st.image(
                "https://images.pexels.com/photos/5380648/pexels-photo-5380648.jpeg?auto=compress&cs=tinysrgb&w=800",
                caption="Attack surface mapping across employee identities and access layers.",
            )
            if org_breaches:
                df = pd.DataFrame(
                    [
                        {
                            "Date": b.breach_date.strftime("%Y-%m-%d"),
                            "Email": b.email,
                            "Breach": b.breach_name,
                            "Data Exposed": b.data_exposed,
                            "Severity": b.severity,
                            "Detected At": b.detected_at.strftime("%Y-%m-%d %H:%M:%S"),
                        }
                        for b in org_breaches
                    ]
                )
                st.dataframe(df, use_container_width=True, hide_index=True)

                # breaches per email chart
                counts = df["Email"].value_counts().reset_index()
                counts.columns = ["Email", "Breaches"]
                st.bar_chart(counts.set_index("Email"), use_container_width=True)
            else:
                st.info("No enterprise breach data yet.")

        if active_org.has_unseen_breaches:
            st.warning(
                "Enterprise alert: new employee breaches detected. Review the breach history table.",
                icon="⚠️",
            )
            active_org.has_unseen_breaches = False
            db_sess.commit()
    finally:
        db_sess.close()


def main():
    st.set_page_config(
        page_title="Dark Web Breach Monitor",
        page_icon="🛡️",
        layout="wide",
    )
    st.markdown(LANDING_CSS, unsafe_allow_html=True)

    init_db()
    ensure_default_state()
    _, SessionLocal = get_engine_and_session()

    if st.session_state.user_id is None:
        # Top navigation bar
        st.markdown(
            """
            <div class="dw-nav">
              <div class="dw-nav-left">
                <span class="dw-nav-brand">DARK WEB MONITOR</span>&nbsp;|&nbsp; Breach Intelligence
              </div>
              <div class="dw-nav-right">
                <a href="#home" class="dw-nav-link">Home</a>
                <a href="#about" class="dw-nav-link">About</a>
                <a href="#login" class="dw-nav-link">Login</a>
                <a href="#faq" class="dw-nav-link">FAQ</a>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Cyber landing hero (stacked vertically)
        hero = st.container()
        with hero:
            st.markdown('<div id="home" class="dw-hero-wrap">', unsafe_allow_html=True)

            # Title + tagline
            st.markdown(
                """
                <div class="dw-hero-title">DARK WEB MONITOR</div>
                <div class="dw-hero-subtitle">
                  Real-Time Dark Web Breach Intelligence Console
                </div>
                <div class="dw-hero-tagline">
                  DARK WEB • STEALER LOGS • CREDENTIAL DUMPS • LEAKED CORP DATA
                </div>
                <div style="margin-top:1rem;">
                  <span class="dw-hero-badge">
                    <span class="dw-dot-live"></span>
                    LIVE DARK WEB MONITORING
                  </span>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Metrics row
            m1, m2, m3 = st.columns(3)
            with m1:
                st.markdown('<div class="dw-hero-metric-label">LEAKED IDENTITIES (SIM)</div>', unsafe_allow_html=True)
                st.markdown('<div class="dw-hero-metric-value">12,431</div>', unsafe_allow_html=True)
            with m2:
                st.markdown('<div class="dw-hero-metric-label">ACTIVE FEEDS</div>', unsafe_allow_html=True)
                st.markdown('<div class="dw-hero-metric-value">27</div>', unsafe_allow_html=True)
            with m3:
                st.markdown('<div class="dw-hero-metric-label">CRITICAL CLUSTERS</div>', unsafe_allow_html=True)
                st.markdown('<div class="dw-hero-metric-value">9</div>', unsafe_allow_html=True)

            # Description block
            st.markdown(
                """
                <div style="margin-top:1.4rem;font-size:0.9rem;color:#d1d5db;">
                  This console continuously:
                  <ul style="margin-top:0.35rem;">
                    <li>Watches dark web forums, stealer logs and credential dumps for your identities.</li>
                    <li>Maps exposed emails and passwords into individual and enterprise risk scores.</li>
                    <li>Maintains a historical breach ledger so you can prove what was leaked and when.</li>
                    <li>Surfaces tactical recommendations so teams can reset, rotate and lock down access fast.</li>
                  </ul>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Full-width hero image + attack bullets
            st.markdown('<div id="about" class="dw-glass">', unsafe_allow_html=True)
            st.image(
                "https://media.istockphoto.com/id/1144604245/photo/a-computer-system-hacked-warning.jpg?s=612x612&w=0&k=20&c=U45FHOm5rflXIRqmYByxlQANtdtycEdFZz2Vp5dgI8E=",
                caption="Critical breach telemetry detected across dark web attack surfaces.",
            )
            st.markdown(
                """
                <ul class="dw-attack-list">
                  <li>🧨 Ransomware crews trading initial access credentials</li>
                  <li>🕶️ Stealer logs exposing corporate VPN & email accounts</li>
                  <li>📦 Cloud snapshots & code repos surfacing in private dumps</li>
                </ul>
                """,
                unsafe_allow_html=True,
            )
            st.markdown('</div>', unsafe_allow_html=True)

            st.markdown('</div>', unsafe_allow_html=True)

        st.markdown("---")
        st.markdown('<div id="login" class="dw-login-heading">Authenticate to access the live console</div>', unsafe_allow_html=True)

        if not st.session_state.show_register:
            login_form(SessionLocal)
            st.markdown("---")
            if st.button("New user? Register"):
                st.session_state.show_register = True
                st.rerun()
        else:
            register_form(SessionLocal)
            st.markdown("---")
            if st.button("Back to login"):
                st.session_state.show_register = False
                st.rerun()

        # Simple FAQ section
        st.markdown('<div id="faq"></div>', unsafe_allow_html=True)
        with st.expander("What does Dark Web Monitor actually do?"):
            st.write(
                "It continuously checks dark web breach sources (via your backend integrations) "
                "for your monitored emails and identities, then turns those findings into risk scores "
                "and a historical breach ledger."
            )
        with st.expander("What is the difference between Individual and Enterprise mode?"):
            st.write(
                "Individual mode focuses on a single user monitoring their own emails; "
                "Enterprise mode lets an organization admin monitor many employee emails and see "
                "one combined organization risk posture."
            )
        with st.expander("Does this store my passwords?"):
            st.write(
                "No. The password monitor uses the Have I Been Pwned Pwned Passwords API with SHA-1 "
                "k-anonymity. Only the first 5 characters of the hash are sent, and nothing is stored."
            )
    else:
        render_dashboard(SessionLocal)


if __name__ == "__main__":
    main()

