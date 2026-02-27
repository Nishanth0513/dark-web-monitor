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
from risk_engine import calculate_risk
from pdf_service import generate_breach_report
from scheduler import simulate_breach_check


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)
DEFAULT_DB_PATH = os.path.join(INSTANCE_DIR, "darkweb_monitor.db")
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH}")


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
    if "show_register" not in st.session_state:
        st.session_state.show_register = False
    if "mode" not in st.session_state:
        st.session_state.mode = "Individual"
    if "active_org_id" not in st.session_state:
        st.session_state.active_org_id = None


def enterprise_score_for_email(breaches: list[OrgBreach]) -> int:
    """
    Enterprise scoring (0-100):
    - Any password leak: +40
    - Each breach: +10
    """
    if not breaches:
        return 0
    score = len(breaches) * 10
    if any("password" in (b.data_exposed or "").lower() for b in breaches):
        score += 40
    return min(100, score)


def enterprise_level_from_score(score_0_100: int) -> str:
    if score_0_100 == 0:
        return "SAFE"
    if score_0_100 <= 33:
        return "MEDIUM"
    if score_0_100 <= 66:
        return "HIGH"
    return "CRITICAL"


def check_password_pwned(password: str) -> tuple[bool, int]:
    """
    Check if a password has appeared in known breaches using
    the Have I Been Pwned Pwned Passwords API (k-anonymity).
    - We only send the first 5 chars of the SHA-1 hash.
    - We never store the password or full hash.
    """
    if not password:
        return False, 0

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code != 200:
            return False, 0
        for line in resp.text.splitlines():
            parts = line.split(":")
            if len(parts) != 2:
                continue
            hash_suffix, count_str = parts
            if hash_suffix.strip().upper() == suffix:
                try:
                    count = int(count_str.strip())
                except ValueError:
                    count = 1
                return True, count
    except Exception:
        return False, 0

    return False, 0


def register_form(SessionLocal):
    st.subheader("Register")
    with st.form("register_form"):
        email = st.text_input("Email", key="reg_email")
        password = st.text_input("Password", type="password", key="reg_password")
        submitted = st.form_submit_button("Create account")
        if submitted:
            email_clean = (email or "").strip().lower()
            if not email_clean or not password:
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
                    password_hash=generate_password_hash(password),
                )
                db_sess.add(user)
                db_sess.commit()
                st.success("Registration successful. Please log in.")
            finally:
                db_sess.close()


def login_form(SessionLocal):
    st.subheader("Login")
    with st.form("login_form"):
        email = st.text_input("Email", key="login_email")
        password = st.text_input("Password", type="password", key="login_password")
        submitted = st.form_submit_button("Login")
        if submitted:
            email_clean = (email or "").strip().lower()
            db_sess = SessionLocal()
            try:
                user = db_sess.execute(
                    select(User).where(User.email == email_clean)
                ).scalar_one_or_none()
                if not user or not check_password_hash(user.password_hash, password):
                    st.error("Invalid email or password.")
                    return
                st.session_state.user_id = user.id
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
            st.subheader("Mode")
            st.session_state.mode = st.radio(
                "Select dashboard mode",
                ["Individual", "Enterprise"],
                index=0 if st.session_state.mode == "Individual" else 1,
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

        score, risk_level, risk_percentage = calculate_risk(breaches)

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Breaches", total_breaches)
        with col2:
            st.metric("Risk Level", risk_level, delta=f"Score {score}")
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

        left, right = st.columns([1, 2])

        with left:
            st.subheader("Monitored Emails")
            if monitored_emails:
                for m in monitored_emails:
                    label = m.email
                    if m.last_checked:
                        label += f" (last: {m.last_checked.strftime('%Y-%m-%d %H:%M')})"
                    st.write("- " + label)
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
                    simulated = simulate_breach_check(m.email)
                    for sb in simulated:
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
        employee_emails = [e.email for e in employees] or ["__none__"]

        org_breaches = (
            db_sess.query(OrgBreach)
            .filter(OrgBreach.org_id == active_org.id, OrgBreach.email.in_(employee_emails))
            .order_by(OrgBreach.detected_at.desc())
            .all()
        )

        per_email_scores = {}
        for e in employees:
            b_list = [b for b in org_breaches if b.email == e.email]
            per_email_scores[e.email] = enterprise_score_for_email(b_list)

        monitored_count = len(employees)
        exposed_count = sum(1 for e in employees if per_email_scores.get(e.email, 0) > 0)
        high_risk_count = sum(1 for e in employees if per_email_scores.get(e.email, 0) >= 67)

        org_score = 0
        if monitored_count > 0:
            org_score = int(round(sum(per_email_scores.values()) / monitored_count))
        org_level = enterprise_level_from_score(org_score)

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Employees Monitored", monitored_count)
        with col2:
            st.metric("Employees Exposed", exposed_count)
        with col3:
            st.metric("High Risk Accounts", high_risk_count)
        with col4:
            st.metric("Organization Risk Score", f"{org_score}/100", delta=org_level)

        st.markdown("---")

        left, right = st.columns([1, 2])
        with left:
            st.subheader("Employee Emails")
            if employees:
                for e in employees:
                    score = per_email_scores.get(e.email, 0)
                    lvl = enterprise_level_from_score(score)
                    st.write(f"- {e.email} — {score}/100 ({lvl})")
            else:
                st.info("No employee emails yet.")

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

            if st.button("Run Enterprise Scan Now"):
                new_breach_found = False
                for e in employees:
                    simulated = simulate_breach_check(e.email)
                    for sb in simulated:
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

        with right:
            st.subheader("Organization Breach History")
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
    init_db()
    ensure_default_state()
    _, SessionLocal = get_engine_and_session()

    if st.session_state.user_id is None:
        st.title("Dark Web Breach Monitor")
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
    else:
        render_dashboard(SessionLocal)


if __name__ == "__main__":
    main()

