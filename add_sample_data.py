from models import db, RemediationAction, ActivityLog, EmailPreview, User, MonitoredEmail, Breach, Organization, OrgEmail, OrgBreach
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
DEFAULT_DB_PATH = os.path.join(INSTANCE_DIR, "darkweb_monitor.db")
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH}")

# Create database connection
engine = create_engine(DATABASE_URL)
db_session = sessionmaker(bind=engine)()

print("📝 Adding sample data...")

# Create sample user
user = User(
    email="demo@example.com",
    password_hash="dummy_hash",
    created_at=datetime.utcnow()
)
db_session.add(user)
db_session.commit()

# Create sample monitored emails
emails = [
    MonitoredEmail(email="akshithareddy2405@gmail.com", user_id=user.id, last_checked=datetime.utcnow() - timedelta(hours=2)),
    MonitoredEmail(email="swiggy@gmail.com", user_id=user.id, last_checked=datetime.utcnow() - timedelta(hours=3)),
    MonitoredEmail(email="test@gmail.com", user_id=user.id, last_checked=datetime.utcnow() - timedelta(hours=1)),
    MonitoredEmail(email="test123@gmail.com", user_id=user.id, last_checked=datetime.utcnow() - timedelta(hours=4))
]
for email in emails:
    db_session.add(email)
db_session.commit()

# Create sample breaches
for email in emails:
    breach = Breach(
        email=email.email,
        breach_name="Sample Breach 2024",
        breach_date=datetime.utcnow() - timedelta(days=30),
        data_exposed="Email, Password, Phone",
        severity="HIGH",
        detected_at=datetime.utcnow() - timedelta(hours=5)
    )
    db_session.add(breach)
    db_session.commit()

# Create sample remediation actions
actions = [
    RemediationAction(
        email="akshithareddy2405@gmail.com",
        breach_id=1,
        action_type="password_change",
        description="Change password due to breach",
        priority=1,
        status="pending"
    ),
    RemediationAction(
        email="swiggy@gmail.com",
        breach_id=2,
        action_type="enable_2fa",
        description="Enable two-factor authentication",
        priority=2,
        status="completed",
        completed_at=datetime.utcnow() - timedelta(hours=1)
    ),
    RemediationAction(
        email="test@gmail.com",
        breach_id=3,
        action_type="monitor_account",
        description="Monitor account for suspicious activity",
        priority=3,
        status="pending"
    )
]
for action in actions:
    db_session.add(action)
db_session.commit()

# Create sample activity logs
logs = [
    ActivityLog(
        email="akshithareddy2405@gmail.com",
        action="breach_detected",
        message="New breach detected for akshithareddy2405@gmail.com",
        severity="critical"
    ),
    ActivityLog(
        email="swiggy@gmail.com",
        action="action_completed",
        message="2FA enabled successfully",
        severity="info"
    ),
    ActivityLog(
        email="test@gmail.com",
        action="breach_detected",
        message="Potential breach found in recent scan",
        severity="warning"
    )
]
for log in logs:
    db_session.add(log)
db_session.commit()

# Create sample email preview
email_preview = EmailPreview(
    recipient="shreyaburra18@gmail.com",
    subject="🚨 High Risk Alert: Multiple Breaches Detected",
    html_content="<h1>Breach Alert</h1><p>High risk breaches detected...</p>",
    risk_score=75,
    status="sent"
)
db_session.add(email_preview)
db_session.commit()

db_session.close()
print("✅ Sample data added successfully!")
print("\n📊 Summary:")
print(f"- Users: 1")
print(f"- Monitored Emails: 4")
print(f"- Breaches: 4")
print(f"- Remediation Actions: 3")
print(f"- Activity Logs: 3")
print(f"- Email Previews: 1")
