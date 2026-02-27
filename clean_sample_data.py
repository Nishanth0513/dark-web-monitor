from models import Breach, MonitoredEmail, RemediationAction, ActivityLog, EmailPreview
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
DEFAULT_DB_PATH = os.path.join(INSTANCE_DIR, "darkweb_monitor.db")
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH}")

# Create database connection
engine = create_engine(DATABASE_URL)
session = sessionmaker(bind=engine)()

print("🗑️ Cleaning sample/dummy data...")
print("=" * 60)

# Delete all sample breaches
breaches_deleted = session.query(Breach).delete()
print(f"✅ Deleted {breaches_deleted} sample breaches")

# Delete duplicate monitored emails (keep unique ones)
emails = session.query(MonitoredEmail).all()
seen = set()
duplicates = []
for email in emails:
    if email.email in seen:
        duplicates.append(email)
    else:
        seen.add(email.email)

for dup in duplicates:
    session.delete(dup)
print(f"✅ Deleted {len(duplicates)} duplicate monitored emails")

# Delete sample remediation actions
actions_deleted = session.query(RemediationAction).delete()
print(f"✅ Deleted {actions_deleted} sample remediation actions")

# Delete sample activity logs
logs_deleted = session.query(ActivityLog).delete()
print(f"✅ Deleted {logs_deleted} sample activity logs")

# Delete sample email previews
previews_deleted = session.query(EmailPreview).delete()
print(f"✅ Deleted {previews_deleted} sample email previews")

session.commit()

print("\n" + "=" * 60)
print("✅ Database cleaned!")
print("\n📊 Remaining data:")
print(f"  - Monitored Emails: {session.query(MonitoredEmail).count()}")
print(f"  - Breaches: {session.query(Breach).count()}")
print(f"  - Remediation Actions: {session.query(RemediationAction).count()}")
print(f"  - Activity Logs: {session.query(ActivityLog).count()}")
print("\n💡 Now run a manual scan in the dashboard to fetch REAL breaches from LeakCheck!")

session.close()
