from models import Breach, MonitoredEmail
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

print("🔍 Checking breaches in database...")
print("=" * 60)

# Get all monitored emails
emails = session.query(MonitoredEmail).all()
print(f"\nMonitored Emails: {len(emails)}")
for email in emails:
    print(f"  - {email.email}")

# Get all breaches
breaches = session.query(Breach).all()
print(f"\nTotal Breaches in Database: {len(breaches)}")

for breach in breaches:
    print(f"\n📧 Email: {breach.email}")
    print(f"   Breach: {breach.breach_name}")
    print(f"   Date: {breach.breach_date}")
    print(f"   Data Exposed: {breach.data_exposed}")
    print(f"   Severity: {breach.severity}")
    print(f"   Detected At: {breach.detected_at}")

print("\n" + "=" * 60)
print("💡 These are SAMPLE breaches added by add_sample_data.py")
print("💡 They are NOT from LeakCheck API - they're dummy data!")
print("\n🔧 To fix: Delete sample breaches and run a real scan")

session.close()
