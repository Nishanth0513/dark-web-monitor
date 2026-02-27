from models import db, RemediationAction, ActivityLog, EmailPreview
from sqlalchemy import create_engine
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)
DEFAULT_DB_PATH = os.path.join(INSTANCE_DIR, "darkweb_monitor.db")
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH}")

# Create database connection
engine = create_engine(DATABASE_URL)

# Create new tables
db.metadata.create_all(engine)

print("✅ Database tables created successfully!")
