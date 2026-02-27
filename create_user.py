from models import User
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from werkzeug.security import generate_password_hash
from datetime import datetime
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
DEFAULT_DB_PATH = os.path.join(INSTANCE_DIR, "darkweb_monitor.db")
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH}")

# Create database connection
engine = create_engine(DATABASE_URL)
session = sessionmaker(bind=engine)()

print("👤 Create a new user account")
print("=" * 40)

email = input("Enter email: ").strip().lower()
password = input("Enter password: ").strip()

if not email or not password:
    print("❌ Email and password are required!")
    exit(1)

# Check if user already exists
existing_user = session.query(User).filter(User.email == email).first()
if existing_user:
    print(f"❌ User {email} already exists!")
    session.close()
    exit(1)

# Create new user
password_hash = generate_password_hash(password)
new_user = User(
    email=email,
    password_hash=password_hash,
    created_at=datetime.utcnow()
)

session.add(new_user)
session.commit()

print(f"✅ User {email} created successfully!")
print(f"📝 User ID: {new_user.id}")
print("🔑 You can now login with these credentials.")

session.close()
