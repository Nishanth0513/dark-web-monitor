from models import User, db
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
DEFAULT_DB_PATH = os.path.join(INSTANCE_DIR, "darkweb_monitor.db")
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH}")

# Create database connection
engine = create_engine(DATABASE_URL)
db.metadata.create_all(engine)
session = sessionmaker(bind=engine)()

print("🔍 Checking users in database...")
users = session.query(User).all()
print(f"Total users: {len(users)}")

for user in users:
    print(f"- ID: {user.id}, Email: {user.email}, Created: {user.created_at}")

# Check if there are any existing users from before
if len(users) == 0:
    print("\n⚠️ No users found in database!")
    print("You need to register a user first.")
elif len(users) == 1 and users[0].email == "demo@example.com":
    print(f"\n⚠️ Only demo user found: {users[0].email}")
    print("This user has a dummy password hash and cannot login.")
    print("Please register a real user account.")

session.close()
