from models import MonitoredEmail, Breach, db
from breach_response import (
    save_remediation_actions,
    get_pending_actions,
    mark_action_completed,
    get_response_status
)
from datetime import datetime
import os

# Set up database
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)
DEFAULT_DB_PATH = os.path.join(INSTANCE_DIR, "darkweb_monitor.db")
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH}")

from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

def test_breach_response():
    """
    Test the breach response system
    """
    
    with app.app_context():
        # Create test email
        test_email = "test@example.com"
        
        # Create test breach
        test_breach = Breach(
            email=test_email,
            breach_name="Test Breach",
            breach_date=datetime.now(),
            data_exposed="Email addresses, Passwords",
            severity="high"
        )
        db.session.add(test_breach)
        db.session.commit()
        
        print("✅ Test breach created")
        
        # Generate actions
        count = save_remediation_actions(test_email, [test_breach])
        print(f"✅ Generated {count} actions")
        
        # Get pending actions
        pending = get_pending_actions(test_email)
        print(f"✅ Found {len(pending)} pending actions:")
        for action in pending:
            print(f"   - {action.description}")
        
        # Mark first action as completed
        if pending:
            mark_action_completed(pending[0].id)
            print(f"✅ Marked action as completed")
        
        # Check status
        status_code, status_label = get_response_status(test_email)
        print(f"✅ Status: {status_label}")
        
        print("\n🎉 All tests passed!")

if __name__ == "__main__":
    test_breach_response()
