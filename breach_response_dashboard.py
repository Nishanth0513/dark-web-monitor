import os
import streamlit as st
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Database setup
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)
DEFAULT_DB_PATH = os.path.join(INSTANCE_DIR, "darkweb_monitor.db")
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH}")

# Initialize Flask app for database
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Import models after database initialization
from models import User, MonitoredEmail, Breach, Organization, OrgEmail, OrgBreach, RemediationAction, ActivityLog, EmailPreview

# Create session
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

# ============================================
# LOCAL BREACH RESPONSE FUNCTIONS (without Flask-SQLAlchemy dependency)
# ============================================

def generate_required_actions(email: str, breaches, db_session):
    """Generate required actions based on breach severity"""
    actions = []
    action_types_added = set()
    
    for breach in breaches:
        exposed_data = breach.data_exposed.lower()
        
        if 'password' in exposed_data:
            password_actions = [
                {'type': 'password_change', 'description': 'Change password immediately', 'priority': 1},
                {'type': 'enable_2fa', 'description': 'Enable Two-Factor Authentication (2FA)', 'priority': 1},
                {'type': 'check_activity', 'description': 'Check account for suspicious activity', 'priority': 1},
                {'type': 'revoke_sessions', 'description': 'Revoke all active sessions', 'priority': 1},
                {'type': 'update_other_sites', 'description': 'Update password on other sites using same password', 'priority': 2}
            ]
            
            for action in password_actions:
                if action['type'] not in action_types_added:
                    actions.append(action)
                    action_types_added.add(action['type'])
        elif 'financial' in exposed_data or 'card' in exposed_data:
            financial_actions = [
                {'type': 'contact_bank', 'description': 'Contact bank immediately', 'priority': 1},
                {'type': 'freeze_card', 'description': 'Freeze/replace credit cards', 'priority': 1},
                {'type': 'monitor_transactions', 'description': 'Monitor transactions for fraud', 'priority': 1}
            ]
            
            for action in financial_actions:
                if action['type'] not in action_types_added:
                    actions.append(action)
                    action_types_added.add(action['type'])
        else:
            email_actions = [
                {'type': 'monitor_phishing', 'description': 'Monitor for phishing emails', 'priority': 2},
                {'type': 'check_spam', 'description': 'Check and update spam filters', 'priority': 3},
                {'type': 'report_suspicious', 'description': 'Report any suspicious emails received', 'priority': 3}
            ]
            
            for action in email_actions:
                if action['type'] not in action_types_added:
                    actions.append(action)
                    action_types_added.add(action['type'])
    
    return actions

def save_remediation_actions_local(email: str, breaches, db_session):
    """Save generated actions to database"""
    actions = generate_required_actions(email, breaches, db_session)
    
    count = 0
    for action in actions:
        # Check for existing actions of the same type for this email (regardless of status)
        existing = db_session.query(RemediationAction).filter_by(
            email=email,
            action_type=action['type']
        ).first()
        
        if not existing:
            new_action = RemediationAction(
                email=email,
                breach_id=breaches[0].id if breaches else None,
                action_type=action['type'],
                description=action['description'],
                priority=action['priority'],
                status='pending'
            )
            db_session.add(new_action)
            count += 1
    
    if count > 0:
        db_session.commit()
        
        # Log activity
        activity = ActivityLog(
            timestamp=datetime.utcnow(),
            email=email,
            action='actions_generated',
            message=f"🔧 Generated {count} new remediation actions for {email}",
            severity='info'
        )
        db_session.add(activity)
        db_session.commit()
    
    return count

def get_pending_actions_local(email: str, db_session):
    """Get all pending actions for an email"""
    return db_session.query(RemediationAction).filter_by(
        email=email,
        status='pending'
    ).order_by(RemediationAction.priority).all()

def get_completed_actions_local(email: str, db_session):
    """Get all completed actions for an email"""
    return db_session.query(RemediationAction).filter_by(
        email=email,
        status='completed'
    ).order_by(RemediationAction.completed_at.desc()).all()

def mark_action_completed_local(action_id: int, db_session):
    """Mark a specific action as completed"""
    action = db_session.query(RemediationAction).filter_by(id=action_id).first()
    
    if action:
        action.status = 'completed'
        action.completed_at = datetime.utcnow()
        db_session.commit()
        
        # Log activity
        activity = ActivityLog(
            timestamp=datetime.utcnow(),
            email=action.email,
            action='action_completed',
            message=f"✅ Completed action: {action.description} for {action.email}",
            severity='info'
        )
        db_session.add(activity)
        db_session.commit()
        
        return True
    
    return False

def calculate_completion_rate_local(email: str, db_session):
    """Calculate completion rate for an email"""
    pending = len(get_pending_actions_local(email, db_session))
    completed = len(get_completed_actions_local(email, db_session))
    total = pending + completed
    
    if total == 0:
        return 0, 0, 0.0
    
    percentage = (completed / total) * 100
    return completed, total, percentage

def get_response_status_local(email: str, db_session):
    """Get response status for an email"""
    completed, total, percentage = calculate_completion_rate_local(email, db_session)
    
    if total == 0:
        return 'no_actions', '✅ No actions required'
    elif completed == 0:
        return 'pending', '⏳ PENDING'
    elif completed < total:
        return 'in_progress', '⚠️ IN PROGRESS'
    else:
        return 'completed', '✅ COMPLETED'

def get_action_summary_local(db_session):
    """Get summary of all pending actions across all accounts"""
    pending_actions = db_session.query(RemediationAction).filter_by(
        status='pending'
    ).all()
    
    summary = {}
    for action in pending_actions:
        action_name = action.action_type.replace('_', ' ').title()
        summary[action_name] = summary.get(action_name, 0) + 1
    
    return summary

def get_breach_statistics_local(db_session):
    """Get overall breach response statistics"""
    breached_emails = db_session.query(Breach).distinct(Breach.email).all()
    total_breached = len(set(b.email for b in breached_emails))
    
    total_pending = db_session.query(RemediationAction).filter_by(status='pending').count()
    total_completed = db_session.query(RemediationAction).filter_by(status='completed').count()
    total_actions = total_pending + total_completed
    
    completion_rate = (total_completed / total_actions * 100) if total_actions > 0 else 0
    
    return {
        'breached_accounts': total_breached,
        'actions_pending': total_pending,
        'actions_completed': total_completed,
        'completion_rate': completion_rate
    }

def get_recent_activities_local(db_session, limit: int = 10):
    """Get recent activity logs"""
    return db_session.query(ActivityLog).order_by(
        ActivityLog.timestamp.desc()
    ).limit(limit).all()

# CSS Styling
DASHBOARD_CSS = """
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

/* Metrics styling */
div[data-testid="metric-container"] {
  background-color: rgba(15, 23, 42, 0.8);
  border: 1px solid rgba(148, 163, 184, 0.2);
  border-radius: 8px;
  padding: 1rem;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
}

/* Expander styling */
.streamlit-expanderHeader {
  background-color: rgba(15, 23, 42, 0.9);
  border-radius: 8px;
}

/* Alert styling */
[data-testid="stAlert"] {
  background-color: rgba(15,23,42,0.98) !important;
  border-radius: 10px !important;
  border: 1px solid rgba(248,250,252,0.12) !important;
}

/* Buttons */
button, .stButton > button {
  border-radius: 8px !important;
  background: linear-gradient(120deg, #06b6d4, #22c55e) !important;
  border: 1px solid rgba(34,197,94,0.9) !important;
  color: #020617 !important;
  font-weight: 600 !important;
}

/* Progress bar */
.stProgress > div > div > div {
  background: linear-gradient(90deg, #22c55e, #06b6d4) !important;
}
</style>
"""

def show_breach_response_center():
    """
    Main Breach Response Center page
    """
    
    st.markdown(DASHBOARD_CSS, unsafe_allow_html=True)
    
    st.title("🚨 Breach Response Center")
    st.caption("Action Required for Compromised Accounts")
    
    # Get database session
    db_session = SessionLocal()
    
    try:
        # Get statistics
        stats = get_breach_statistics_local(db_session)
        
        # Display overview metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "🔴 Breached Accounts",
                stats['breached_accounts']
            )
        
        with col2:
            st.metric(
                "⚠️ Actions Pending",
                stats['actions_pending']
            )
        
        with col3:
            st.metric(
                "✅ Actions Completed",
                stats['actions_completed']
            )
        
        with col4:
            st.metric(
                "📈 Completion Rate",
                f"{stats['completion_rate']:.0f}%"
            )
        
        st.divider()
        
        # Get all unique breached emails using a different approach
        breached_emails_query = db_session.query(Breach.email).distinct().all()
        breached_emails = [{'email': row[0]} for row in breached_emails_query]
        
        if not breached_emails:
            st.info("✅ No breached accounts found. All clear!")
            return
        
        # Display accounts found in breaches
        st.subheader("🔴 Accounts Found in Breaches (Action Required)")
        
        for i, account in enumerate(breached_emails):
            email = account['email']
            
            # Get breaches for this email
            breaches = db_session.query(Breach).filter_by(email=email).all()
            
            # Get actions
            pending_actions = get_pending_actions_local(email, db_session)
            completed_actions = get_completed_actions_local(email, db_session)
            
            # Calculate status
            status_code, status_label = get_response_status_local(email, db_session)
            completed, total, percentage = calculate_completion_rate_local(email, db_session)
            
            # Determine if should be expanded
            should_expand = (status_code in ['pending', 'in_progress'])
            
            # Display account card
            with st.expander(
                f"📧 **{email}** - {status_label}",
                expanded=should_expand
            ):
                
                # Show breach details
                st.write("**Breach Details:**")
                for breach in breaches:
                    st.info(f"""
                    **{breach.breach_name}**  
                    Date: {breach.breach_date.strftime('%Y-%m-%d')}  
                    Data Exposed: {breach.data_exposed}
                    """)
                
                st.write("---")
                
                # Show required actions
                st.subheader("⚠️ REQUIRED ACTIONS:")
                
                if total == 0:
                    # Generate actions if none exist
                    if st.button(f"Generate Actions for {email}", key=f"gen_{i}_{hash(email) % 10000}"):
                        count = save_remediation_actions_local(email, breaches, db_session)
                        if count > 0:
                            st.success(f"✅ Generated {count} actions!")
                        else:
                            st.info("ℹ️ All necessary actions already exist for this account.")
                        st.rerun()
                else:
                    # Show actions summary
                    st.info(f"📋 {total} security actions required ({completed} completed)")
                    
                    # Show pending actions with checkboxes
                    if pending_actions:
                        st.write("**Pending:**")
                        for j, action in enumerate(pending_actions):
                            col1, col2 = st.columns([0.9, 0.1])
                            
                            with col1:
                                st.write(f"☐ {action.description}")
                            
                            with col2:
                                # Use a combination of account index, action ID, and action index for uniqueness
                                unique_key = f"complete_{i}_{action.id}_{j}_{hash(email) % 1000}"
                                if st.button("✓", key=unique_key):
                                    if mark_action_completed_local(action.id, db_session):
                                        st.success("✅")
                                        st.rerun()
                    
                    # Show completed actions
                    if completed_actions:
                        st.write("**Completed:**")
                        for action in completed_actions:
                            st.write(f"✅ {action.description}")
                    
                    # Show progress
                    st.write("---")
                    st.write(f"**Status:** {status_label} ({completed}/{total} completed)")
                    st.progress(percentage / 100)
                    
                    # Action buttons
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        if st.button("📧 Send Reminder", key=f"remind_{i}_{hash(email) % 10000}"):
                            st.success("Reminder sent!")
                    
                    with col2:
                        if st.button("📊 Generate Report", key=f"report_{i}_{hash(email) % 10000}"):
                            st.success("Report generated!")
                    
                    with col3:
                        if completed == total:
                            if st.button("✅ Archive", key=f"archive_{i}_{hash(email) % 10000}"):
                                st.success("Account secured and archived!")
                        else:
                            # Show regenerate option if needed
                            if st.button("🔄 Regenerate Actions", key=f"regen_{i}_{hash(email) % 10000}"):
                                st.warning("⚠️ This will create new actions if any are missing...")
                                count = save_remediation_actions_local(email, breaches, db_session)
                                if count > 0:
                                    st.success(f"✅ Added {count} new actions!")
                                else:
                                    st.info("ℹ️ No additional actions needed.")
                                st.rerun()
        
        st.divider()
        
        # Remediation summary
        st.subheader("✅ Remediation Summary")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Actions Needed Across All Accounts:**")
            action_summary = get_action_summary_local(db_session)
            
            if action_summary:
                for action_type, count in action_summary.items():
                    st.write(f"• {action_type}: {count}")
            else:
                st.write("No pending actions")
        
        with col2:
            st.write("**Overall Progress:**")
            st.metric("Completion Rate", f"{stats['completion_rate']:.1f}%")
            st.progress(stats['completion_rate'] / 100)
        
        st.divider()
        
        # Recent activity
        st.subheader("📈 Recent Activity")
        
        activities = get_recent_activities_local(db_session, limit=10)
        
        if activities:
            for activity in activities:
                time_str = activity.timestamp.strftime('%I:%M %p')
                st.text(f"{time_str} - {activity.message}")
        else:
            st.info("No recent activity")
    
    finally:
        db_session.close()

def main():
    """Main entry point for the Breach Response Center dashboard"""
    
    # Set page config
    st.set_page_config(
        page_title="Breach Response Center",
        page_icon="🚨",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Sidebar navigation
    with st.sidebar:
        st.title("🚨 BRC")
        st.caption("Breach Response Center")
        
        st.divider()
        
        # Quick stats
        db_session = SessionLocal()
        try:
            stats = get_breach_statistics_local(db_session)
            
            st.metric("Total Breached", stats['breached_accounts'])
            st.metric("Pending Actions", stats['actions_pending'])
            st.metric("Completion", f"{stats['completion_rate']:.0f}%")
            
        finally:
            db_session.close()
        
        st.divider()
        
        # Refresh button
        if st.button("🔄 Refresh Data", type="primary"):
            st.rerun()
        
        st.divider()
        
        # Navigation
        st.subheader("Navigation")
        if st.button("🏠 Dashboard"):
            st.rerun()
        
        if st.button("📊 Reports"):
            st.info("Reports feature coming soon!")
        
        if st.button("⚙️ Settings"):
            st.info("Settings feature coming soon!")
        
        st.divider()
        
        # System info
        st.subheader("System Info")
        st.text(f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        st.text("Version: 1.0.0")
    
    # Main content
    show_breach_response_center()

if __name__ == "__main__":
    main()
