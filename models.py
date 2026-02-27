from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    has_unseen_breaches = db.Column(db.Boolean, default=False)


class MonitoredEmail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    last_checked = db.Column(db.DateTime, nullable=True)


class Breach(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    breach_name = db.Column(db.String(255), nullable=False)
    breach_date = db.Column(db.DateTime, nullable=False)
    data_exposed = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(50), nullable=False)
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)


class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    org_email = db.Column(db.String(255), nullable=True)  # New field for organization contact email
    admin_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    has_unseen_breaches = db.Column(db.Boolean, default=False)


class OrgEmail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False)
    role = db.Column(db.String(50), default='Employee')  # CEO, CTO, Admin, etc.
    systems = db.Column(db.String(500), default='')  # Comma-separated list of systems
    last_checked = db.Column(db.DateTime, nullable=True)


class OrgBreach(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    breach_name = db.Column(db.String(255), nullable=False)
    breach_date = db.Column(db.DateTime, nullable=False)
    data_exposed = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(50), nullable=False)
    score = db.Column(db.Integer, default=0)
    is_canary = db.Column(db.Boolean, default=False)
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)


class RiskHistory(db.Model):
    __tablename__ = 'risk_history'
    
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False)
    eri = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class EmployeeRiskHistory(db.Model):
    __tablename__ = 'employee_risk_history'
    
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class RemediationAction(db.Model):
    __tablename__ = 'remediation_actions'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    breach_id = db.Column(db.Integer, db.ForeignKey('breach.id'), nullable=True)
    
    # Action details
    action_type = db.Column(db.String(100), nullable=False)  # 'password_change', 'enable_2fa', etc.
    description = db.Column(db.String(500), nullable=False)  # Human-readable description
    priority = db.Column(db.Integer, default=1)  # 1=high, 2=medium, 3=low
    
    # Status tracking
    status = db.Column(db.String(50), default='pending')  # 'pending', 'completed', 'ignored'
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    
    def __repr__(self):
        return f"<RemediationAction {self.email} - {self.action_type}>"


class ActivityLog(db.Model):
    __tablename__ = 'activity_log'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    email = db.Column(db.String(255), nullable=True)
    action = db.Column(db.String(100), nullable=False)  # 'breach_detected', 'action_completed', etc.
    message = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(50), default='info')  # 'info', 'warning', 'critical'
    
    def __repr__(self):
        return f"<ActivityLog {self.timestamp} - {self.action}>"


class EmailPreview(db.Model):
    __tablename__ = 'email_previews'
    
    id = db.Column(db.Integer, primary_key=True)
    recipient = db.Column(db.String(255), nullable=False)
    subject = db.Column(db.String(500), nullable=False)
    html_content = db.Column(db.Text, nullable=True)
    risk_score = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='sent')
    
    def __repr__(self):
        return f"<EmailPreview to {self.recipient}>"

