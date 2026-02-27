from models import RemediationAction, ActivityLog, EmailPreview, Breach, MonitoredEmail, db
from datetime import datetime
from typing import List, Dict, Tuple, Optional
from sqlalchemy.orm import Session

# ============================================
# ACTION GENERATION
# ============================================

def generate_required_actions(email: str, breaches: List[Breach]) -> List[Dict]:
    """
    Generate required actions based on breach severity
    """
    actions = []
    action_types_added = set()
    
    for breach in breaches:
        exposed_data = (breach.data_exposed or "").lower()
        
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


def save_remediation_actions(email: str, breaches: List[Breach], db_session: Optional[Session] = None) -> int:
    """
    Save generated actions to database
    """
    session = db_session or db.session
    actions = generate_required_actions(email, breaches)
    
    count = 0
    for action in actions:
        existing = session.query(RemediationAction).filter_by(
            email=email,
            action_type=action['type'],
            status='pending'
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
            session.add(new_action)
            count += 1
    
    session.commit()
    log_activity(email, 'actions_generated', f"Generated {count} remediation actions for {email}", 'info', db_session=session)
    return count


# ============================================
# ACTION TRACKING
# ============================================

def get_pending_actions(email: str, db_session: Optional[Session] = None) -> List[RemediationAction]:
    """Get all pending actions for an email"""
    session = db_session or db.session
    return session.query(RemediationAction).filter_by(
        email=email,
        status='pending'
    ).order_by(RemediationAction.priority).all()


def get_completed_actions(email: str, db_session: Optional[Session] = None) -> List[RemediationAction]:
    """Get all completed actions for an email"""
    session = db_session or db.session
    return session.query(RemediationAction).filter_by(
        email=email,
        status='completed'
    ).order_by(RemediationAction.completed_at.desc()).all()


def mark_action_completed(action_id: int, db_session: Optional[Session] = None) -> bool:
    """Mark a specific action as completed"""
    session = db_session or db.session
    action = session.query(RemediationAction).filter_by(id=action_id).first()
    
    if action:
        action.status = 'completed'
        action.completed_at = datetime.utcnow()
        session.commit()
        log_activity(action.email, 'action_completed', f"✅ Completed action: {action.description} for {action.email}", 'info', db_session=session)
        return True
    return False


def get_action_summary(db_session: Optional[Session] = None, user_id: Optional[int] = None) -> Dict:
    """Get summary of all pending actions across all accounts"""
    session = db_session or db.session
    query = session.query(RemediationAction).filter_by(status='pending')
    
    if user_id:
        monitored_emails = session.query(MonitoredEmail.email).filter_by(user_id=user_id).all()
        emails = [e[0] for e in monitored_emails]
        query = query.filter(RemediationAction.email.in_(emails))
        
    pending_actions = query.all()
    
    summary = {}
    for action in pending_actions:
        action_name = action.action_type.replace('_', ' ').title()
        summary[action_name] = summary.get(action_name, 0) + 1
    return summary


def calculate_completion_rate(email: str, db_session: Optional[Session] = None) -> Tuple[int, int, float]:
    """Calculate completion rate for an email"""
    pending = len(get_pending_actions(email, db_session=db_session))
    completed = len(get_completed_actions(email, db_session=db_session))
    total = pending + completed
    
    if total == 0:
        return 0, 0, 0.0
    return completed, total, (completed / total) * 100


# ============================================
# STATUS DETERMINATION
# ============================================

def get_response_status(email: str, db_session: Optional[Session] = None) -> Tuple[str, str]:
    """Get response status for an email"""
    completed, total, percentage = calculate_completion_rate(email, db_session=db_session)
    
    if total == 0:
        return 'no_actions', '✅ No actions required'
    elif completed == 0:
        return 'pending', '⏳ PENDING'
    elif completed < total:
        return 'in_progress', '⚠️ IN PROGRESS'
    else:
        return 'completed', '✅ COMPLETED'


# ============================================
# ACTIVITY LOGGING
# ============================================

def log_activity(email: str = None, action: str = '', 
                 message: str = '', severity: str = 'info',
                 db_session: Optional[Session] = None):
    """Log activity to database"""
    session = db_session or db.session
    activity = ActivityLog(
        timestamp=datetime.utcnow(),
        email=email,
        action=action,
        message=message,
        severity=severity
    )
    session.add(activity)
    session.commit()


def get_recent_activities(limit: int = 10, db_session: Optional[Session] = None, user_id: Optional[int] = None) -> List[ActivityLog]:
    """Get recent activity logs"""
    session = db_session or db.session
    query = session.query(ActivityLog)
    
    if user_id:
        monitored_emails = session.query(MonitoredEmail.email).filter_by(user_id=user_id).all()
        emails = [e[0] for e in monitored_emails]
        query = query.filter(ActivityLog.email.in_(emails))
        
    return query.order_by(ActivityLog.timestamp.desc()).limit(limit).all()


# ============================================
# STATISTICS
# ============================================

def get_breach_statistics(db_session: Optional[Session] = None, user_id: Optional[int] = None) -> Dict:
    """Get overall breach response statistics"""
    session = db_session or db.session
    
    # Base queries
    breach_query = session.query(Breach.email).distinct()
    pending_query = session.query(RemediationAction).filter_by(status='pending')
    completed_query = session.query(RemediationAction).filter_by(status='completed')
    
    if user_id:
        monitored_emails = session.query(MonitoredEmail.email).filter_by(user_id=user_id).all()
        emails = [e[0] for e in monitored_emails]
        breach_query = breach_query.filter(Breach.email.in_(emails))
        pending_query = pending_query.filter(RemediationAction.email.in_(emails))
        completed_query = completed_query.filter(RemediationAction.email.in_(emails))
        
    total_breached = len(set(row[0] for row in breach_query.all()))
    total_pending = pending_query.count()
    total_completed = completed_query.count()
    total_actions = total_pending + total_completed
    
    completion_rate = (total_completed / total_actions * 100) if total_actions > 0 else 0
    
    return {
        'breached_accounts': total_breached,
        'actions_pending': total_pending,
        'actions_completed': total_completed,
        'completion_rate': completion_rate
    }


# ============================================
# EMAIL INTEGRATION (DEMO MODE)
# ============================================

def send_breach_alert_email(email: str, breaches: List[Breach], 
                            actions: List[Dict], risk_score: int,
                            db_session: Optional[Session] = None) -> bool:
    """Send email alert for new breach (demo mode - saves preview)"""
    session = db_session or db.session
    
    action_html = "".join([f"<li>{a['description']}</li>" for action in actions])
    breach_html = "".join([f"<div style='margin: 10px 0; padding: 10px; background: #f8f9fa; border-left: 4px solid #dc3545;'><strong>{b.breach_name}</strong><br>Date: {b.breach_date.strftime('%Y-%m-%d')}<br>Exposed: {b.data_exposed}</div>" for breach in breaches])
    
    html = f"""
    <html>
    <body style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>
        <div style='background: #667eea; padding: 30px; text-align: center;'><h1 style='color: white; margin: 0;'>🚨 Security Alert</h1></div>
        <div style='padding: 30px;'>
            <p><strong>Dear User,</strong></p>
            <p>Your email <strong style='color: #dc3545;'>{email}</strong> was found in a data breach.</p>
            <h3>Breaches Detected:</h3>{breach_html}
            <div style='background: #fff3cd; padding: 20px; margin: 20px 0; border-radius: 8px;'>
                <h3 style='color: #856404;'>⚠️ IMMEDIATE ACTION REQUIRED</h3>
                <ol style='color: #856404;'>{action_html}</ol>
            </div>
            <div style='text-align: center; margin: 30px 0;'><a href='http://localhost:8501' style='background: #667eea; color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; font-weight: bold;'>Go to Dashboard</a></div>
        </div>
    </body>
    </html>
    """
    
    preview = EmailPreview(recipient=email, subject=f"🚨 Security Alert: Breach Detected", html_content=html, risk_score=risk_score)
    session.add(preview)
    session.commit()
    log_activity(email, 'email_sent', f"📧 Email alert sent to {email}", db_session=session)
    return True
