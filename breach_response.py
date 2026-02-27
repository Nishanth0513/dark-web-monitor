from models import RemediationAction, ActivityLog, EmailPreview, Breach, MonitoredEmail, db
from datetime import datetime
from typing import List, Dict, Tuple

# ============================================
# ACTION GENERATION
# ============================================

def generate_required_actions(email: str, breaches: List[Breach]) -> List[Dict]:
    """
    Generate required actions based on breach severity
    
    Args:
        email: Email address
        breaches: List of Breach objects
    
    Returns:
        List of action dictionaries
    """
    
    actions = []
    action_types_added = set()  # Prevent duplicates
    
    for breach in breaches:
        exposed_data = breach.data_exposed.lower()
        
        # If password was exposed - HIGH PRIORITY
        if 'password' in exposed_data:
            password_actions = [
                {
                    'type': 'password_change',
                    'description': 'Change password immediately',
                    'priority': 1
                },
                {
                    'type': 'enable_2fa',
                    'description': 'Enable Two-Factor Authentication (2FA)',
                    'priority': 1
                },
                {
                    'type': 'check_activity',
                    'description': 'Check account for suspicious activity',
                    'priority': 1
                },
                {
                    'type': 'revoke_sessions',
                    'description': 'Revoke all active sessions',
                    'priority': 1
                },
                {
                    'type': 'update_other_sites',
                    'description': 'Update password on other sites using same password',
                    'priority': 2
                }
            ]
            
            for action in password_actions:
                if action['type'] not in action_types_added:
                    actions.append(action)
                    action_types_added.add(action['type'])
        
        # If financial data exposed - CRITICAL
        elif 'financial' in exposed_data or 'card' in exposed_data:
            financial_actions = [
                {
                    'type': 'contact_bank',
                    'description': 'Contact bank immediately',
                    'priority': 1
                },
                {
                    'type': 'freeze_card',
                    'description': 'Freeze/replace credit cards',
                    'priority': 1
                },
                {
                    'type': 'monitor_transactions',
                    'description': 'Monitor transactions for fraud',
                    'priority': 1
                }
            ]
            
            for action in financial_actions:
                if action['type'] not in action_types_added:
                    actions.append(action)
                    action_types_added.add(action['type'])
        
        # If only email exposed - MEDIUM PRIORITY
        else:
            email_actions = [
                {
                    'type': 'monitor_phishing',
                    'description': 'Monitor for phishing emails',
                    'priority': 2
                },
                {
                    'type': 'check_spam',
                    'description': 'Check and update spam filters',
                    'priority': 3
                },
                {
                    'type': 'report_suspicious',
                    'description': 'Report any suspicious emails received',
                    'priority': 3
                }
            ]
            
            for action in email_actions:
                if action['type'] not in action_types_added:
                    actions.append(action)
                    action_types_added.add(action['type'])
    
    return actions


def save_remediation_actions(email: str, breaches: List[Breach]) -> int:
    """
    Save generated actions to database
    
    Returns:
        Number of actions created
    """
    
    # Generate actions
    actions = generate_required_actions(email, breaches)
    
    # Save to database
    count = 0
    for action in actions:
        # Check if action already exists
        existing = RemediationAction.query.filter_by(
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
            db.session.add(new_action)
            count += 1
    
    db.session.commit()
    
    # Log activity
    log_activity(
        email=email,
        action='actions_generated',
        message=f"Generated {count} remediation actions for {email}",
        severity='info'
    )
    
    return count


# ============================================
# ACTION TRACKING
# ============================================

def get_pending_actions(email: str) -> List[RemediationAction]:
    """Get all pending actions for an email"""
    return RemediationAction.query.filter_by(
        email=email,
        status='pending'
    ).order_by(RemediationAction.priority).all()


def get_completed_actions(email: str) -> List[RemediationAction]:
    """Get all completed actions for an email"""
    return RemediationAction.query.filter_by(
        email=email,
        status='completed'
    ).order_by(RemediationAction.completed_at.desc()).all()


def mark_action_completed(action_id: int) -> bool:
    """
    Mark a specific action as completed
    
    Returns:
        True if successful, False otherwise
    """
    action = RemediationAction.query.filter_by(id=action_id).first()
    
    if action:
        action.status = 'completed'
        action.completed_at = datetime.utcnow()
        db.session.commit()
        
        # Log activity
        log_activity(
            email=action.email,
            action='action_completed',
            message=f"✅ Completed action: {action.description} for {action.email}",
            severity='info'
        )
        
        return True
    
    return False


def get_action_summary() -> Dict:
    """
    Get summary of all pending actions across all accounts
    
    Returns:
        Dictionary with action types and counts
    """
    pending_actions = RemediationAction.query.filter_by(
        status='pending'
    ).all()
    
    summary = {}
    for action in pending_actions:
        action_name = action.action_type.replace('_', ' ').title()
        summary[action_name] = summary.get(action_name, 0) + 1
    
    return summary


def calculate_completion_rate(email: str) -> Tuple[int, int, float]:
    """
    Calculate completion rate for an email
    
    Returns:
        (completed_count, total_count, percentage)
    """
    pending = len(get_pending_actions(email))
    completed = len(get_completed_actions(email))
    total = pending + completed
    
    if total == 0:
        return 0, 0, 0.0
    
    percentage = (completed / total) * 100
    
    return completed, total, percentage


# ============================================
# STATUS DETERMINATION
# ============================================

def get_response_status(email: str) -> Tuple[str, str]:
    """
    Get response status for an email
    
    Returns:
        (status_code, status_label)
        status_code: 'pending', 'in_progress', 'completed'
        status_label: Display text
    """
    completed, total, percentage = calculate_completion_rate(email)
    
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
                 message: str = '', severity: str = 'info'):
    """
    Log activity to database
    
    Args:
        email: Optional email address
        action: Action type
        message: Log message
        severity: 'info', 'warning', 'critical'
    """
    activity = ActivityLog(
        timestamp=datetime.utcnow(),
        email=email,
        action=action,
        message=message,
        severity=severity
    )
    db.session.add(activity)
    db.session.commit()


def get_recent_activities(limit: int = 10) -> List[ActivityLog]:
    """Get recent activity logs"""
    return ActivityLog.query.order_by(
        ActivityLog.timestamp.desc()
    ).limit(limit).all()


# ============================================
# STATISTICS
# ============================================

def get_breach_statistics() -> Dict:
    """
    Get overall breach response statistics
    
    Returns:
        Dictionary with statistics
    """
    # Get all emails with breaches
    breached_emails = Breach.query.distinct(Breach.email).all()
    
    total_breached = len(set(b.email for b in breached_emails))
    
    # Count action statuses
    total_pending = RemediationAction.query.filter_by(
        status='pending'
    ).count()
    
    total_completed = RemediationAction.query.filter_by(
        status='completed'
    ).count()
    
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
                            actions: List[Dict], risk_score: int) -> bool:
    """
    Send email alert for new breach (demo mode - saves preview)
    """
    
    # Build action list HTML
    action_html = ""
    for action in actions:
        action_html += f"<li>{action['description']}</li>"
    
    # Build breach list HTML
    breach_html = ""
    for breach in breaches:
        breach_html += f"""
        <div style='margin: 10px 0; padding: 10px; background: #f8f9fa; border-left: 4px solid #dc3545;'>
            <strong>{breach.breach_name}</strong><br>
            Date: {breach.breach_date.strftime('%Y-%m-%d')}<br>
            Exposed: {breach.data_exposed}
        </div>
        """
    
    html = f"""
    <html>
    <body style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>
        <div style='background: #667eea; padding: 30px; text-align: center;'>
            <h1 style='color: white; margin: 0;'>🚨 Security Alert</h1>
        </div>
        <div style='padding: 30px;'>
            <p><strong>Dear User,</strong></p>
            <p>Your email <strong style='color: #dc3545;'>{email}</strong> was found in a data breach.</p>
            
            <h3>Breaches Detected:</h3>
            {breach_html}
            
            <div style='background: #fff3cd; padding: 20px; margin: 20px 0; border-radius: 8px;'>
                <h3 style='color: #856404;'>⚠️ IMMEDIATE ACTION REQUIRED</h3>
                <ol style='color: #856404;'>
                    {action_html}
                </ol>
            </div>
            
            <div style='text-align: center; margin: 30px 0;'>
                <a href='http://localhost:8501' 
                   style='background: #667eea; color: white; padding: 15px 30px; 
                          text-decoration: none; border-radius: 8px; font-weight: bold;'>
                    Go to Dashboard
                </a>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Save preview (demo mode)
    preview = EmailPreview(
        recipient=email,
        subject=f"🚨 Security Alert: Breach Detected",
        html_content=html,
        risk_score=risk_score
    )
    db.session.add(preview)
    db.session.commit()
    
    log_activity(email, 'email_sent', f"📧 Email alert sent to {email}")
    return True
