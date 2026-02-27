"""
Alert Service for Dark Web Monitor
Sends SMS and email notifications when high/critical risk is detected
"""

import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from dotenv import load_dotenv
from twilio.rest import Client

# Load environment variables
load_dotenv()

# Twilio configuration
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.getenv("TWILIO_PHONE_NUMBER")
ALERT_PHONE_NUMBER = os.getenv("YOUR_PHONE_NUMBER")

# Email configuration
ALERT_EMAIL = os.getenv("ALERT_EMAIL")  # Recipient from .env
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_EMAIL = os.getenv("SMTP_EMAIL")  # Sender (molkyqwerty@gmail.com)
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")


def send_sms_alert(risk_level, score, email, breach_count):
    """
    Send SMS alert for high/critical risk detection
    
    Args:
        risk_level: Risk level string (e.g., "HIGH", "CRITICAL")
        score: Risk score (0-100)
        email: Email that triggered the alert
        breach_count: Number of breaches detected
    
    Returns:
        bool: True if SMS sent successfully, False otherwise
    """
    if not all([TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER, ALERT_PHONE_NUMBER]):
        print("⚠️ SMS alert skipped: Twilio credentials not configured")
        return False
    
    try:
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        
        # Create alert message based on risk level
        if score >= 85:
            message = (
                f"🚨 CRITICAL SECURITY ALERT\n"
                f"Risk Score: {score}/100\n"
                f"Email: {email}\n"
                f"Breaches: {breach_count}\n"
                f"Action: IMMEDIATE PASSWORD RESET REQUIRED"
            )
        else:  # score >= 60 (HIGH)
            message = (
                f"⚠️ HIGH RISK ALERT\n"
                f"Risk Score: {score}/100\n"
                f"Email: {email}\n"
                f"Breaches: {breach_count}\n"
                f"Action: Review and update credentials"
            )
        
        # Send SMS
        sms = client.messages.create(
            body=message,
            from_=TWILIO_PHONE_NUMBER,
            to=ALERT_PHONE_NUMBER
        )
        
        print(f"✅ SMS alert sent: {sms.sid}")
        return True
        
    except Exception as e:
        print(f"❌ SMS alert failed: {e}")
        return False


def send_email_alert(risk_level, score, email, breach_count, breaches_list=None):
    """
    Send email alert to molkyqwerty@gmail.com for high/critical risk detection
    
    Args:
        risk_level: Risk level string (e.g., "HIGH", "CRITICAL")
        score: Risk score (0-100)
        email: Email that triggered the alert
        breach_count: Number of breaches detected
        breaches_list: Optional list of breach details
    
    Returns:
        bool: True if email sent successfully, False otherwise
    """
    if not all([SMTP_EMAIL, SMTP_PASSWORD]):
        print("⚠️ Email alert skipped: SMTP credentials not configured")
        return False
    
    try:
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"🚨 {risk_level} Risk Alert - Dark Web Monitor"
        msg['From'] = SMTP_EMAIL
        msg['To'] = ALERT_EMAIL
        
        # Create HTML email body
        if score >= 85:
            alert_color = "#dc2626"
            alert_icon = "🚨"
            alert_title = "CRITICAL SECURITY ALERT"
            action_text = "IMMEDIATE ACTION REQUIRED"
        else:
            alert_color = "#f59e0b"
            alert_icon = "⚠️"
            alert_title = "HIGH RISK ALERT"
            action_text = "URGENT ACTION RECOMMENDED"
        
        # Build breach details HTML
        breach_details_html = ""
        if breaches_list and len(breaches_list) > 0:
            breach_details_html = "<h3>Recent Breaches:</h3><ul>"
            for breach in breaches_list[:10]:  # Show top 10
                breach_name = breach.get('breach_name', 'Unknown')
                breach_date = breach.get('breach_date', 'Unknown')
                data_exposed = breach.get('data_exposed', 'Unknown')
                breach_details_html += f"<li><strong>{breach_name}</strong> ({breach_date}) - {data_exposed}</li>"
            breach_details_html += "</ul>"
        
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .alert-box {{ background: {alert_color}; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
                .alert-title {{ font-size: 24px; font-weight: bold; margin-bottom: 10px; }}
                .metric {{ background: #f3f4f6; padding: 15px; border-radius: 6px; margin: 10px 0; }}
                .metric-label {{ font-size: 12px; color: #6b7280; text-transform: uppercase; }}
                .metric-value {{ font-size: 24px; font-weight: bold; color: #111827; }}
                .actions {{ background: #fef3c7; padding: 15px; border-radius: 6px; border-left: 4px solid #f59e0b; }}
                ul {{ padding-left: 20px; }}
                .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; font-size: 12px; color: #6b7280; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="alert-box">
                    <div class="alert-title">{alert_icon} {alert_title}</div>
                    <p>{action_text}</p>
                </div>
                
                <div class="metric">
                    <div class="metric-label">Risk Score</div>
                    <div class="metric-value">{score}/100 - {risk_level}</div>
                </div>
                
                <div class="metric">
                    <div class="metric-label">Affected Email</div>
                    <div class="metric-value">{email}</div>
                </div>
                
                <div class="metric">
                    <div class="metric-label">Total Breaches Detected</div>
                    <div class="metric-value">{breach_count}</div>
                </div>
                
                {breach_details_html}
                
                <div class="actions">
                    <h3>Recommended Actions:</h3>
                    <ul>
                        {"<li>Force password reset for all affected accounts immediately</li>" if score >= 85 else ""}
                        {"<li>Enable account isolation/blocking</li>" if score >= 85 else ""}
                        {"<li>Alert security team immediately</li>" if score >= 85 else ""}
                        <li>Review all recent account activity</li>
                        <li>Enable multi-factor authentication (MFA)</li>
                        <li>Monitor for suspicious login attempts</li>
                        {"<li>Consider credential rotation for related services</li>" if score >= 60 else ""}
                    </ul>
                </div>
                
                <div class="footer">
                    <p>Alert generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                    <p>This is an automated alert from Dark Web Monitor. Do not reply to this email.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Attach HTML content
        html_part = MIMEText(html, 'html')
        msg.attach(html_part)
        
        # Send email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.send_message(msg)
        
        print(f"✅ Email alert sent to {ALERT_EMAIL}")
        return True
        
    except Exception as e:
        print(f"❌ Email alert failed: {e}")
        return False


def send_combined_alert(risk_level, score, email, breach_count, breaches_list=None):
    """
    Send both SMS and email alerts for high/critical risk
    
    Args:
        risk_level: Risk level string (e.g., "HIGH", "CRITICAL")
        score: Risk score (0-100)
        email: Email that triggered the alert
        breach_count: Number of breaches detected
        breaches_list: Optional list of breach details
    
    Returns:
        dict: Status of SMS and email sending
    """
    results = {
        'sms_sent': False,
        'email_sent': False
    }
    
    # Only send alerts for HIGH (60+) or CRITICAL (85+) risk
    if score < 60:
        print(f"ℹ️ Risk score {score} below alert threshold (60). No alerts sent.")
        return results
    
    print(f"🚨 Triggering alerts for {risk_level} risk (score: {score})")
    
    # Send SMS alert
    results['sms_sent'] = send_sms_alert(risk_level, score, email, breach_count)
    
    # Send email alert
    results['email_sent'] = send_email_alert(risk_level, score, email, breach_count, breaches_list)
    
    return results


if __name__ == "__main__":
    # Test the alert service
    print("🧪 Testing Alert Service\n")
    
    # Test with HIGH risk
    print("Testing HIGH risk alert...")
    send_combined_alert(
        risk_level="HIGH",
        score=75,
        email="test@example.com",
        breach_count=5,
        breaches_list=[
            {'breach_name': 'Collection #1', 'breach_date': '2019-01-07', 'data_exposed': 'Email, Password'},
            {'breach_name': 'LinkedIn', 'breach_date': '2021-06-22', 'data_exposed': 'Email, Name, Phone'},
        ]
    )
    
    print("\n" + "="*50 + "\n")
    
    # Test with CRITICAL risk
    print("Testing CRITICAL risk alert...")
    send_combined_alert(
        risk_level="CRITICAL",
        score=92,
        email="admin@company.com",
        breach_count=12,
        breaches_list=[
            {'breach_name': 'Canary Trap Detected', 'breach_date': '2024-01-15', 'data_exposed': 'Email, Password, SSN'},
            {'breach_name': 'Collection #1', 'breach_date': '2019-01-07', 'data_exposed': 'Email, Password'},
        ]
    )
