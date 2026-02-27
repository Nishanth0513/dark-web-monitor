#!/usr/bin/env python3
"""
Debug script to test alert service integration
"""

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Check all environment variables
print("🔍 Environment Variables Check:")
print("=" * 50)

# Check Twilio
twilio_sid = os.getenv("TWILIO_ACCOUNT_SID")
twilio_token = os.getenv("TWILIO_AUTH_TOKEN")
twilio_phone = os.getenv("TWILIO_PHONE_NUMBER")
alert_phone = os.getenv("YOUR_PHONE_NUMBER")

print(f"TWILIO_ACCOUNT_SID: {'✅ Set' if twilio_sid else '❌ Missing'}")
print(f"TWILIO_AUTH_TOKEN: {'✅ Set' if twilio_token else '❌ Missing'}")
print(f"TWILIO_PHONE_NUMBER: {'✅ Set' if twilio_phone else '❌ Missing'}")
print(f"YOUR_PHONE_NUMBER: {'✅ Set' if alert_phone else '❌ Missing'}")

# Check Email
alert_email = os.getenv("ALERT_EMAIL")
smtp_server = os.getenv("SMTP_SERVER")
smtp_port = os.getenv("SMTP_PORT")
smtp_email = os.getenv("SMTP_EMAIL")
smtp_password = os.getenv("SMTP_PASSWORD")

print(f"\nALERT_EMAIL: {alert_email}")
print(f"SMTP_SERVER: {smtp_server}")
print(f"SMTP_PORT: {smtp_port}")
print(f"SMTP_EMAIL: {smtp_email}")
print(f"SMTP_PASSWORD: {'✅ Set' if smtp_password else '❌ Missing'}")

print("\n" + "=" * 50)

# Test alert service directly
print("\n🧪 Testing Alert Service Directly:")
print("=" * 50)

try:
    from alert_service import send_combined_alert
    
    # Test HIGH risk alert
    print("Testing HIGH risk alert...")
    result = send_combined_alert(
        risk_level="HIGH",
        score=75,
        email="test@example.com",
        breach_count=5,
        breaches_list=[
            {'breach_name': 'Test Breach', 'breach_date': '2024-01-01', 'data_exposed': 'Email, Password'}
        ]
    )
    
    print(f"Results: {result}")
    print(f"SMS sent: {result.get('sms_sent')}")
    print(f"Email sent: {result.get('email_sent')}")
    
except Exception as e:
    print(f"❌ Error testing alert service: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 50)
print("📝 Debugging Tips:")
print("1. Check if ALERT_EMAIL is set in .env")
print("2. Verify SMTP credentials are correct")
print("3. Check console output for error messages")
print("4. Run 'python test_email.py' to test email only")
