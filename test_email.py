#!/usr/bin/env python3
"""
Quick test for email alerts
"""

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Check if SMTP credentials are configured
smtp_email = os.getenv("SMTP_EMAIL")
smtp_password = os.getenv("SMTP_PASSWORD")

print("🔍 Email Configuration Check:")
print("=" * 40)

if not smtp_email:
    print("❌ SMTP_EMAIL not set in .env")
    print("   Add: SMTP_EMAIL=your_email@gmail.com")
elif smtp_email == "your_email@gmail.com":
    print("⚠️  SMTP_EMAIL is still the placeholder")
    print("   Replace with your actual Gmail address")
else:
    print(f"✅ SMTP_EMAIL: {smtp_email}")

if not smtp_password:
    print("❌ SMTP_PASSWORD not set in .env")
    print("   Add: SMTP_PASSWORD=your_16_char_app_password")
elif smtp_password == "your_16_char_app_password_here":
    print("⚠️  SMTP_PASSWORD is still the placeholder")
    print("   Replace with your actual Gmail app password")
else:
    print(f"✅ SMTP_PASSWORD: {'*' * len(smtp_password)}")

print("\n" + "=" * 40)

if smtp_email and smtp_password and smtp_email != "your_email@gmail.com" and smtp_password != "your_16_char_app_password_here":
    print("✅ Email configuration looks good!")
    print("\n📧 Testing email alert...")
    
    try:
        from alert_service import send_email_alert
        
        # Test email alert
        result = send_email_alert(
            risk_level="HIGH",
            score=75,
            email="test@example.com",
            breach_count=5,
            breaches_list=[
                {'breach_name': 'Test Breach', 'breach_date': '2024-01-01', 'data_exposed': 'Email, Password'}
            ]
        )
        
        if result:
            print("✅ Test email sent successfully to molkyqwerty@gmail.com")
        else:
            print("❌ Test email failed")
            
    except Exception as e:
        print(f"❌ Error sending test email: {e}")
        print("\nTroubleshooting:")
        print("1. Make sure 2-Step Verification is enabled on your Google account")
        print("2. Generate a new App password from Google Account settings")
        print("3. Use the 16-character password without spaces")
else:
    print("⚠️  Please update your .env file with actual SMTP credentials")
    print("\nSteps:")
    print("1. Go to https://myaccount.google.com/security")
    print("2. Enable 2-Step Verification")
    print("3. Click 'App passwords'")
    print("4. Generate password for Mail app")
    print("5. Update .env with your credentials")
