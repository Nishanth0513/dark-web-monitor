#!/usr/bin/env python3
"""
Standalone SMS test script using Twilio
NOT integrated with main application - for testing only
"""

import os
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Your Twilio credentials (from .env file)
ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.getenv("TWILIO_PHONE_NUMBER")
YOUR_PHONE_NUMBER = os.getenv("YOUR_PHONE_NUMBER")

def send_security_alert_sms():
    """Send a test security alert SMS"""
    
    try:
        # Initialize Twilio client
        client = Client(ACCOUNT_SID, AUTH_TOKEN)
        
        # Security alert message (shorter format)
        message_body = "SECURITY ALERT: Account isolated. Reset password now: https://your-dashboard.com/reset"
        
        # Send SMS
        message = client.messages.create(
            body=message_body,
            from_=TWILIO_PHONE_NUMBER,
            to=YOUR_PHONE_NUMBER
        )
        
        print(f"✅ SMS sent successfully!")
        print(f"Message SID: {message.sid}")
        print(f"From: {TWILIO_PHONE_NUMBER}")
        print(f"To: {YOUR_PHONE_NUMBER}")
        print(f"Message: {message_body}")
        
        return True
        
    except TwilioRestException as e:
        print(f"❌ Twilio Error: {e}")
        return False
    except Exception as e:
        print(f"❌ General Error: {e}")
        return False

def test_twilio_connection():
    """Test Twilio connection and account info"""
    
    try:
        client = Client(ACCOUNT_SID, AUTH_TOKEN)
        account = client.api.accounts(ACCOUNT_SID).fetch()
        
        print(f"✅ Connected to Twilio successfully!")
        print(f"Account SID: {account.sid}")
        print(f"Account Status: {account.status}")
        print(f"Date Created: {account.date_created}")
        
        # List available phone numbers
        incoming_numbers = client.incoming_phone_numbers.list(limit=5)
        print(f"\n📞 Available Twilio Numbers:")
        for number in incoming_numbers:
            print(f"  - {number.phone_number} ({number.friendly_name})")
        
        if not incoming_numbers:
            print("  No Twilio numbers found. You need to buy a number from Twilio console.")
        
        return True
        
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return False

if __name__ == "__main__":
    print("🧪 Twilio SMS Test Script")
    print("=" * 50)
    
    # Test connection first
    print("\n1. Testing Twilio connection...")
    if not test_twilio_connection():
        print("\n❌ Cannot proceed with SMS test - connection failed")
        exit(1)
    
    # Send test SMS
    print("\n2. Sending security alert SMS...")
    if send_security_alert_sms():
        print("\n🎉 SMS test completed successfully!")
    else:
        print("\n❌ SMS test failed!")
    
    print("\n" + "=" * 50)
    print("📝 Notes:")
    print("- Make sure you have a Twilio phone number")
    print("- Replace YOUR_PHONE_NUMBER with your actual number")
    print("- Replace TWILIO_PHONE_NUMBER with your Twilio number")
    print("- Check your Twilio account balance")
    
    print("\n🔧 Troubleshooting:")
    print("❌ If you see 'Authenticate' error:")
    print("   1. Check ACCOUNT_SID is correct (starts with 'AC')")
    print("   2. Check AUTH_TOKEN is correct (from Twilio Console)")
    print("   3. Make sure your Twilio account is active")
    
    print("❌ If you see 'From/To number not valid' error:")
    print("   1. YOUR_PHONE_NUMBER must be in international format (+country+number)")
    print("   2. TWILIO_PHONE_NUMBER must be your Twilio number")
    print("   3. Verify your Twilio number can SMS to your country")
    
    print("❌ If you see 'insufficient funds' error:")
    print("   1. Add funds to your Twilio account")
    print("   2. Check your Twilio balance at console.twilio.com")
    
    print("\n📱 Twilio Console: https://console.twilio.com")
    print("📞 Buy Number: https://www.twilio.com/console/phone-numbers/search")
