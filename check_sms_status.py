#!/usr/bin/env python3
"""
Check SMS delivery status in Twilio
"""

import os
from twilio.rest import Client
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Your credentials from .env file
ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")

def check_message_status(message_sid):
    """Check the delivery status of a specific message"""
    
    client = Client(ACCOUNT_SID, AUTH_TOKEN)
    
    try:
        message = client.messages(message_sid).fetch()
        
        print("📊 SMS Delivery Status:")
        print("=" * 40)
        print(f"Message SID: {message.sid}")
        print(f"Status: {message.status}")
        print(f"From: {message.from_}")
        print(f"To: {message.to}")
        print(f"Date Created: {message.date_created}")
        print(f"Date Sent: {message.date_sent}")
        print(f"Date Updated: {message.date_updated}")
        print(f"Error Code: {message.error_code}")
        print(f"Error Message: {message.error_message}")
        print("=" * 40)
        
        # Status meanings
        status_meanings = {
            "queued": "Message is queued to be sent",
            "sending": "Message is being sent",
            "sent": "Message was sent to carrier",
            "delivered": "Message was delivered to recipient",
            "undelivered": "Message was not delivered",
            "failed": "Message failed to send",
            "received": "Message was received (for inbound)"
        }
        
        print(f"Status Meaning: {status_meanings.get(message.status, 'Unknown status')}")
        
        if message.error_code:
            print(f"⚠️ Error Details: {message.error_message}")
        
        return message.status
        
    except Exception as e:
        print(f"❌ Error checking status: {e}")
        return None

if __name__ == "__main__":
    # Use the new message SID from your test
    message_sid = "SM40a5eacbeca81e4668283a0c8c501e12"
    
    print("🔍 Checking SMS delivery status...")
    status = check_message_status(message_sid)
    
    if status == "delivered":
        print("✅ SMS was delivered to carrier")
        print("💡 If you still didn't receive it, check:")
        print("   - Phone's SMS inbox (including spam folder)")
        print("   - DND (Do Not Disturb) registration")
        print("   - Carrier SMS filtering")
    elif status == "sent":
        print("📤 SMS was sent to carrier, awaiting delivery")
        print("⏳ Please wait a few more minutes")
    elif status in ["failed", "undelivered"]:
        print("❌ SMS delivery failed")
        print("🔧 Try a different approach:")
        print("   - Use an Indian Twilio number")
        print("   - Check recipient number format")
        print("   - Verify recipient's carrier supports international SMS")
