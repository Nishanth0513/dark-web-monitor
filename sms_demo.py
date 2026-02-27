#!/usr/bin/env python3
"""
SMS Demo - Shows how the alert system would work
"""

def simulate_security_alert():
    """Simulate the security alert SMS"""
    
    your_phone = "+919014402965"
    message = (
        "🚨 SECURITY ALERT: Your account has been isolated due to suspicious activity. "
        "Please reset your password immediately to prevent permanent block. "
        "Visit: https://your-dashboard.com/reset"
    )
    
    print("📱 SMS Simulation:")
    print("=" * 50)
    print(f"To: {your_phone}")
    print(f"From: [Your Twilio Number]")
    print(f"Message: {message}")
    print("=" * 50)
    print("✅ This is what you would receive via SMS")
    print("✅ Ready to integrate once you have a Twilio number")

if __name__ == "__main__":
    simulate_security_alert()
