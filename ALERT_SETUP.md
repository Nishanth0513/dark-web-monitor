# Alert System Setup Guide

## Overview
The Dark Web Monitor now includes automated SMS and email alerts that trigger when high or critical risk is detected.

## Alert Triggers
- **HIGH Risk (60-84 score)**: Sends SMS + Email alert
- **CRITICAL Risk (85+ score)**: Sends urgent SMS + Email alert

## Recipients
- **SMS**: Your phone number (configured in `.env`)
- **Email**: Always sent to `molkyqwerty@gmail.com`

---

## Setup Instructions

### 1. SMS Alerts (Twilio)

You already have Twilio configured! Your `.env` file should have:

```env
TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TWILIO_AUTH_TOKEN=your_auth_token_here
TWILIO_PHONE_NUMBER=+1xxxxxxxxxx
YOUR_PHONE_NUMBER=+91xxxxxxxxxx
```

✅ SMS alerts are ready to work!

---

### 2. Email Alerts (Gmail SMTP)

To enable email alerts, you need to add Gmail SMTP credentials to your `.env` file.

#### Step 1: Generate Gmail App Password

1. Go to your Google Account: https://myaccount.google.com/
2. Click **Security** in the left menu
3. Enable **2-Step Verification** (if not already enabled)
4. Go back to Security, scroll down to **App passwords**
5. Click **App passwords**
6. Select **Mail** and **Other (Custom name)**
7. Enter "Dark Web Monitor" as the name
8. Click **Generate**
9. Copy the 16-character password (e.g., `abcd efgh ijkl mnop`)

#### Step 2: Update `.env` File

Add these lines to your `.env` file:

```env
# SMTP Email Configuration (for email alerts)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_EMAIL=your_email@gmail.com
SMTP_PASSWORD=abcdefghijklmnop
```

Replace:
- `your_email@gmail.com` with your Gmail address
- `abcdefghijklmnop` with your 16-character app password (no spaces)

---

## Testing the Alert System

### Test 1: Run the standalone test script

```bash
python alert_service.py
```

This will:
- Send a test HIGH risk alert
- Send a test CRITICAL risk alert
- Show you what the SMS and email look like

### Test 2: Trigger alerts in the dashboard

1. Start the Streamlit app:
   ```bash
   streamlit run streamlit_app.py
   ```

2. Add an email that has breaches (e.g., `test@example.com`)

3. Run a manual scan

4. If the risk score is 60+, you'll see:
   - 🔔 Alert notification in the sidebar
   - SMS sent to your phone
   - Email sent to molkyqwerty@gmail.com

---

## Alert Email Format

The email includes:
- **Risk level** (HIGH or CRITICAL)
- **Risk score** (0-100)
- **Affected email**
- **Total breaches detected**
- **Top 10 breach details**
- **Recommended actions** based on risk level

---

## Alert SMS Format

**HIGH Risk:**
```
⚠️ HIGH RISK ALERT
Risk Score: 75/100
Email: test@example.com
Breaches: 5
Action: Review and update credentials
```

**CRITICAL Risk:**
```
🚨 CRITICAL SECURITY ALERT
Risk Score: 92/100
Email: admin@company.com
Breaches: 12
Action: IMMEDIATE PASSWORD RESET REQUIRED
```

---

## Troubleshooting

### SMS not sending?
- Check Twilio credentials in `.env`
- Verify phone numbers are in international format (+country code)
- Check Twilio account balance
- Run `python test_sms.py` to test

### Email not sending?
- Verify Gmail app password is correct (no spaces)
- Make sure 2-Step Verification is enabled on your Google account
- Check SMTP credentials in `.env`
- Try running `python alert_service.py` to see error messages

### Alerts not triggering?
- Risk score must be 60+ to trigger alerts
- Check that monitored emails have breaches
- Run a manual scan to update breach data
- Check console/terminal for error messages

---

## Security Notes

- ✅ `.env` file is in `.gitignore` (credentials won't be committed)
- ✅ Use Gmail app passwords (not your actual password)
- ✅ SMS uses Twilio's secure API
- ✅ Email alerts are sent via encrypted SMTP (TLS)

---

## What Happens When Alert Triggers

### Individual Dashboard
- Calculates risk score for your monitored emails
- If score ≥ 60, sends SMS + Email to you
- Shows alert status in sidebar

### Enterprise Dashboard
- Calculates organization risk score (average of all employees)
- If org score ≥ 60, sends SMS + Email
- Alert includes highest-risk employee email
- Shows alert status in sidebar

---

## Next Steps

1. ✅ Add SMTP credentials to `.env`
2. ✅ Test with `python alert_service.py`
3. ✅ Monitor your emails in the dashboard
4. ✅ Receive automatic alerts when risk is high!

Your alert system is now ready to protect you from dark web breaches! 🛡️
