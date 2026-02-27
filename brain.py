import requests
import time
import os
import hashlib

try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None

if load_dotenv is not None:
    load_dotenv(".env")
    load_dotenv(".env.example")

HIBP_API_KEY = os.getenv("HIBP_API_KEY")
BASE_URL = "https://haveibeenpwned.com/api/v3/breachedaccount"
MIN_SECONDS_BETWEEN_REQUESTS = 1.6
_last_hibp_request_ts = 0.0

canaries = ["admin_trap@company.com", "honeypot@test.com", "fake_ceo@company.com"]

def fetch_email_breaches(email):
    try:
        url = f"https://leakcheck.io/api/public?check={email}"
        response = requests.get(url, timeout=15)
        if response.status_code != 200:
            print(f"Error: {response.status_code} - {response.text}")
            return None

        data = response.json()
        if not isinstance(data, dict):
            return None

        if data.get("success") and data.get("found", 0) > 0:
            sources = data.get("sources", [])
            breaches = []
            if isinstance(sources, list):
                for src in sources:
                    if isinstance(src, dict):
                        src_name = src.get("name") or "Unknown"
                        src_date = src.get("date") or "Unknown"
                    else:
                        src_name = str(src)
                        src_date = "Unknown"
                    breaches.append({
                        "Name": str(src_name),
                        "DataClasses": ["Email"],
                        "Source": "LeakCheck",
                        "BreachDate": str(src_date),
                    })
            return breaches

        return []
    except requests.exceptions.RequestException as e:
        print("Connection error:", e)
        return None


def fetch_real_breaches(email):
    return fetch_email_breaches(email)

def calculate_live_risk(email, breaches, canary_list):
    if email in canary_list:
        return 100, "CRITICAL: Canary/Honeypot Triggered"

    if not breaches:
        return 0, "Safe"

    max_score = 0
    reason = "Low Risk"

    for breach in breaches:
        data_classes = breach.get('DataClasses', [])
        
        if "Passwords" in data_classes:
            current_score = 85
            current_reason = f"High Risk: Password leaked in {breach['Name']}"
        else:
            current_score = 30
            current_reason = "Medium Risk: Non-sensitive data leaked"

        if current_score > max_score:
            max_score = current_score
            reason = current_reason

    return max_score, reason

def calculate_risk(email, breach_data):
    if email in canaries:
        return 100
    
    if "Passwords" in breach_data.get("DataClasses", []):
        return 85
    
    return 30


def pwned_password_count(password):
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {
        "user-agent": "ZeroTrust-AI-Monitor",
        "Add-Padding": "true",
    }
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code != 200:
            print(f"Error: {response.status_code} - {response.text}")
            return None
        for line in response.text.splitlines():
            parts = line.split(":")
            if len(parts) != 2:
                continue
            returned_suffix, count_str = parts[0].strip().upper(), parts[1].strip()
            if returned_suffix == suffix:
                try:
                    return int(count_str)
                except Exception:
                    return None
        return 0
    except Exception as e:
        print(f"Connection Error: {e}")
        return None


if __name__ == "__main__":
    print("=== Backend Smoke Test (No Dashboard) ===")
    print("1) Email breach check (LeakCheck public API)")
    print("2) Password pwned check (no API key required)")
    mode = input("Choose (1/2): ").strip()

    if mode == "2":
        pwd = input("Enter password to check: ")
        count = pwned_password_count(pwd)
        if count is None:
            raise SystemExit("Password check failed")
        if count > 0:
            print(f"Pwned: YES ({count} times)")
        else:
            print("Pwned: NO")
        raise SystemExit(0)

    test_email = input("Enter email to check: ").strip()
    if not test_email:
        raise SystemExit("No email entered")

    print("\nFetching breach data...")
    breaches = fetch_email_breaches(test_email)

    if breaches is None:
        raise SystemExit("Request failed (see errors above)")

    score, reason = calculate_live_risk(test_email, breaches, canaries)
    print(f"\nRisk Score: {score}/100")
    print(f"Reason: {reason}")
    print(f"Breaches Found: {len(breaches)}")

    if breaches:
        print("\nFirst few breaches:")
        for breach in breaches[:5]:
            name = breach.get("Name", "Unknown")
            breach_date = breach.get("BreachDate", "Unknown")
            print(f"- {name} ({breach_date})")
