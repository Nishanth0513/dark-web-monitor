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

RAPIDAPI_KEY = os.getenv("RAPIDAPI_KEY")
RAPIDAPI_HOST = os.getenv("RAPIDAPI_HOST")
RAPIDAPI_EMAIL_URL_TEMPLATE = os.getenv("RAPIDAPI_EMAIL_URL_TEMPLATE")

canaries = ["admin_trap@company.com", "honeypot@test.com", "fake_ceo@company.com"]

def fetch_email_breaches(email):
    global _last_hibp_request_ts
    if not RAPIDAPI_KEY or not RAPIDAPI_HOST or not RAPIDAPI_EMAIL_URL_TEMPLATE:
        print("Error: RapidAPI email breach lookup is not configured.")
        print("Set RAPIDAPI_KEY, RAPIDAPI_HOST, and RAPIDAPI_EMAIL_URL_TEMPLATE in your environment.")
        return None

    headers = {
        "X-RapidAPI-Key": RAPIDAPI_KEY,
        "X-RapidAPI-Host": RAPIDAPI_HOST,
        "user-agent": "ZeroTrust-AI-Monitor",
    }

    try:
        now = time.time()
        wait_s = MIN_SECONDS_BETWEEN_REQUESTS - (now - _last_hibp_request_ts)
        if wait_s > 0:
            time.sleep(wait_s)

        url = RAPIDAPI_EMAIL_URL_TEMPLATE.format(email=email)
        response = requests.get(url, headers=headers, timeout=20)
        _last_hibp_request_ts = time.time()

        if response.status_code == 200:
            data = response.json()
            if data is None:
                return []
            if isinstance(data, list):
                return data
            breaches = data.get("breaches") if isinstance(data, dict) else None
            if isinstance(breaches, list):
                return breaches
            return data
        elif response.status_code == 404:
            return []
        elif response.status_code == 429:
            print("Rate limited by RapidAPI (429). Slow down requests.")
            return None
        elif response.status_code in (401, 403):
            print("Error: Unauthorized/Forbidden. Check your RapidAPI key and plan.")
            return None
        else:
            print(f"Error: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"Connection Error: {e}")
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
    print("1) Email breach check (RapidAPI key required)")
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

    print("Set RAPIDAPI_KEY / RAPIDAPI_HOST / RAPIDAPI_EMAIL_URL_TEMPLATE in your environment (or .env) before running email checks.")
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
