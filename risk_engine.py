from typing import List, Tuple, Optional
from datetime import datetime
from models import Breach


CANARY_EMAILS = [
    "admin_trap@company.com",
    "honeypot@test.com",
    "fake_ceo@company.com",
]

SOURCE_CATEGORIES = [
    (["bank", "finance", "fintech", "payment", "wallet"], 40, "Banking/Finance"),
    (["crypto", "bitcoin", "ethereum", "blockchain"], 40, "Crypto"),
    (["health", "medical", "hospital", "pharmacy"], 35, "Healthcare"),
    (["gov", "government", "federal", "ministry"], 35, "Government"),
    (["linkedin", "professional", "career", "work"], 30, "Professional"),
    (["amazon", "shop", "store", "retail", "ecommerce"], 20, "Shopping"),
    (["facebook", "twitter", "instagram", "social"], 20, "Social Media"),
    (["game", "gaming", "steam", "play", "xbox"], 10, "Gaming"),
    (["forum", "blog", "community", "board"], 5, "Forum/Blog"),
]

DATA_TYPE_SCORES = [
    (["password", "passwords"], 30),
    (["credit card", "credit cards", "card number"], 30),
    (["bank account", "account number"], 30),
    (["social security", "ssn", "national id"], 30),
    (["phone", "phone number", "mobile"], 20),
    (["address", "physical address", "street"], 15),
    (["date of birth", "dob", "birth date"], 15),
    (["email", "email address"], 10),
    (["username", "usernames"], 5),
    (["ip address", "ip addresses"], 5),
]


def _score_source_category(breach_name: str) -> int:
    """Factor 1: Source Category (Max 40 points)"""
    name_lower = breach_name.lower()
    for keywords, points, _ in SOURCE_CATEGORIES:
        if any(kw in name_lower for kw in keywords):
            return points
    return 15


def _score_data_types(data_exposed: str) -> int:
    """Factor 2: Data Types Exposed (Max 30 points)"""
    data_lower = data_exposed.lower()
    max_score = 0
    for keywords, points in DATA_TYPE_SCORES:
        if any(kw in data_lower for kw in keywords):
            max_score = max(max_score, points)
    return max_score


def _score_breach_age(breach_date: datetime) -> int:
    """Factor 3: Breach Age (Max 15 points)"""
    if not breach_date:
        return 1
    
    age_days = (datetime.utcnow() - breach_date).days
    age_months = age_days / 30.0
    
    if age_months <= 6:
        return 15
    elif age_months <= 12:
        return 12
    elif age_months <= 24:
        return 8
    elif age_months <= 48:
        return 4
    else:
        return 1


def _score_password_exposure(pwned_count: Optional[int]) -> int:
    """Factor 4: Password Exposed (Max 10 points)"""
    if pwned_count is None or pwned_count == 0:
        return 0
    elif pwned_count > 100:
        return 10
    elif pwned_count >= 10:
        return 7
    else:
        return 4


def _score_single_breach(
    breach: Breach,
    email: str,
    pwned_count: Optional[int] = None
) -> Tuple[int, bool]:
    """Calculate score for a single breach. Returns (score, is_canary_triggered)"""
    
    # Factor 5: Canary Override
    if email.lower() in [c.lower() for c in CANARY_EMAILS]:
        return 100, True
    
    # Factor 1: Source Category
    source_score = _score_source_category(breach.breach_name)
    
    # Factor 2: Data Types
    data_score = _score_data_types(breach.data_exposed or "")
    
    # Factor 3: Breach Age
    age_score = _score_breach_age(breach.breach_date)
    
    # Factor 4: Password Exposure
    pwd_score = _score_password_exposure(pwned_count)
    
    total = source_score + data_score + age_score + pwd_score
    return min(100, total), False


def calculate_risk(
    breaches: List[Breach],
    email: Optional[str] = None,
    pwned_count: Optional[int] = None
) -> Tuple[int, str, int]:
    """Calculate risk score for multiple breaches. Takes highest score."""
    
    if not breaches:
        return 0, "SAFE", 0
    
    max_score = 0
    canary_triggered = False
    
    for breach in breaches:
        score, is_canary = _score_single_breach(
            breach,
            email or breach.email,
            pwned_count
        )
        if is_canary:
            return 100, "CRITICAL — INTERNAL LEAK DETECTED", 100
        max_score = max(max_score, score)
    
    # Map score to risk level
    if max_score >= 85:
        level = "CRITICAL"
    elif max_score >= 60:
        level = "HIGH"
    elif max_score >= 35:
        level = "MEDIUM"
    elif max_score >= 1:
        level = "LOW"
    else:
        level = "SAFE"
    
    return max_score, level, max_score

