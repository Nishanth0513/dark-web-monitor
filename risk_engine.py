from typing import List, Tuple
from models import Breach


def _score_single_breach(breach: Breach) -> int:
    data = (breach.data_exposed or "").lower()
    score = 0

    if "password" in data:
        score += 5
    if "financial" in data or "credit card" in data or "bank" in data:
        score += 10

    if score == 0:
        score = 1

    return score


def calculate_risk(breaches: List[Breach]) -> Tuple[int, str, int]:
    total_score = 0
    for b in breaches:
        total_score += _score_single_breach(b)

    if total_score == 0:
        level = "SAFE"
    elif 1 <= total_score <= 5:
        level = "MEDIUM"
    elif 6 <= total_score <= 15:
        level = "HIGH"
    else:
        level = "CRITICAL"

    percentage = min(100, total_score * 5)
    return total_score, level, percentage

