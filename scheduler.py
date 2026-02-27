from datetime import datetime
import random


def simulate_breach_check(email: str):
    """
    Mock breach check for demo.
    Returns a list of breach dicts with keys:
    breach_name, breach_date, data_exposed, severity
    """
    random.seed(email + datetime.utcnow().strftime("%Y-%m-%d"))
    possible = []

    if random.random() < 0.6:
        possible.append(
            {
                "breach_name": "Credential Dump #A",
                "breach_date": datetime(2023, 5, 10),
                "data_exposed": "Email addresses, passwords",
                "severity": "HIGH",
            }
        )

    if random.random() < 0.3:
        possible.append(
            {
                "breach_name": "Card Skimming Incident",
                "breach_date": datetime(2024, 2, 2),
                "data_exposed": "Email addresses, financial data, credit cards",
                "severity": "CRITICAL",
            }
        )

    if random.random() < 0.4:
        possible.append(
            {
                "breach_name": "Marketing List Exposure",
                "breach_date": datetime(2022, 8, 1),
                "data_exposed": "Email addresses",
                "severity": "MEDIUM",
            }
        )

    return possible

