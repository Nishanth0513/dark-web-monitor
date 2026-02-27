from typing import List, Dict, Any
from models import OrgEmail, OrgBreach, RemediationAction
from risk_engine import ROLE_MULTIPLIERS

def calculate_eri(
    org_emails: List[OrgEmail],
    org_breaches: List[OrgBreach],
    remediation_tasks: List[RemediationAction]
) -> Dict[str, Any]:
    """
    Computes the Enterprise Risk Index (ERI) based on the mandatory formula.
    """
    total_emails = len(org_emails)
    if total_emails == 0:
        return {"eri": 0, "label": "SAFE", "metrics": {}}

    # 1. Individual Risk Scores & Weighted Risk Mean
    # Map breaches to emails
    email_to_max_score = {e.email: 0 for e in org_emails}
    email_to_role = {e.email: e.role for e in org_emails}
    
    for b in org_breaches:
        if b.email in email_to_max_score:
            email_to_max_score[b.email] = max(email_to_max_score[b.email], b.score)

    # Role Weights (CEO/CTO/CISO = 1.5, etc.)
    weighted_sum = 0
    total_weight = 0
    privileged_count = 0
    privileged_high_risk_count = 0
    compromised_count = 0
    critical_sector_breaches = 0

    privileged_roles = ["CEO", "CTO", "CISO", "Admin", "Finance"]

    for email, score in email_to_max_score.items():
        role = email_to_role[email]
        weight = ROLE_MULTIPLIERS.get(role, 1.0)
        
        weighted_sum += (score * weight)
        total_weight += weight
        
        if score > 0:
            compromised_count += 1
            
        if role in privileged_roles:
            privileged_count += 1
            if score > 80:
                privileged_high_risk_count += 1

    weighted_mean = weighted_sum / total_weight if total_weight > 0 else 0

    # 2. Privileged Exposure Amplifier
    privileged_bonus = 0
    # If any privileged account > 80 -> +10
    has_any_high_privileged = any(
        email_to_max_score[e.email] > 80 
        for e in org_emails if e.role in privileged_roles
    )
    if has_any_high_privileged:
        privileged_bonus += 10
    
    # If >20% privileged are High/Critical -> +15
    if privileged_count > 0 and (privileged_high_risk_count / privileged_count) > 0.20:
        privileged_bonus += 15

    # 3. Compromise Density Multiplier
    density = compromised_count / total_emails
    density_multiplier = 1 + density

    # 4. Critical Sector Amplifier
    # Banking/Crypto (40), Healthcare/Government (35)
    critical_categories = ["Banking/Finance", "Crypto", "Healthcare", "Government"]
    # We need to know the category of each breach. 
    # For now, let's assume breach.severity captures this or we check names.
    # In a real implementation, we'd store the category in OrgBreach.
    # Let's count breaches that have high scores (indicative of critical sectors in our model).
    critical_breach_count = sum(1 for b in org_breaches if b.score >= 35) 
    if len(org_breaches) > 0 and (critical_breach_count / len(org_breaches)) > 0.30:
        critical_sector_bonus = 10
    else:
        critical_sector_bonus = 0

    # 5. Remediation Delay Penalty
    # If >25% tasks overdue -> +5
    # For this demo, let's assume 'pending' tasks older than 7 days are 'overdue'
    from datetime import datetime, timedelta
    overdue_threshold = datetime.utcnow() - timedelta(days=7)
    pending_tasks = [t for t in remediation_tasks if t.status == 'pending']
    overdue_tasks = [t for t in pending_tasks if t.created_at < overdue_threshold]
    
    remediation_penalty = 0
    if len(remediation_tasks) > 0 and (len(overdue_tasks) / len(remediation_tasks)) > 0.25:
        remediation_penalty = 5

    # Final ERI Calculation
    eri_raw = (weighted_mean * density_multiplier) + privileged_bonus + critical_sector_bonus + remediation_penalty
    eri = min(100, eri_raw)

    # ERI Labels
    if eri >= 85:
        label = "CRITICAL"
    elif eri >= 60:
        label = "HIGH"
    elif eri >= 35:
        label = "ELEVATED"
    elif eri >= 1:
        label = "LOW"
    else:
        label = "SAFE"

    return {
        "eri": round(eri, 2),
        "label": label,
        "metrics": {
            "weighted_mean": round(weighted_mean, 2),
            "density": round(density * 100, 2),
            "privileged_ratio": round((privileged_count / total_emails) * 100, 2) if total_emails > 0 else 0,
            "remediation_posture": round((1 - (len(pending_tasks) / len(remediation_tasks))) * 100, 2) if len(remediation_tasks) > 0 else 100
        }
    }
