from typing import List, Dict, Any
from datetime import datetime, timedelta
from models import OrgEmail, OrgBreach, RemediationAction
from risk_engine import ROLE_MULTIPLIERS, SOURCE_CATEGORIES

def calculate_eri(
    org_emails: List[OrgEmail],
    org_breaches: List[OrgBreach],
    remediation_tasks: List[RemediationAction]
) -> Dict[str, Any]:
    """
    Computes the Enterprise Risk Index (ERI) based on the senior engineer's mandatory formula.
    """
    total_accounts = len(org_emails)
    if total_accounts == 0:
        return {"eri": 0, "label": "SAFE", "metrics": {}}

    # Step 1 – Weighted Mean
    # Map roles and initialize scores
    email_to_role = {e.email: e.role for e in org_emails}
    email_to_max_score = {e.email: 0 for e in org_emails}
    
    # 7) Multiple breaches rule → take MAX score per email (already calculated in OrgBreach.score)
    for b in org_breaches:
        if b.email in email_to_max_score:
            email_to_max_score[b.email] = max(email_to_max_score[b.email], b.score)

    weighted_sum = 0
    total_weight = 0
    compromised_count = 0
    
    privileged_roles = ["CEO", "CTO", "CISO", "Admin", "Finance"]
    privileged_count = 0
    privileged_high_critical_count = 0
    has_any_high_privileged = False

    for email, score in email_to_max_score.items():
        role = email_to_role[email]
        weight = ROLE_MULTIPLIERS.get(role, 1.0)
        
        # 1) Use final individual score (after role multiplier applied)
        weighted_sum += (score * weight)
        total_weight += weight
        
        if score > 0:
            compromised_count += 1
            
        if role in privileged_roles:
            privileged_count += 1
            if score > 80:
                has_any_high_privileged = True
            if score >= 60: # High (60-84) or Critical (85-100)
                privileged_high_critical_count += 1

    weighted_mean = weighted_sum / total_weight if total_weight > 0 else 0

    # Step 2 – Compromise Density
    density = compromised_count / total_accounts
    density_multiplier = 1 + density

    # Step 3 – Privileged Exposure Amplifier
    privileged_bonus = 0
    if has_any_high_privileged:
        privileged_bonus = 10
    
    if privileged_count > 0 and (privileged_high_critical_count / privileged_count) > 0.20:
        privileged_bonus += 15

    # Step 4 – Critical Sector Amplifier
    critical_sector_bonus = 0
    critical_sectors = ["Banking/Finance", "Crypto", "Healthcare", "Government"]
    critical_breach_count = 0
    
    for b in org_breaches:
        name_lower = b.breach_name.lower()
        is_critical = False
        for keywords, _, sector_label in SOURCE_CATEGORIES:
            if sector_label in critical_sectors and any(kw in name_lower for kw in keywords):
                is_critical = True
                break
        if is_critical:
            critical_breach_count += 1
            
    if len(org_breaches) > 0 and (critical_breach_count / len(org_breaches)) > 0.30:
        critical_sector_bonus = 10

    # Step 5 – Remediation Penalty
    remediation_penalty = 0
    overdue_threshold = datetime.utcnow() - timedelta(days=7)
    pending_tasks = [t for t in remediation_tasks if t.status == 'pending']
    overdue_tasks = [t for t in pending_tasks if t.created_at < overdue_threshold]
    
    if len(remediation_tasks) > 0 and (len(overdue_tasks) / len(remediation_tasks)) > 0.25:
        remediation_penalty = 5

    # FINAL ORGANIZATION SCORE
    org_score_raw = (weighted_mean * density_multiplier) + privileged_bonus + critical_sector_bonus + remediation_penalty
    eri = min(100, org_score_raw)

    # RISK LABEL MAPPING
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
            "privileged_ratio": round((privileged_count / total_accounts) * 100, 2) if total_accounts > 0 else 0,
            "remediation_posture": round((1 - (len(pending_tasks) / len(remediation_tasks))) * 100, 2) if len(remediation_tasks) > 0 else 100
        }
    }
