from datetime import datetime, timedelta
import random
from models import OrgEmail, OrgBreach, RiskHistory, ActivityLog, EmployeeRiskHistory
from risk_engine import calculate_risk
from enterprise_engine import calculate_eri
from alert_service import trigger_escalation, send_employee_alert_email

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

def run_enterprise_scheduler(db_sess, active_org):
    """
    Periodic background check (Enterprise context).
    Calculates scores, ERI, and triggers escalations.
    """
    employees = db_sess.query(OrgEmail).filter_by(org_id=active_org.id).all()
    if not employees:
        return

    any_new_high_risk = False
    
    for e in employees:
        # 1. Fetch/Simulate breaches
        breaches_data = simulate_breach_check(e.email)
        
        # 2. Update OrgBreach table
        employee_max_score = 0
        for b_data in breaches_data:
            existing = db_sess.query(OrgBreach).filter_by(
                org_id=active_org.id, 
                email=e.email, 
                breach_name=b_data['breach_name']
            ).first()
            
            # Mocking a Breach object for the engine
            from models import Breach
            mock_b = Breach(
                breach_name=b_data['breach_name'],
                breach_date=b_data['breach_date'],
                data_exposed=b_data['data_exposed']
            )
            score, level, is_canary = calculate_risk([mock_b], email=e.email, role=e.role)
            employee_max_score = max(employee_max_score, score)

            if not existing:
                new_b = OrgBreach(
                    org_id=active_org.id,
                    email=e.email,
                    breach_name=b_data['breach_name'],
                    breach_date=b_data['breach_date'],
                    data_exposed=b_data['data_exposed'],
                    severity=b_data['severity'],
                    score=score,
                    is_canary=is_canary
                )
                db_sess.add(new_b)
                
                # Log the evaluation
                db_sess.add(ActivityLog(
                    email=e.email,
                    action='breach_detected',
                    message=f"New breach '{b_data['breach_name']}' scored {score}/100",
                    severity='critical' if score >= 85 else 'warning' if score >= 60 else 'info'
                ))
                
                # Escalation trigger for individual high risk
                if score >= 60:
                    send_employee_alert_email(e.email, level, score, len(breaches_data))
                    
                if score >= 90:
                    trigger_escalation('PRIVILEGED_HIGH_RISK' if e.role in ['CEO', 'CTO', 'Admin'] else 'INDIVIDUAL_CRITICAL', 
                                      {'email': e.email, 'score': score, 'message': f"Critical breach for {e.role}"})
                if is_canary:
                    trigger_escalation('CANARY_TRIGGERED', {'email': e.email, 'message': "CANARY TRAP TRIPPED"})
        
        # Save per-employee risk history
        db_sess.add(EmployeeRiskHistory(
            org_id=active_org.id,
            email=e.email,
            score=employee_max_score,
            timestamp=datetime.utcnow()
        ))

    db_sess.commit()
    
    # 3. Calculate ERI
    org_breaches = db_sess.query(OrgBreach).filter_by(org_id=active_org.id).all()
    from models import RemediationAction
    remediation_tasks = db_sess.query(RemediationAction).all()
    
    eri_data = calculate_eri(employees, org_breaches, remediation_tasks)
    eri = eri_data['eri']
    
    # 4. Save Risk History
    history = RiskHistory(org_id=active_org.id, eri=eri)
    db_sess.add(history)
    
    # Log systemic evaluation
    db_sess.add(ActivityLog(
        action='systemic_risk_evaluation',
        message=f"Systemic Risk Evaluation: ERI={eri}, Label={eri_data['label']}",
        severity='critical' if eri >= 85 else 'warning' if eri >= 60 else 'info'
    ))
    
    # 5. Global Escalation
    if eri >= 85:
        trigger_escalation('ERI_CRITICAL', {'score': eri, 'message': f"Organization ERI is CRITICAL: {eri}"})
        
    db_sess.commit()
    print(f"✅ Scheduler run complete. ERI: {eri}")
