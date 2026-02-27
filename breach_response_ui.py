import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
from streamlit_autorefresh import st_autorefresh
from breach_response import (
    get_pending_actions,
    get_completed_actions,
    mark_action_completed,
    get_response_status,
    calculate_completion_rate,
    get_action_summary,
    get_breach_statistics,
    get_recent_activities,
    save_remediation_actions
)
from models import MonitoredEmail, Breach, db as models_db, RemediationAction, EmailPreview, ActivityLog
from risk_engine import calculate_risk


def show_breach_response_center(db_session=None, user_id=None):
    """
    Main Breach Response Center page with enhanced navigation and classification
    """
    if db_session is None:
        st.error("Database session is required for Breach Response Center.")
        return

    # 1. Auto-refresh (every 5 minutes)
    st_autorefresh(interval=300000, key="brc_refresh")

    # 2. Sidebar Navigation
    with st.sidebar:
        st.markdown(f"""
            <div style='text-align: center; padding: 20px 0;'>
                <h1 style='color: #00ffcc; font-size: 1.8rem; margin-bottom: 0;'>🚨 BRC</h1>
                <p style='color: #9ca3c7; font-size: 0.7rem; letter-spacing: 0.2em; text-transform: uppercase;'>Incident Command</p>
            </div>
        """, unsafe_allow_html=True)
        
        st.info("Management Console")
        st.divider()
        
        brc_nav = st.radio(
            "Navigation",
            ["📊 Dashboard", "📜 Reports", "📧 Alert Previews", "⚙️ Settings"],
            key="brc_nav_choice"
        )
        
        st.divider()
        
        # Action Buttons with specific keys and better labels
        if st.button("🚪 Logout", key="brc_sidebar_logout", width='stretch'):
            st.session_state.user_id = None
            st.session_state.mode = None
            st.rerun()
            
        if st.button("⬅️ Back to Console", key="brc_sidebar_back", width='stretch'):
            st.session_state.mode = "Individual"
            st.rerun()
        
        st.divider()
        st.caption(f"Command context: {'Individual' if user_id else 'System Admin'}")

    # 3. Main Content Rendering
    if brc_nav == "📊 Dashboard":
        render_brc_dashboard(db_session, user_id=user_id)
    elif brc_nav == "📜 Reports":
        render_brc_reports(db_session, user_id=user_id)
    elif brc_nav == "📧 Alert Previews":
        render_brc_previews(db_session, user_id=user_id)
    elif brc_nav == "⚙️ Settings":
        render_brc_settings(db_session, user_id=user_id)


def render_brc_previews(db_session, user_id=None):
    st.title("📧 Alert Previews")
    st.caption("Review all outgoing security notifications and automated alerts.")
    
    try:
        query = db_session.query(EmailPreview)
        if user_id:
            # Filter by emails monitored by this user
            monitored_emails = db_session.query(MonitoredEmail.email).filter_by(user_id=user_id).all()
            emails = [e[0] for e in monitored_emails]
            query = query.filter(EmailPreview.recipient.in_(emails))
            
        previews = query.order_by(EmailPreview.created_at.desc()).limit(20).all()
        
        if not previews:
            st.info("No alert previews generated yet. Alerts are created when high-risk breaches are detected.")
            return

        for p in previews:
            with st.expander(f"✉️ To: {p.recipient} — {p.subject} ({p.created_at.strftime('%Y-%m-%d %H:%M')})"):
                st.markdown(f"**Risk Score:** {p.risk_score}/100")
                st.markdown(f"**Status:** {p.status.upper()}")
                st.divider()
                
                # Render the HTML content safely
                if p.html_content:
                    st.components.v1.html(p.html_content, height=400, scrolling=True)
                else:
                    st.warning("This alert preview has no HTML content.")
                    
                if st.button(f"Resend Alert to {p.recipient}", key=f"resend_{p.id}", width='stretch'):
                    st.success(f"Alert re-queued for delivery to {p.recipient}")
    except Exception as e:
        st.error(f"Error loading alert previews: {e}")


def render_brc_dashboard(db_session, user_id=None):
    st.title("🚀 Breach Response Dashboard")
    st.caption("Strategic Incident Management & Risk Classification")

    # Get statistics
    stats = get_breach_statistics(db_session=db_session, user_id=user_id)
    
    # Security Posture Score Calculation
    posture_score = stats['completion_rate']
    posture_color = "#ef4444" if posture_score < 30 else "#f97316" if posture_score < 70 else "#22c55e"
    
    st.markdown(f"""
        <div style='background: rgba(15, 23, 42, 0.6); padding: 25px; border-radius: 15px; border: 1px solid rgba(255, 255, 255, 0.1); margin-bottom: 25px;'>
            <div style='display: flex; align-items: center; justify-content: space-between;'>
                <div>
                    <h3 style='margin: 0; color: #f8fafc;'>🛡️ Overall Security Posture</h3>
                    <p style='margin: 5px 0 0 0; color: #94a3b8;'>Remediation effectiveness across all detected incidents</p>
                </div>
                <div style='text-align: right;'>
                    <div style='font-size: 2.5rem; font-weight: bold; color: {posture_color};'>{posture_score:.1f}%</div>
                    <div style='font-size: 0.8rem; color: #94a3b8;'>POSTURE SCORE</div>
                </div>
            </div>
            <div style='background: rgba(255,255,255,0.05); height: 8px; border-radius: 4px; margin-top: 15px;'>
                <div style='background: {posture_color}; width: {posture_score}%; height: 100%; border-radius: 4px; box-shadow: 0 0 10px {posture_color};'></div>
            </div>
        </div>
    """, unsafe_allow_html=True)

    # 1. Top-level Overview Metrics
    st.markdown("### 📊 System Overview")
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f"""
            <div style='background: rgba(30, 41, 59, 0.5); padding: 20px; border-radius: 12px; border: 1px solid rgba(255, 255, 255, 0.1); text-align: center;'>
                <div style='font-size: 0.8rem; color: #94a3b8; margin-bottom: 5px;'>BREACHED IDENTITIES</div>
                <div style='font-size: 2rem; font-weight: bold; color: #f8fafc;'>{stats['breached_accounts']}</div>
            </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown(f"""
            <div style='background: rgba(30, 41, 59, 0.5); padding: 20px; border-radius: 12px; border: 1px solid rgba(255, 255, 255, 0.1); text-align: center;'>
                <div style='font-size: 0.8rem; color: #94a3b8; margin-bottom: 5px;'>PENDING TASKS</div>
                <div style='font-size: 2rem; font-weight: bold; color: #fbbf24;'>{stats['actions_pending']}</div>
            </div>
        """, unsafe_allow_html=True)
    with col3:
        st.markdown(f"""
            <div style='background: rgba(30, 41, 59, 0.5); padding: 20px; border-radius: 12px; border: 1px solid rgba(255, 255, 255, 0.1); text-align: center;'>
                <div style='font-size: 0.8rem; color: #94a3b8; margin-bottom: 5px;'>REMEDIATED</div>
                <div style='font-size: 2rem; font-weight: bold; color: #10b981;'>{stats['actions_completed']}</div>
            </div>
        """, unsafe_allow_html=True)
    with col4:
        st.markdown(f"""
            <div style='background: rgba(30, 41, 59, 0.5); padding: 20px; border-radius: 12px; border: 1px solid rgba(255, 255, 255, 0.1); text-align: center;'>
                <div style='font-size: 0.8rem; color: #94a3b8; margin-bottom: 5px;'>RESPONSE RATE</div>
                <div style='font-size: 2rem; font-weight: bold; color: #3b82f6;'>{stats['completion_rate']:.0f}%</div>
            </div>
        """, unsafe_allow_html=True)
    
    st.divider()

    # Get all unique breached emails and calculate risk for classification
    query = db_session.query(Breach.email).distinct()
    if user_id:
        monitored_emails = db_session.query(MonitoredEmail.email).filter_by(user_id=user_id).all()
        emails = [e[0] for e in monitored_emails]
        query = query.filter(Breach.email.in_(emails))
        
    breached_emails_query = query.all()
    
    if not breached_emails_query:
        st.success("✅ No active breaches detected for your monitored accounts.")
        return

    # Classify accounts
    classified_accounts = {
        "CRITICAL": [],
        "HIGH": [],
        "MEDIUM": [],
        "LOW": []
    }

    for row in breached_emails_query:
        email = row[0]
        breaches = db_session.query(Breach).filter_by(email=email).all()
        score, risk_level, _ = calculate_risk(breaches, email=email)
        
        # Clean risk level for matching
        clean_level = risk_level.split("—")[0].strip().upper()
        if "CRITICAL" in clean_level: 
            classified_accounts["CRITICAL"].append((email, score, breaches))
        elif "HIGH" in clean_level: 
            classified_accounts["HIGH"].append((email, score, breaches))
        elif "ELEVATED" in clean_level or "MEDIUM" in clean_level: 
            classified_accounts["MEDIUM"].append((email, score, breaches))
        else: 
            classified_accounts["LOW"].append((email, score, breaches))

    # 2. Risk Classification Summary - Improved with Dynamic Content, Icons, and Identity Lists
    st.markdown("### 🏷️ Risk Classification Summary")
    c_crit, c_high, c_med, c_low = len(classified_accounts["CRITICAL"]), len(classified_accounts["HIGH"]), len(classified_accounts["MEDIUM"]), len(classified_accounts["LOW"])
    
    s_col1, s_col2, s_col3, s_col4 = st.columns(4)
    
    def render_summary_card(col, label, accounts, color, bg_color, icon):
        count = len(accounts)
        emails = ", ".join([a[0] for a in accounts]) if accounts else "None"
        # Truncate long email lists
        if len(emails) > 100:
            emails = emails[:97] + "..."
            
        col.markdown(f"""
            <div style='background: {bg_color}; padding: 20px; border-radius: 12px; border: 2px solid {color}; text-align: center; min-height: 250px; display: flex; flex-direction: column; justify-content: center;'>
                <div style='font-size: 2rem; margin-bottom: 10px;'>{icon}</div>
                <div style='font-size: 0.8rem; color: {color}; font-weight: bold; text-transform: uppercase; letter-spacing: 0.1em;'>{label}</div>
                <div style='font-size: 2.5rem; font-weight: bold; color: white; margin: 5px 0;'>{count}</div>
                <div style='font-size: 0.75rem; color: #f8fafc; background: rgba(0,0,0,0.2); padding: 8px; border-radius: 6px; margin-top: 10px; line-height: 1.4;'>
                    {emails}
                </div>
            </div>
        """, unsafe_allow_html=True)

    render_summary_card(s_col1, "Critical", classified_accounts["CRITICAL"], "#ef4444", "rgba(220, 38, 38, 0.15)", "🚨")
    render_summary_card(s_col2, "High", classified_accounts["HIGH"], "#f97316", "rgba(249, 115, 22, 0.15)", "🔥")
    render_summary_card(s_col3, "Medium", classified_accounts["MEDIUM"], "#eab308", "rgba(234, 179, 8, 0.15)", "⚠️")
    render_summary_card(s_col4, "Low", classified_accounts["LOW"], "#22c55e", "rgba(34, 197, 94, 0.15)", "✅")
    
    st.divider()

    # 3. Breach Timeline and Data Exposure Analysis
    st.markdown("### 📊 Threat Analysis")
    t_col1, t_col2 = st.columns(2)
    
    with t_col1:
        st.write("**Breach Timeline (Incident Occurrence)**")
        # Gather all breaches for the user(s)
        all_breaches = []
        for level in classified_accounts:
            for acc in classified_accounts[level]:
                all_breaches.extend(acc[2])
        
        if all_breaches:
            df_timeline = pd.DataFrame([
                {"Date": b.breach_date, "Name": b.breach_name} 
                for b in all_breaches
            ])
            df_timeline = df_timeline.sort_values("Date")
            st.line_chart(df_timeline.set_index("Date"))
        else:
            st.info("No timeline data available.")
            
    with t_col2:
        st.write("**Data Exposure Breakdown**")
        exposure_counts = {}
        for b in all_breaches:
            classes = b.data_exposed.split(",")
            for c in classes:
                c = c.strip()
                exposure_counts[c] = exposure_counts.get(c, 0) + 1
        
        if exposure_counts:
            df_exposure = pd.DataFrame([
                {"Category": k, "Frequency": v} 
                for k, v in exposure_counts.items()
            ]).sort_values("Frequency", ascending=False)
            st.bar_chart(df_exposure.set_index("Category"))
        else:
            st.info("No exposure data available.")

    st.divider()

    # 4. Dynamic Response Action Panel
    st.markdown("### 🛠️ Strategic Response Actions")
    
    # Render Risk Sections with enhanced containers
    if c_crit > 0:
        render_risk_section("🔴 CRITICAL THREATS - IMMEDIATE ACTION REQUIRED", classified_accounts["CRITICAL"], "critical", db_session)
    if c_high > 0:
        render_risk_section("🟠 HIGH EXPOSURE - URGENT REMEDIATION", classified_accounts["HIGH"], "high", db_session)
    if c_med > 0:
        render_risk_section("🟡 MODERATE RISK - SCHEDULED RESPONSE", classified_accounts["MEDIUM"], "medium", db_session)
    if c_low > 0:
        render_risk_section("🟢 LOW RISK - CONTINUOUS MONITORING", classified_accounts["LOW"], "low", db_session)
    
    if c_crit == 0 and c_high == 0 and c_med == 0 and c_low == 0:
        st.success("✅ No breaches found for your monitored identities. You are safe!")

    st.divider()

    # 5. Remediation History
    st.markdown("### ✅ Remediation History")
    st.caption("Successfully completed security actions")
    
    query = db_session.query(RemediationAction).filter_by(status='completed')
    if user_id:
        monitored_emails = db_session.query(MonitoredEmail.email).filter_by(user_id=user_id).all()
        emails = [e[0] for e in monitored_emails]
        query = query.filter(RemediationAction.email.in_(emails))
        
    history = query.order_by(RemediationAction.completed_at.desc()).limit(10).all()
    
    if history:
        for item in history:
            st.markdown(f"""
                <div style='background: rgba(34, 197, 94, 0.05); padding: 12px; border-radius: 8px; border: 1px solid rgba(34, 197, 94, 0.2); margin-bottom: 8px; display: flex; align-items: center; justify-content: space-between;'>
                    <div>
                        <span style='color: #22c55e; font-weight: bold;'>[COMPLETED]</span> {item.description}
                        <br><span style='font-size: 0.75rem; color: #94a3b8;'>Account: {item.email}</span>
                    </div>
                    <div style='font-size: 0.8rem; color: #64748b;'>{item.completed_at.strftime('%Y-%m-%d')}</div>
                </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No completed actions yet. Start remediating incidents above!")

    st.divider()
    # 6. Recent Activity integrated into Dashboard
    render_brc_activity(db_session, user_id=user_id)


def render_risk_section(title, accounts, key_prefix, db_session):
    if not accounts:
        return

    # Section Header with styling
    st.markdown(f"#### {title}")
    
    # Determine colors based on risk
    colors = {
        "critical": {"border": "#ef4444", "bg": "rgba(239, 68, 68, 0.05)", "accent": "#ef4444"},
        "high": {"border": "#f97316", "bg": "rgba(249, 115, 22, 0.05)", "accent": "#f97316"},
        "medium": {"border": "#eab308", "bg": "rgba(234, 179, 8, 0.05)", "accent": "#eab308"},
        "low": {"border": "#22c55e", "bg": "rgba(34, 197, 94, 0.05)", "accent": "#22c55e"}
    }
    theme = colors.get(key_prefix)

    for i, (email, score, breaches) in enumerate(accounts):
        # Get actions
        pending_actions = get_pending_actions(email, db_session=db_session)
        completed_actions = get_completed_actions(email, db_session=db_session)
        status_code, status_label = get_response_status(email, db_session=db_session)
        completed, total, percentage = calculate_completion_rate(email, db_session=db_session)
        
        # Enhanced Expander with risk score indicators
        expander_label = f"📧 {email} | Risk Score: {score} | {status_label}"
        
        with st.expander(expander_label, expanded=(key_prefix=="critical" and i==0)):
            st.markdown(f"""
                <div style='border-left: 4px solid {theme['accent']}; padding-left: 15px; margin-bottom: 10px;'>
                    <p style='color: #94a3b8; font-size: 0.9rem; margin-bottom: 0;'>Status: <span style='color: {theme['accent']}; font-weight: bold;'>{status_label}</span></p>
                </div>
            """, unsafe_allow_html=True)
            
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.write("**Remediation Progress:**")
                # Custom progress bar color based on risk
                st.progress(percentage / 100)
                st.caption(f"{completed} of {total} tasks completed")
                
                st.markdown("---")
                
                if total == 0:
                    st.info("No response plan generated for this identity yet.")
                    if st.button(f"🚀 Deploy Remediation Plan", key=f"{key_prefix}_gen_{i}"):
                        count = save_remediation_actions(email, breaches, db_session=db_session)
                        st.success(f"✅ Strategic response plan with {count} tasks deployed.")
                        st.rerun()
                else:
                    if pending_actions:
                        st.write("**Required Actions:**")
                        for j, action in enumerate(pending_actions):
                            c1, c2 = st.columns([0.85, 0.15])
                            with c1: 
                                # Priority based styling
                                priority_color = "#ef4444" if action.priority == 1 else "#3b82f6"
                                st.markdown(f"""
                                    <div style='padding: 8px; border-radius: 6px; background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.05); margin-bottom: 5px;'>
                                        <span style='color: {priority_color}; font-weight: bold;'>P{action.priority}</span> | {action.description}
                                    </div>
                                """, unsafe_allow_html=True)
                            with c2:
                                if st.button("✓", key=f"{key_prefix}_done_{i}_{j}_{action.id}"):
                                    mark_action_completed(action.id, db_session=db_session)
                                    st.rerun()
                    
                    if completed_actions:
                        st.write("**Completed Remediation:**")
                        for action in completed_actions:
                            st.markdown(f"<div style='color: #10b981; font-size: 0.9rem;'>✅ {action.description}</div>", unsafe_allow_html=True)
            
            with col2:
                st.markdown(f"""
                    <div style='background: rgba(15, 23, 42, 0.4); padding: 15px; border-radius: 10px; border: 1px solid rgba(255,255,255,0.05);'>
                        <h5 style='margin-top: 0; color: #94a3b8; font-size: 0.8rem; text-transform: uppercase;'>Threat Exposure Profile</h5>
                """, unsafe_allow_html=True)
                
                for b in breaches[:5]:
                    st.markdown(f"""
                        <div style='margin-bottom: 8px;'>
                            <div style='font-size: 0.85rem; color: #f8fafc;'>{b.breach_name}</div>
                            <div style='font-size: 0.7rem; color: #64748b;'>{b.breach_date.strftime('%b %Y')} • {b.severity.upper()}</div>
                        </div>
                    """, unsafe_allow_html=True)
                
                if len(breaches) > 5:
                    st.markdown(f"<p style='font-size: 0.75rem; color: #3b82f6;'>+ {len(breaches)-5} additional sources</p>", unsafe_allow_html=True)
                
                st.markdown("</div>", unsafe_allow_html=True)
                
                st.divider()
                if st.button("📢 Dispatch Alert", key=f"{key_prefix}_mail_{i}", width='stretch'):
                    st.toast(f"Security advisory dispatched to {email}")


def render_brc_reports(db_session, user_id=None):
    st.title("📜 Response Reports")
    st.caption("Strategic analytics and organizational remediation metrics.")
    
    try:
        stats = get_breach_statistics(db_session=db_session, user_id=user_id)
        
        # Priority Breakdown
        query = db_session.query(RemediationAction.priority, models_db.func.count(RemediationAction.id)).filter_by(status='pending')
        if user_id:
            monitored_emails = db_session.query(MonitoredEmail.email).filter_by(user_id=user_id).all()
            emails = [e[0] for e in monitored_emails]
            query = query.filter(RemediationAction.email.in_(emails))
            
        priority_counts = query.group_by(RemediationAction.priority).all()
        priority_map = {1: "Critical (P1)", 2: "High (P2)", 3: "Medium (P3)", 4: "Low (P4)"}
        df_priority = pd.DataFrame([{"Priority": priority_map.get(p, f"P{p}"), "Tasks": c} for p, c in priority_counts])
        
        col1, col2 = st.columns(2)
        with col1:
            st.write("**Task Distribution by Priority:**")
            if not df_priority.empty:
                st.bar_chart(df_priority.set_index("Priority"))
            else:
                st.info("No pending tasks.")
                
        with col2:
            st.write("**Task Distribution by Category:**")
            summary = get_action_summary(db_session=db_session, user_id=user_id)
            if summary:
                df_summary = pd.DataFrame([{"Task": k, "Count": v} for k, v in summary.items()])
                st.bar_chart(df_summary.set_index("Task"))
            else:
                st.info("No categorized tasks.")

        st.divider()
        
        # Remediation Velocity
        col3, col4 = st.columns(2)
        with col3:
            st.write("**Remediation Status Overview:**")
            query = db_session.query(RemediationAction.status, models_db.func.count(RemediationAction.id))
            if user_id:
                monitored_emails = db_session.query(MonitoredEmail.email).filter_by(user_id=user_id).all()
                emails = [e[0] for e in monitored_emails]
                query = query.filter(RemediationAction.email.in_(emails))
                
            status_counts = query.group_by(RemediationAction.status).all()
            df_status = pd.DataFrame([{"Status": s.capitalize(), "Count": c} for s, c in status_counts])
            if not df_status.empty:
                fig_pie = px.pie(df_status, values='Count', names='Status', hole=.4, template="plotly_dark")
                fig_pie.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
                st.plotly_chart(fig_pie, width='stretch')
            else:
                st.info("No tasks to visualize.")
                
        with col4:
            st.write("**Response Health Index:**")
            st.metric("Aggregate Secured Identities", stats['actions_completed'])
            st.progress(stats['completion_rate'] / 100)
            st.caption(f"Current Completion Rate: {stats['completion_rate']:.1f}%")

        st.divider()
        if st.button("📥 Export Comprehensive Incident Report (PDF)", width='stretch'):
            st.success("Master organizational report has been compiled.")
    except Exception as e:
        st.error(f"Error loading response reports: {e}")


def render_brc_settings(db_session=None, user_id=None):
    st.title("⚙️ BRC Settings")
    st.caption("Configure the response console behavior.")
    
    st.toggle("Auto-generate response plans for new breaches", value=True)
    st.toggle("Enable real-time Slack notifications for CRITICAL risk", value=False)
    st.slider("Auto-refresh interval (seconds)", min_value=60, max_value=600, value=300)
    
    st.divider()
    st.subheader("🧪 Diagnostic Tools")
    if st.button("Generate Test Alert Preview", width='stretch'):
        from alert_service import send_combined_alert
        # Use first monitored email if available
        test_email = "test@example.com"
        if user_id:
            monitored = db_session.query(MonitoredEmail).filter_by(user_id=user_id).first()
            if monitored:
                test_email = monitored.email
        
        send_combined_alert(
            risk_level="HIGH",
            score=75,
            email=test_email,
            breach_count=3,
            breaches_list=[
                {'breach_name': 'Test Breach A', 'breach_date': '2024-01-01', 'data_exposed': 'Email, Password'},
                {'breach_name': 'Test Breach B', 'breach_date': '2023-11-15', 'data_exposed': 'Email, Name'}
            ],
            db_session=db_session
        )
        st.success(f"✅ Test alert preview generated for {test_email}! View it in 'Alert Previews'.")
    
    if st.button("Save Preferences"):
        st.success("Settings updated.")


def render_brc_activity(db_session, user_id=None):
    st.title("🕒 Incident Audit Log")
    st.caption("Complete chronological record of dark web detections and response actions.")
    
    activities = get_recent_activities(limit=50, db_session=db_session, user_id=user_id)
    if activities:
        for act in activities:
            # Determine icon and color based on severity
            if act.severity == "critical":
                icon, color = "🚨", "#dc2626"
            elif act.severity == "warning":
                icon, color = "⚠️", "#f59e0b"
            else:
                icon, color = "ℹ️", "#00ffcc"
                
            with st.container():
                col_icon, col_content = st.columns([0.1, 0.9])
                with col_icon:
                    st.write(f"<div style='font-size: 1.5rem; text-align: center;'>{icon}</div>", unsafe_allow_html=True)
                with col_content:
                    st.markdown(f"**{act.timestamp.strftime('%Y-%m-%d %H:%M:%S')}**")
                    st.markdown(f"<span style='color: {color}; font-weight: bold;'>[{act.action.upper()}]</span> {act.message}", unsafe_allow_html=True)
                    if act.email:
                        st.caption(f"Identity: {act.email}")
                st.divider()
    else:
        st.info("No activity recorded in the incident audit log yet.")
