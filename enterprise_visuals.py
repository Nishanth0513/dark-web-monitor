import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from datetime import datetime, timedelta
from enterprise_engine import calculate_eri
from models import OrgEmail, OrgBreach, RemediationAction, RiskHistory, ActivityLog, EmployeeRiskHistory
from sqlalchemy import desc

def render_enterprise_visuals(db_sess, active_org, employees, org_breaches):
    """
    Renders the Mandatory Visual Intelligence Modules for Enterprise Mode.
    """
    # Filter remediation tasks only for this organization's emails
    employee_emails = [e.email for e in employees]
    remediation_tasks = db_sess.query(RemediationAction).filter(RemediationAction.email.in_(employee_emails)).all()
    
    # 1. Executive Command Panel
    eri_data = calculate_eri(employees, org_breaches, remediation_tasks)
    eri = eri_data['eri']
    metrics = eri_data['metrics']
    
    st.subheader("🛡️ Executive Command Panel")
    c1, c2, c3, c4, c5 = st.columns(5)
    
    # Get trend (dummy for now, would use RiskHistory)
    last_history = db_sess.query(RiskHistory).filter_by(org_id=active_org.id).order_by(desc(RiskHistory.timestamp)).offset(1).first()
    trend_arrow = "➡️"
    if last_history:
        if eri > last_history.eri: trend_arrow = "🔺"
        elif eri < last_history.eri: trend_arrow = "🔻"
        
    c1.metric("Enterprise Risk Index", f"{eri}", delta=f"{trend_arrow} {eri_data['label']}")
    c2.metric("Exposure Density", f"{metrics.get('density', 0)}%")
    c3.metric("Privileged Exposure", f"{metrics.get('privileged_ratio', 0)}%")
    c4.metric("Remediation Posture", f"{metrics.get('remediation_posture', 0)}%")
    c5.metric("Total Breaches", len(org_breaches))

    st.markdown("---")
    
    # 2. Risk Distribution Histogram & 7. Privileged Exposure Graph
    col_a, col_b = st.columns(2)
    
    with col_a:
        st.subheader("📊 Risk Distribution")
        scores = [b.score for b in org_breaches] if org_breaches else [0]
        fig_hist = px.histogram(scores, nbins=20, labels={'value': 'Risk Score'}, 
                               title="Breach Severity Distribution", color_discrete_sequence=['#ef4444'])
        fig_hist.update_layout(template="plotly_dark", plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)')
        st.plotly_chart(fig_hist, use_container_width=True)

    with col_b:
        st.subheader("🔑 Privileged Exposure")
        # Role vs Avg Score
        role_data = []
        for e in employees:
            e_breaches = [b for b in org_breaches if b.email == e.email]
            max_score = max([b.score for b in e_breaches]) if e_breaches else 0
            role_data.append({"Role": e.role, "Score": max_score})
        
        if role_data:
            df_role = pd.DataFrame(role_data).groupby("Role")["Score"].mean().reset_index()
            fig_role = px.bar(df_role, x="Role", y="Score", color="Score", 
                             color_continuous_scale='Reds', title="Avg Risk Score by Role")
            fig_role.update_layout(template="plotly_dark", plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)')
            st.plotly_chart(fig_role, use_container_width=True)

    st.markdown("---")

    # 3. Enterprise Heatmap (Users x Systems)
    st.subheader("🌡️ Enterprise Risk Heatmap (Identities × Systems)")
    heatmap_data = []
    all_systems = set()
    for e in employees:
        systems = [s.strip() for s in e.systems.split(",") if s.strip()]
        if not systems: systems = ["General Corp"]
        all_systems.update(systems)
        
        e_breaches = [b for b in org_breaches if b.email == e.email]
        max_score = max([b.score for b in e_breaches]) if e_breaches else 0
        
        for s in systems:
            heatmap_data.append({"User": e.email.split("@")[0], "System": s, "Risk": max_score})
            
    if heatmap_data:
        df_heat = pd.DataFrame(heatmap_data)
        fig_heat = px.density_heatmap(df_heat, x="System", y="User", z="Risk", 
                                     color_continuous_scale='Reds', title="Systemic Exposure Intensity")
        fig_heat.update_layout(template="plotly_dark", paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
        st.plotly_chart(fig_heat, use_container_width=True)
    else:
        st.info("No system mapping available for heatmap.")

    st.markdown("---")

    # 4. Radar (Spider) Graph & 6. Blast Radius Graph
    col_c, col_d = st.columns(2)
    
    with col_c:
        st.subheader("🕸️ Risk Vector Radar")
        selected_email = st.selectbox("Select User for Deep Analysis", [e.email for e in employees])
        if selected_email:
            e_breaches = [b for b in org_breaches if b.email == selected_email]
            if e_breaches:
                # Dummy axes for demo based on mandatory requirements
                # In real app, we'd extract these from the breach scoring breakdown
                latest_b = e_breaches[0]
                fig_radar = go.Figure(data=go.Scatterpolar(
                    r=[latest_b.score, 70, 40, 90, 80], # Dummy values
                    theta=['Source Severity', 'Data Sensitivity', 'Breach Age', 'Password Risk', 'Role Criticality'],
                    fill='toself',
                    line_color='#00ffcc'
                ))
                fig_radar.update_layout(polar=dict(radialaxis=dict(visible=True, range=[0, 100])), 
                                       template="plotly_dark", paper_bgcolor='rgba(0,0,0,0)')
                st.plotly_chart(fig_radar, use_container_width=True)
            else:
                st.info("No breaches for selected user.")

    with col_d:
        st.subheader("💥 Blast Radius Analysis")
        # Directed network: User -> Role -> Systems -> Sensitivity
        user_nodes = [e.email.split("@")[0] for e in employees]
        roles = list(set([e.role for e in employees]))
        
        # Get all unique systems
        systems = []
        for e in employees:
            e_systems = [s.strip() for s in e.systems.split(",") if s.strip()]
            for s in e_systems:
                if s not in systems:
                    systems.append(s)
        if not systems:
            systems = ["General Corp"]
            
        sensitivities = ["Critical (SSN/Pass)", "High (Phone)", "Medium (PII)", "Low (Metadata)"]
        
        label_list = user_nodes + roles + systems + sensitivities
        
        links = []
        for i, e in enumerate(employees):
            u_idx = i
            r_idx = len(user_nodes) + roles.index(e.role)
            links.append({"source": u_idx, "target": r_idx, "value": 1})
            
            e_breaches = [b for b in org_breaches if b.email == e.email]
            max_score = max([b.score for b in e_breaches]) if e_breaches else 0
            
            e_systems = [s.strip() for s in e.systems.split(",") if s.strip()]
            if not e_systems: e_systems = ["General Corp"]
            
            for s in e_systems:
                if s in systems:
                    s_idx = len(user_nodes) + len(roles) + systems.index(s)
                    links.append({"source": r_idx, "target": s_idx, "value": 1})
                    
                    # Link system to sensitivity based on risk score
                    sens_idx = len(user_nodes) + len(roles) + len(systems)
                    if max_score >= 85: sens_idx += 0
                    elif max_score >= 60: sens_idx += 1
                    elif max_score >= 35: sens_idx += 2
                    else: sens_idx += 3
                    
                    links.append({"source": s_idx, "target": sens_idx, "value": 1})
        
        if links:
            fig_blast = go.Figure(data=[go.Sankey(
                node = dict(pad = 15, thickness = 20, line = dict(color = "black", width = 0.5),
                            label = label_list, color = "rgba(239, 68, 68, 0.8)"),
                link = dict(source = [l['source'] for l in links], 
                            target = [l['target'] for l in links], 
                            value = [l['value'] for l in links],
                            color = "rgba(255, 255, 255, 0.2)")
            )])
            fig_blast.update_layout(title_text="Identity Exposure Flow (User → Role → Assets → Sensitivity)", 
                                   font_size=10, template="plotly_dark", paper_bgcolor='rgba(0,0,0,0)')
            st.plotly_chart(fig_blast, use_container_width=True)
        else:
            st.info("Insufficient data for Blast Radius mapping.")

    st.markdown("---")
    
    # 5. Enterprise Trend Line
    st.subheader("📈 Enterprise Risk Trend")
    # Fetch last 30 entries for trend
    history = db_sess.query(RiskHistory).filter_by(org_id=active_org.id).order_by(RiskHistory.timestamp.asc()).all()
    if history:
        df_hist = pd.DataFrame([{"Time": h.timestamp, "ERI": h.eri} for h in history])
        # Ensure Time is datetime
        df_hist["Time"] = pd.to_datetime(df_hist["Time"])
        
        fig_trend = px.line(df_hist, x="Time", y="ERI", title="Systemic Risk Index (ERI) Progression")
        fig_trend.update_layout(
            template="plotly_dark", 
            plot_bgcolor='rgba(0,0,0,0)', 
            paper_bgcolor='rgba(0,0,0,0)',
            xaxis=dict(showgrid=False),
            yaxis=dict(range=[0, 100], showgrid=True, gridcolor='rgba(255,255,255,0.1)')
        )
        fig_trend.update_traces(line=dict(color='#00ffcc', width=3), mode='lines+markers')
        st.plotly_chart(fig_trend, use_container_width=True)
    else:
        st.info("Insufficient historical data for trend analysis. Run scans to generate data points.")
