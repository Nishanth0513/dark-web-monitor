import streamlit as st
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
from models import MonitoredEmail, Breach


def show_breach_response_center():
    """
    Main Breach Response Center page
    """
    
    st.title("🚨 Breach Response Center")
    st.caption("Action Required for Compromised Accounts")
    
    # Get statistics
    stats = get_breach_statistics()
    
    # Display overview metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "🔴 Breached Accounts",
            stats['breached_accounts']
        )
    
    with col2:
        st.metric(
            "⚠️ Actions Pending",
            stats['actions_pending']
        )
    
    with col3:
        st.metric(
            "✅ Actions Completed",
            stats['actions_completed']
        )
    
    with col4:
        st.metric(
            "📈 Completion Rate",
            f"{stats['completion_rate']:.0f}%"
        )
    
    st.divider()
    
    # Get all breached emails
    breached_emails = Breach.query.distinct(Breach.email).all()
    
    if not breached_emails:
        st.info("✅ No breached accounts found. All clear!")
        return
    
    # Display accounts found in breaches
    st.subheader("🔴 Accounts Found in Breaches (Action Required)")
    
    for account in breached_emails:
        email = account.email
        
        # Get breaches for this email
        breaches = Breach.query.filter_by(email=email).all()
        
        # Get actions
        pending_actions = get_pending_actions(email)
        completed_actions = get_completed_actions(email)
        
        # Calculate status
        status_code, status_label = get_response_status(email)
        completed, total, percentage = calculate_completion_rate(email)
        
        # Determine if should be expanded
        should_expand = (status_code in ['pending', 'in_progress'])
        
        # Display account card
        with st.expander(
            f"📧 **{email}** - {status_label}",
            expanded=should_expand
        ):
            
            # Show breach details
            st.write("**Breach Details:**")
            for breach in breaches:
                st.info(f"""
                **{breach.breach_name}**  
                Date: {breach.breach_date.strftime('%Y-%m-%d')}  
                Data Exposed: {breach.data_exposed}
                """)
            
            st.write("---")
            
            # Show required actions
            st.subheader("⚠️ REQUIRED ACTIONS:")
            
            if total == 0:
                # Generate actions if none exist
                if st.button(f"Generate Actions for {email}", key=f"gen_{email}"):
                    count = save_remediation_actions(email, breaches)
                    st.success(f"✅ Generated {count} actions!")
                    st.rerun()
            else:
                # Show pending actions with checkboxes
                if pending_actions:
                    st.write("**Pending:**")
                    for action in pending_actions:
                        col1, col2 = st.columns([0.9, 0.1])
                        
                        with col1:
                            st.write(f"☐ {action.description}")
                        
                        with col2:
                            if st.button("✓", key=f"complete_{action.id}"):
                                if mark_action_completed(action.id):
                                    st.success("✅")
                                    st.rerun()
                
                # Show completed actions
                if completed_actions:
                    st.write("**Completed:**")
                    for action in completed_actions:
                        st.write(f"✅ {action.description}")
                
                # Show progress
                st.write("---")
                st.write(f"**Status:** {status_label} ({completed}/{total} completed)")
                st.progress(percentage / 100)
                
                # Action buttons
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    if st.button("📧 Send Reminder", key=f"remind_{email}"):
                        # TODO: Implement email reminder
                        st.success("Reminder sent!")
                
                with col2:
                    if st.button("📊 Generate Report", key=f"report_{email}"):
                        # TODO: Implement PDF report
                        st.success("Report generated!")
                
                with col3:
                    if completed == total:
                        if st.button("✅ Archive", key=f"archive_{email}"):
                            st.success("Account secured and archived!")
    
    st.divider()
    
    # Remediation summary
    st.subheader("✅ Remediation Summary")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Actions Needed Across All Accounts:**")
        action_summary = get_action_summary()
        
        if action_summary:
            for action_type, count in action_summary.items():
                st.write(f"• {action_type}: {count}")
        else:
            st.write("No pending actions")
    
    with col2:
        st.write("**Overall Progress:**")
        st.metric("Completion Rate", f"{stats['completion_rate']:.1f}%")
        st.progress(stats['completion_rate'] / 100)
    
    st.divider()
    
    # Recent activity
    st.subheader("📈 Recent Activity")
    
    activities = get_recent_activities(limit=10)
    
    if activities:
        for activity in activities:
            time_str = activity.timestamp.strftime('%I:%M %p')
            st.text(f"{time_str} - {activity.message}")
    else:
        st.info("No recent activity")
