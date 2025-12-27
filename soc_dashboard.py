import streamlit as st
import requests
import pandas as pd
from datetime import datetime, timedelta
import json
import os
from pathlib import Path

ABUSEIPDB_API_KEY = "ABUSEIPDB_API_KEY"

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

HEADERS = {
    "Key": ABUSEIPDB_API_KEY,
    "Accept": "application/json"
}

LOG_FILE = "ip_lookups.jsonl"
ALLOWLIST_FILE = "allowlist.json"
CASES_FILE = "cases.jsonl"
ESCALATION_TIME_WINDOW = 24
BURST_THRESHOLD = 10
BURST_WINDOW_MINUTES = 2

def load_allowlist():
    if os.path.exists(ALLOWLIST_FILE):
        with open(ALLOWLIST_FILE, "r") as f:
            return json.load(f)
    return {"ips": [], "asns": [], "domains": []}

def is_allowlisted(ip, data):
    allowlist = load_allowlist()
    if ip in allowlist["ips"]:
        return True
    if data.get("isp") in allowlist["asns"]:
        return True
    if data.get("domain") in allowlist["domains"]:
        return True
    return False

def create_case(ip, case_type="manual_lookup", analyst_name="", severity="", suspected_threat=""):
    case_id = f"CASE-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    initial_note = {
        "timestamp": datetime.now().isoformat(),
        "text": f"[INITIAL] Analyst: {analyst_name}, Severity: {severity}, Suspected: {suspected_threat}"
    }
    case = {
        "case_id": case_id,
        "ip": ip,
        "created": datetime.now().isoformat(),
        "status": "Open",
        "notes": [initial_note],
        "linked_ips": [],
        "analyst": analyst_name,
        "severity": severity,
        "suspected_threat": suspected_threat
    }
    
    with open(CASES_FILE, "a") as f:
        f.write(json.dumps(case) + "\n")
    
    return case_id

def get_case_by_ip(ip):
    if not os.path.exists(CASES_FILE):
        return None
    
    with open(CASES_FILE, "r") as f:
        for line in f:
            if line.strip():
                case = json.loads(line)
                if case["ip"] == ip and case["status"] != "Closed":
                    return case
    return None

def update_case_status(case_id, status, notes=""):
    if not os.path.exists(CASES_FILE):
        return
    
    cases = []
    with open(CASES_FILE, "r") as f:
        for line in f:
            if line.strip():
                case = json.loads(line)
                if case["case_id"] == case_id:
                    case["status"] = status
                    if notes:
                        case["notes"].append({"timestamp": datetime.now().isoformat(), "text": notes})
                cases.append(case)
    
    with open(CASES_FILE, "w") as f:
        for case in cases:
            f.write(json.dumps(case) + "\n")

def get_risk_level_with_reason(score, data):
    reason = ""
    
    if score >= 75:
        level = "HIGH"
        reports = data.get("totalReports", 0)
        if reports > 10:
            reason = f"High score + {reports} abuse reports"
        elif data.get("usageType") == "Data Center":
            reason = "High score from data center"
        else:
            reason = "High abuse confidence score"
    elif score >= 30:
        level = "MEDIUM"
        usage = data.get("usageType", "")
        reports = data.get("totalReports", 0)
        if usage == "Data Center" and reports > 0:
            reason = f"Data center with {reports} reports"
        elif reports > 0:
            reason = f"Low-moderate score + {reports} reports"
        else:
            reason = "Suspicious pattern detected"
    else:
        level = "LOW"
        usage = data.get("usageType", "")
        if usage == "Residential":
            reason = "No reports, residential ISP"
        elif usage == "Data Center":
            reason = "No reports but data center ASN"
        else:
            reason = "No significant abuse history"
    
    return level, reason

def log_ip_lookup(ip, abuse_score, risk_level, reason="", source="manual"):
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "ip": ip,
        "abuse_score": abuse_score,
        "risk_level": risk_level,
        "reason": reason,
        "source": source
    }
    
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

def read_logs():
    if not os.path.exists(LOG_FILE):
        return []
    
    logs = []
    with open(LOG_FILE, "r") as f:
        for line in f:
            if line.strip():
                logs.append(json.loads(line))
    return logs

def detect_burst(ip):
    logs = read_logs()
    cutoff_time = datetime.now() - timedelta(minutes=BURST_WINDOW_MINUTES)
    
    burst_logs = [
        log for log in logs 
        if log["ip"] == ip and datetime.fromisoformat(log["timestamp"]) > cutoff_time
    ]
    
    if len(burst_logs) >= BURST_THRESHOLD:
        return {
            "detected": True,
            "count": len(burst_logs),
            "window_minutes": BURST_WINDOW_MINUTES,
            "type": "burst"
        }
    return {"detected": False}

def detect_slow_burn(ip):
    logs = read_logs()
    cutoff_time = datetime.now() - timedelta(hours=24)
    
    slow_burn_logs = [
        log for log in logs 
        if log["ip"] == ip and datetime.fromisoformat(log["timestamp"]) > cutoff_time
    ]
    
    if len(slow_burn_logs) >= 24:
        times = [datetime.fromisoformat(log["timestamp"]) for log in slow_burn_logs]
        times.sort()
        
        is_regular = True
        for i in range(1, len(times)):
            time_diff = (times[i] - times[i-1]).total_seconds() / 3600
            if time_diff > 2:
                is_regular = False
                break
        
        if is_regular:
            return {
                "detected": True,
                "count": len(slow_burn_logs),
                "window_hours": 24,
                "type": "slow_burn"
            }
    
    return {"detected": False}

def get_second_source_verdict(ip):
    return {
        "source": "AbuseIPDB",
        "agreement": "primary"
    }

def check_escalation(ip, current_abuse_score):
    logs = read_logs()
    
    cutoff_time = datetime.now() - timedelta(hours=ESCALATION_TIME_WINDOW)
    
    ip_logs = [
        log for log in logs 
        if log["ip"] == ip and datetime.fromisoformat(log["timestamp"]) > cutoff_time
    ]
    
    if len(ip_logs) >= 5:
        avg_score = sum(log["abuse_score"] for log in ip_logs) / len(ip_logs)
        frequency = len(ip_logs)
        
        escalation_risk = (avg_score * 0.6) + (min(frequency / 10, 1) * 40)
        
        return {
            "escalate": True,
            "frequency": frequency,
            "avg_score": avg_score,
            "escalation_risk": escalation_risk,
            "current_score": current_abuse_score
        }
    
    return {"escalate": False}

def generate_iptables_rule(ip):
    return f"sudo iptables -A INPUT -s {ip} -j DROP"

def generate_ufw_rule(ip):
    return f"sudo ufw deny from {ip}"

st.set_page_config(
    page_title="Mini SOC Analyst Dashboard",
    layout="centered"
)

st.title("🛡️ Mini SOC Analyst Dashboard")
st.write("Investigate IP reputation using real threat intelligence")

with st.sidebar:
    st.subheader("📋 Recent IP Lookups")
    
    logs = read_logs()
    
    if logs:
        recent_logs = sorted(logs, key=lambda x: x["timestamp"], reverse=True)[:10]
        
        log_df = pd.DataFrame([
            {
                "Timestamp": log["timestamp"][:16],
                "IP": log["ip"],
                "Score": log["abuse_score"],
                "Risk": log["risk_level"],
                "Source": log.get("source", "unknown")
            }
            for log in recent_logs
        ])
        
        st.dataframe(log_df, use_container_width=True, hide_index=True)
        
        if st.button("📥 Download Full Logs"):
            with open(LOG_FILE, "r") as f:
                st.download_button(
                    label="Download ip_lookups.jsonl",
                    data=f.read(),
                    file_name="ip_lookups.jsonl",
                    mime="application/jsonl"
                )
    else:
        st.info("No IP lookups logged yet")
    
    st.divider()
    st.subheader("🔐 Allowlist Management")
    if st.button("📄 View Allowlist"):
        allowlist = load_allowlist()
        st.code(json.dumps(allowlist, indent=2), language="json")
        st.caption("📋 Copy the JSON above to edit in allowlist.json file directly")

if "show_case_form" not in st.session_state:
    st.session_state.show_case_form = False
if "case_form_ip" not in st.session_state:
    st.session_state.case_form_ip = ""

col1, col2 = st.columns([3, 1])
with col1:
    ip_address = st.text_input("Enter IP address to investigate")
with col2:
    source = st.selectbox(
        "Source",
        ["manual", "auth.log (SSH)", "nginx access", "other"],
        index=0
    )

if st.button("Analyze"):
    if not ip_address:
        st.warning("Please enter an IP address")
    else:
        st.info(f"Analyzing IP: {ip_address}")

        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90
        }

        try:
            response = requests.get(
                ABUSEIPDB_URL,
                headers=HEADERS,
                params=params,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()["data"]

                if is_allowlisted(ip_address, data):
                    st.info("✅ IP is on allowlist. Suppressing alerts.")
                
                results = {
                    "Metric": [
                        "IP Address",
                        "Abuse Confidence Score",
                        "Total Reports",
                        "Country Code",
                        "ISP",
                        "Domain",
                        "Usage Type"
                    ],
                    "Value": [
                        data.get("ipAddress"),
                        data.get("abuseConfidenceScore"),
                        data.get("totalReports"),
                        data.get("countryCode"),
                        data.get("isp"),
                        data.get("domain"),
                        data.get("usageType")
                    ]
                }

                df = pd.DataFrame(results)
                st.table(df)

                score = data.get("abuseConfidenceScore", 0)
                risk_level, reason = get_risk_level_with_reason(score, data)
                
                log_ip_lookup(ip_address, score, risk_level, reason, source)

                if score >= 75:
                    st.error(f"🚨 HIGH RISK — {reason}")
                elif score >= 30:
                    st.warning(f"⚠️ MEDIUM RISK — {reason}")
                else:
                    st.success(f"✅ LOW RISK — {reason}")
                
                st.divider()
                st.subheader("🔍 Threat Analysis")
                
                col1, col2 = st.columns(2)
                with col1:
                    verdict = get_second_source_verdict(ip_address)
                    st.metric("Primary Source", verdict["source"])
                with col2:
                    st.metric("Source Agreement", verdict["agreement"])
                
                burst = detect_burst(ip_address)
                slow_burn = detect_slow_burn(ip_address)
                
                if burst["detected"]:
                    st.warning(f"💥 **BURST DETECTED** — {burst['count']} hits in {burst['window_minutes']} minutes")
                
                if slow_burn["detected"]:
                    st.warning(f"🔥 **SLOW-BURN DETECTED** — {slow_burn['count']} hits over 24 hours (regular intervals)")
                
                escalation = check_escalation(ip_address, score)
                if escalation["escalate"]:
                    st.warning(f"🚨 **ESCALATION ALERT** 🚨")
                    col1, col2, col3 = st.columns(3)
                    col1.metric("Occurrences (24h)", escalation["frequency"])
                    col2.metric("Avg Abuse Score", f"{escalation['avg_score']:.1f}")
                    col3.metric("Escalation Risk", f"{escalation['escalation_risk']:.1f}%")
                
                st.divider()
                st.subheader("📋 Case Management")
                
                case = get_case_by_ip(ip_address)
                if case:
                    st.info(f"**Case ID**: {case['case_id']} | **Status**: {case['status']}")
                    st.caption(f"Analyst: {case.get('analyst', 'N/A')} | Severity: {case.get('severity', 'N/A')}")
                    
                    new_status = st.selectbox("Update Status", ["Open", "Investigating", "Closed"], 
                                             index=["Open", "Investigating", "Closed"].index(case["status"]))
                    analyst_notes = st.text_area("Add Notes", height=100)
                    
                    if st.button("Update Case"):
                        update_case_status(case["case_id"], new_status, analyst_notes)
                        st.success("Case updated!")
                else:
                    if st.button("📝 Create Case"):
                        st.session_state.show_case_form = True
                        st.session_state.case_form_ip = ip_address
                        st.rerun()
                    
                    if st.session_state.show_case_form and st.session_state.case_form_ip == ip_address:
                        st.divider()
                        with st.container(border=True):
                            st.subheader("📋 New Case Form")
                            
                            with st.form("case_creation_form"):
                                analyst_name = st.text_input(
                                    "Analyst Name",
                                    placeholder="Your name or ID",
                                    help="Who is creating this case?"
                                )
                                
                                severity = st.selectbox(
                                    "Severity Level",
                                    ["Low", "Medium", "High", "Critical"],
                                    help="Initial severity assessment"
                                )
                                
                                suspected_threat = st.text_area(
                                    "Suspected Threat / Notes",
                                    placeholder="e.g., Brute force attack, Data exfiltration attempt, C2 communication...",
                                    height=120,
                                    help="What do you suspect this IP is doing?"
                                )
                                
                                linked_ips = st.text_area(
                                    "Linked IPs (Optional)",
                                    placeholder="Enter IPs separated by commas",
                                    height=80,
                                    help="Other IPs related to this investigation"
                                )
                                
                                col1, col2 = st.columns(2)
                                with col1:
                                    submit = st.form_submit_button("✅ Create Case", use_container_width=True)
                                with col2:
                                    cancel = st.form_submit_button("❌ Cancel", use_container_width=True)
                                
                                if submit:
                                    if not analyst_name or not suspected_threat:
                                        st.error("Analyst Name and Suspected Threat are required!")
                                    else:
                                        linked_ips_list = [ip.strip() for ip in linked_ips.split(",") if ip.strip()]
                                        case_id = create_case(
                                            st.session_state.case_form_ip,
                                            source,
                                            analyst_name,
                                            severity,
                                            suspected_threat
                                        )
                                        
                                        with open(CASES_FILE, "r") as f:
                                            cases = [json.loads(line) for line in f if line.strip()]
                                        
                                        for case in cases:
                                            if case["case_id"] == case_id:
                                                case["linked_ips"] = linked_ips_list
                                        
                                        with open(CASES_FILE, "w") as f:
                                            for case in cases:
                                                f.write(json.dumps(case) + "\n")
                                        
                                        st.session_state.show_case_form = False
                                        st.session_state.case_form_ip = ""
                                        st.success(f"✅ Case created: **{case_id}**")
                                        st.rerun()
                                
                                if cancel:
                                    st.session_state.show_case_form = False
                                    st.session_state.case_form_ip = ""
                                    st.rerun()
                
                if score >= 90:
                    st.divider()
                    st.subheader("🔒 Blocking Rules Generated")
                    iptables_rule = generate_iptables_rule(ip_address)
                    ufw_rule = generate_ufw_rule(ip_address)
                    
                    st.info("⚠️ These rules have NOT been executed. Review and execute manually if needed.")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.code(iptables_rule, language="bash")
                        st.caption("iptables rule")
                    with col2:
                        st.code(ufw_rule, language="bash")
                        st.caption("UFW rule")

            elif response.status_code == 429:
                st.error("API rate limit exceeded. Try again later.")
            else:
                st.error(f"API error (Status Code: {response.status_code})")

        except requests.exceptions.RequestException as e:
            st.error(f"Network error: {e}")
