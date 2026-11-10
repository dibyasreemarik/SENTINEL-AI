import pandas as pd
import streamlit as st
from urllib.parse import urlparse
from sentinel.url_checks import inspect_url
from sentinel.network_checks import inspect_tls, inspect_headers
from sentinel.reports import initialize_db, add_report, get_reports
from sentinel.assessment import build_assessment

st.set_page_config(page_title="SENTINEL AI", page_icon="🛡️", layout="wide")
initialize_db()

st.markdown("""
<style>
.block-container {padding-top: 2rem; max-width: 1200px;}
.hero {padding: 1.5rem 1.7rem; border: 1px solid #dbe4f0; border-radius: 18px;
       background: linear-gradient(120deg,#eff6ff,#f5f3ff);}
.hero h1 {margin:0; color:#172554; letter-spacing:.04em;}
.hero p {color:#475569; margin:.4rem 0 0;}
.small-note {color:#64748b;font-size:.88rem;}
.metric-card {padding:1rem;border:1px solid #dbe4f0;border-radius:14px;}
</style>
<div class="hero">
<h1>🛡️ SENTINEL AI</h1>
<p>Digital Trust & Web Threat Intelligence Platform</p>
<p><b>ONE URL. MULTIPLE SIGNALS. CLEARER DECISIONS.</b></p>
</div>
""", unsafe_allow_html=True)

with st.sidebar:
    st.title("SENTINEL AI")
    page = st.radio("Navigate", ["Website Assessment", "Community Reports", "About & Limitations"])
    st.divider()
    st.caption("Hackathon prototype • Python + Streamlit + SQLite")

if page == "Website Assessment":
    st.subheader("Assess a website")
    st.write("Review URL patterns, TLS verification, HTTP security headers and community context together.")
    url = st.text_input("Website URL", placeholder="https://example.com")
    scan = st.button("Run assessment", type="primary", use_container_width=True)

    if scan:
        try:
            with st.spinner("Inspecting available signals…"):
                url_result = inspect_url(url)
                tls_result = inspect_tls(url_result["normalized_url"])
                header_result = inspect_headers(url_result["normalized_url"])
                reports = get_reports(url_result["hostname"])
                assessment = build_assessment(url_result, tls_result, header_result, reports)
                st.session_state["last_scan"] = {
                    "url": url_result, "tls": tls_result, "headers": header_result,
                    "reports": reports, "assessment": assessment
                }
        except Exception as exc:
            st.error(str(exc))

    result = st.session_state.get("last_scan")
    if result:
        a = result["assessment"]
        st.divider()
        st.subheader("Assessment overview")
        c1, c2, c3 = st.columns(3)
        c1.metric("URL risk indicators", f'{result["url"]["score"]}/100')
        c2.metric("Combined heuristic", f'{a["score"]}/100')
        c3.metric("Community reports", a["community_report_count"])
        color = {"LOW":"🟢","MEDIUM":"🟠","HIGH":"🔴"}[a["band"]]
        st.markdown(f"### {color} {a['band']} indicated risk")
        st.caption(a["disclaimer"])

        tab1, tab2, tab3, tab4 = st.tabs(["URL analysis", "TLS certificate", "Security headers", "Community context"])
        with tab1:
            st.write("**Normalized URL:**", result["url"]["normalized_url"])
            st.write("**Hostname:**", result["url"]["hostname"])
            for flag in result["url"]["flags"]:
                st.write("•", flag)
        with tab2:
            st.write("**Status:**", result["tls"].get("status"))
            st.info(result["tls"].get("message", "No additional details."))
            if result["tls"].get("issuer"):
                st.json({"issuer": result["tls"]["issuer"], "subject": result["tls"]["subject"],
                         "expires": result["tls"]["not_after"]})
        with tab3:
            st.info(result["headers"].get("message", "No header details."))
            if result["headers"].get("headers"):
                rows = [{"Header": k, "Detected": "Yes" if v["present"] else "No",
                         "Value": v["value"], "Purpose": v["meaning"]}
                        for k, v in result["headers"]["headers"].items()]
                st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        with tab4:
            st.write("Reports are community-submitted and are not automatically verified.")
            if result["reports"]:
                st.dataframe(pd.DataFrame(result["reports"]), use_container_width=True, hide_index=True)
            else:
                st.write("No reports stored for this hostname.")
        with st.expander("Why did SENTINEL produce this assessment?"):
            for reason in a["reasons"]:
                st.write("•", reason)
            st.caption("The combined score is a prototype heuristic. Missing headers and community reports must be interpreted in context.")

elif page == "Community Reports":
    st.subheader("Community threat intelligence")
    st.write("Submit a report to the local prototype database. Do not include passwords, personal data or confidential information.")
    with st.form("report_form"):
        domain = st.text_input("Domain / hostname", placeholder="example.com")
        report_type = st.selectbox("Report type", ["Phishing suspicion", "Impersonation", "Malware warning", "Scam / fraud", "Other"])
        description = st.text_area("What did you observe?")
        reporter = st.text_input("Reporter name (optional)")
        submitted = st.form_submit_button("Submit report", type="primary")
        if submitted:
            clean_domain = domain.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
            if not clean_domain or "." not in clean_domain or not description.strip():
                st.error("Enter a valid-looking domain and a short description.")
            else:
                add_report(clean_domain, report_type, description, reporter)
                st.success("Report saved locally. It is unverified and does not prove malicious activity.")
    st.divider()
    st.subheader("Recent submissions")
    reports = get_reports()
    if reports:
        st.dataframe(pd.DataFrame(reports), use_container_width=True, hide_index=True)
    else:
        st.info("No community reports have been submitted yet.")

else:
    st.subheader("About SENTINEL AI")
    st.write("SENTINEL AI brings multiple web-trust signals into one explainable workflow.")
    st.markdown("""
    **Prototype modules**
    - URL pattern heuristics
    - TLS certificate verification
    - HTTP security-header observations
    - SQLite community-report storage
    - Explainable risk summary

    **Important limitations**
    - This is not a malware scanner, penetration test or certified security rating.
    - The score is a hand-built heuristic, not a trained AI/ML model.
    - HTTPS does not prove a site is benign.
    - Missing security headers do not prove a site is malicious.
    - Community reports may be inaccurate or unverified.
    - Network checks are best-effort and can fail because of DNS, firewalls, rate limits or site behaviour.
    """)
    st.info("Before production: validate scoring against labelled safe/malicious URLs, measure precision/recall and false-positive rates, harden network fetching, and add trusted threat-intelligence feeds.")

st.divider()
st.markdown('<p class="small-note">SENTINEL AI • Hackathon prototype • Findings are indicators, not a safety guarantee.</p>', unsafe_allow_html=True)
