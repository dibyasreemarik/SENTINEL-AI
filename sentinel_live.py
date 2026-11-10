import ipaddress
import re
import socket
import ssl
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, unquote, urljoin

import pandas as pd
import requests
import streamlit as st

DB_PATH = Path(__file__).resolve().parent / "sentinel_reports.db"
SUSPICIOUS_TERMS = {
    "login", "verify", "verification", "secure", "account", "update",
    "password", "banking", "wallet", "signin", "gift", "free", "bonus"
}
SECURITY_HEADERS = {
    "Content-Security-Policy": "Helps restrict which resources a page may load.",
    "Strict-Transport-Security": "Tells browsers to use HTTPS for future visits.",
    "X-Content-Type-Options": "Helps prevent MIME-type sniffing.",
    "X-Frame-Options": "Helps control whether the page can be embedded in frames.",
    "Referrer-Policy": "Controls how much referrer information is shared.",
}
REDIRECT_CODES = {301, 302, 303, 307, 308}


def inspect_url(raw_url):
    value = (raw_url or "").strip()
    if not value:
        raise ValueError("Enter a URL.")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a valid HTTP or HTTPS website URL.")
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    decoded = unquote(value)
    flags, points = [], 0
    if len(value) > 100:
        flags.append("Unusually long URL"); points += 10
    if len(host) > 50:
        flags.append("Unusually long hostname"); points += 8
    try:
        ipaddress.ip_address(host.strip("[]"))
        flags.append("URL uses an IP address instead of a domain"); points += 25
    except ValueError:
        pass
    if "@" in parsed.netloc:
        flags.append("Contains an @ symbol in the authority section"); points += 20
    if host.startswith("xn--") or ".xn--" in host:
        flags.append("Contains punycode / internationalized hostname"); points += 15
    if len([x for x in host.split(".") if x]) >= 5:
        flags.append("Many hostname subdomains"); points += 12
    found = sorted(t for t in SUSPICIOUS_TERMS if t in decoded.lower())
    if found:
        flags.append("Contains attention-grabbing terms: " + ", ".join(found))
        points += min(15, 5 + 2 * len(found))
    if re.search(r"%[0-9a-fA-F]{2}", value):
        flags.append("Contains percent-encoded characters"); points += 5
    if parsed.scheme.lower() == "http":
        flags.append("Uses HTTP rather than HTTPS"); points += 8
    if not flags:
        flags.append("No listed URL-pattern indicators detected")
    return {"normalized_url": value, "hostname": host, "scheme": parsed.scheme.lower(),
            "flags": flags, "score": min(points, 100)}


def public_host(host):
    if host.lower() in {"localhost", "localhost.localdomain"}:
        raise ValueError("Localhost targets are blocked in this prototype.")
    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        addresses = list({ipaddress.ip_address(x[4][0]) for x in infos})
    if not addresses or any(not ip.is_global for ip in addresses):
        raise ValueError("Target resolves to a non-public IP address and was blocked.")


def inspect_tls(url):
    parsed = urlparse(url)
    host = parsed.hostname
    if parsed.scheme != "https":
        return {"status": "Not applicable", "verified": False,
                "message": "The submitted URL does not use HTTPS."}
    try:
        public_host(host)
        context = ssl.create_default_context()
        with socket.create_connection((host, parsed.port or 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                cert = secure_sock.getpeercert()
        return {"status": "Verified", "verified": True,
                "issuer": dict(x[0] for x in cert.get("issuer", [])),
                "subject": dict(x[0] for x in cert.get("subject", [])),
                "not_after": cert.get("notAfter", "Not provided"),
                "message": "Certificate chain and hostname verification succeeded."}
    except Exception as exc:
        return {"status": "Failed / unavailable", "verified": False,
                "message": f"TLS verification could not be completed: {exc}"}


def inspect_headers(url):
    current = url
    try:
        for _ in range(4):
            parsed = urlparse(current)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError("Redirected to an unsupported URL.")
            public_host(parsed.hostname)
            response = requests.get(current, timeout=7, allow_redirects=False, stream=True,
                                    headers={"User-Agent": "SentinelAI-Hackathon-Prototype/1.0"})
            if response.status_code in REDIRECT_CODES:
                location = response.headers.get("Location")
                response.close()
                if not location:
                    break
                current = urljoin(current, location)
                continue
            headers, status = dict(response.headers), response.status_code
            response.close()
            observations = {}
            for name, meaning in SECURITY_HEADERS.items():
                value = headers.get(name)
                observations[name] = {"present": bool(value), "value": value or "Not detected",
                                      "meaning": meaning}
            return {"status_code": status, "final_url": current, "headers": observations,
                    "message": "Headers retrieved. Missing headers are observations, not proof of compromise."}
        raise ValueError("Too many redirects or redirect could not be followed.")
    except Exception as exc:
        return {"status_code": None, "final_url": current, "headers": {},
                "message": f"Header inspection unavailable: {exc}"}


def db_connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_db():
    with db_connect() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL,
            report_type TEXT NOT NULL, description TEXT NOT NULL,
            reporter TEXT, created_at TEXT NOT NULL)""")


def add_report(domain, report_type, description, reporter=""):
    with db_connect() as conn:
        conn.execute("""INSERT INTO reports(domain, report_type, description, reporter, created_at)
                        VALUES (?, ?, ?, ?, ?)""",
                     (domain.strip().lower(), report_type, description.strip(), reporter.strip(),
                      datetime.now(timezone.utc).isoformat(timespec="seconds")))


def get_reports(domain=None, limit=100):
    with db_connect() as conn:
        if domain:
            rows = conn.execute("SELECT * FROM reports WHERE domain=? ORDER BY id DESC LIMIT ?",
                                (domain.strip().lower(), limit)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM reports ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(row) for row in rows]


def build_assessment(url_result, tls_result, header_result, reports):
    score = int(url_result["score"])
    reasons = list(url_result["flags"])
    if tls_result.get("status") == "Failed / unavailable" and url_result["scheme"] == "https":
        score += 15
        reasons.append("TLS verification failed or was unavailable")
    headers = header_result.get("headers", {})
    missing = [name for name, item in headers.items() if not item["present"]]
    score += min(20, len(missing) * 4)
    if missing:
        reasons.append("Missing observed security headers: " + ", ".join(missing))
    score = min(score, 100)
    band = "LOW" if score <= 19 else ("MEDIUM" if score <= 49 else "HIGH")
    return {"score": score, "band": band, "reasons": reasons,
            "missing_headers": missing, "community_report_count": len(reports),
            "disclaimer": "Heuristic prioritisation only. This is not a probability of attack or a guarantee of safety."}


st.set_page_config(page_title="SENTINEL AI", page_icon="🛡️", layout="wide")
initialize_db()
st.markdown("""
<style>
.block-container{padding-top:2rem;max-width:1200px}
.hero{padding:1.5rem 1.7rem;border:1px solid #dbe4f0;border-radius:18px;
background:linear-gradient(120deg,#eff6ff,#f5f3ff)}
.hero h1{margin:0;color:#172554;letter-spacing:.04em}
.hero p{color:#475569;margin:.4rem 0 0}
.small-note{color:#64748b;font-size:.88rem}
</style>
<div class="hero"><h1>🛡️ SENTINEL AI</h1>
<p>Digital Trust & Web Threat Intelligence Platform</p>
<p><b>ONE URL. MULTIPLE SIGNALS. CLEARER DECISIONS.</b></p></div>
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
    if st.button("Run assessment", type="primary", use_container_width=True):
        try:
            with st.spinner("Inspecting available signals…"):
                ur = inspect_url(url)
                tls = inspect_tls(ur["normalized_url"])
                hdr = inspect_headers(ur["normalized_url"])
                reports = get_reports(ur["hostname"])
                st.session_state["last_scan"] = {
                    "url": ur, "tls": tls, "headers": hdr, "reports": reports,
                    "assessment": build_assessment(ur, tls, hdr, reports)}
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
        icon = {"LOW": "🟢", "MEDIUM": "🟠", "HIGH": "🔴"}[a["band"]]
        st.markdown(f"### {icon} {a['band']} indicated risk")
        st.caption(a["disclaimer"])
        t1, t2, t3, t4 = st.tabs(["URL analysis", "TLS certificate", "Security headers", "Community context"])
        with t1:
            st.write("**Normalized URL:**", result["url"]["normalized_url"])
            st.write("**Hostname:**", result["url"]["hostname"])
            for item in result["url"]["flags"]:
                st.write("•", item)
        with t2:
            st.write("**Status:**", result["tls"].get("status"))
            st.info(result["tls"].get("message", "No additional details."))
            if result["tls"].get("issuer"):
                st.json({"issuer": result["tls"]["issuer"], "subject": result["tls"]["subject"],
                         "expires": result["tls"]["not_after"]})
        with t3:
            st.info(result["headers"].get("message", "No header details."))
            if result["headers"].get("headers"):
                rows = [{"Header": k, "Detected": "Yes" if v["present"] else "No",
                         "Value": v["value"], "Purpose": v["meaning"]}
                        for k, v in result["headers"]["headers"].items()]
                st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        with t4:
            st.write("Community reports are submitted by users and are not automatically verified.")
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
    st.write("Submit a report to the prototype database. Do not include passwords, personal data or confidential information.")
    with st.form("report_form"):
        domain = st.text_input("Domain / hostname", placeholder="example.com")
        report_type = st.selectbox("Report type", ["Phishing suspicion", "Impersonation", "Malware warning", "Scam / fraud", "Other"])
        description = st.text_area("What did you observe?")
        reporter = st.text_input("Reporter name (optional)")
        submitted = st.form_submit_button("Submit report", type="primary")
        if submitted:
            clean = domain.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
            if not clean or "." not in clean or not description.strip():
                st.error("Enter a valid-looking domain and a short description.")
            else:
                add_report(clean, report_type, description, reporter)
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
