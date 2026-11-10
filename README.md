# SENTINEL AI — Digital Trust & Web Threat Intelligence Platform

A runnable Streamlit hackathon prototype based on the supplied presentation.

## Features
- URL-pattern heuristic analysis
- TLS certificate-chain and hostname verification
- HTTP security-header observations
- SQLite community-report storage
- Explainable 0–100 prioritisation score with LOW / MEDIUM / HIGH bands

## Run locally
1. Install Python 3.10 or newer.
2. Open a terminal in this folder.
3. Create and activate a virtual environment (recommended).
4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
5. Start the app:
   ```bash
   streamlit run app.py
   ```

## Suggested team split
- Member 1: URL heuristics, TLS and HTTP header checks.
- Member 2: Streamlit interface, SQLite reports, integration and testing.

## Important technical honesty
This is a modular prototype, not a trained AI model. The score is a transparent heuristic, not an attack probability. Community reports are unverified and do not directly increase the score. HTTPS is not proof that a site is benign. Missing headers are not proof of maliciousness.

## Safety notes
The network module blocks localhost and hosts resolving to non-public IP addresses and limits redirects. This is a basic prototype safeguard, not a complete production-grade SSRF defence. Do not use it to scan systems without authorization. Avoid submitting personal or confidential information in community reports.

## Before the hackathon demo
- Test with a small, documented set of known safe and deliberately suspicious URLs.
- Show one example with HTTPS and one with HTTP.
- Demonstrate a community report and how it appears as separate context.
- Explain why a low score is not a guarantee of safety.
- Record limitations and future work honestly.
