# 📧 Phishing Email Analyzer

A lightweight, automated Python security tool designed to triage `.eml` files, extract threat indicators, analyze header anomalies, and score potential phishing threats.

---

## 🌟 Overview

The **Phishing Email Analyzer** parses raw email message files (`.eml`) and performs rapid static security analysis without requiring external dependencies. It inspects delivery pathways, scrutinizes body text for social engineering cues, extracts embedded hyperlinks, and calculates an overall risk score to help security analysts and users identify malicious communications.

---

## ✨ Features

- **Header Discrepancy Detection**: Checks for spoofed identities and mismatched `From` vs. `Reply-To` addresses.
- **Urgency & Phishing Keyword Scrutiny**: Flags high-risk psychological triggers (e.g., account suspension, urgent password updates, credential verifications, fraudulent financial transfers).
- **Embedded URL & IP Domain Extraction**: Parses embedded web links and flags bare IP addresses commonly used to bypass domain reputation filters.
- **Multipart Content Parsing**: Decodes both plain text (`text/plain`) and HTML (`text/html`) email structures safely.
- **Transparent Risk Scoring (0–100)**: Aggregates severity weights across header and body heuristics into an intuitive triage verdict.
- **Zero Third-Party Dependencies**: Built entirely using Python's standard library (`email`, `re`, `urllib.parse`, `sys`).

---

## 🚦 Risk Severity Matrix

| Score Range | Severity Level | Verdict | Recommended Action |
|:---:|:---:|:---:|:---|
| **70 – 100** | 🔴 **Critical** | `CRITICAL / HIGH RISK MALICIOUS` | Block sender, isolate message, purge from mailboxes, block extracted URLs. |
| **35 – 69** | 🟡 **Suspicious** | `SUSPICIOUS / INVESTIGATE FURTHER` | Verify authentication records (SPF/DKIM/DMARC), sandbox links, confirm with sender out-of-band. |
| **0 – 34** | 🟢 **Low Risk** | `LOW RISK / SAFE` | Normal email; no primary heuristic threat indicators flagged. |

---

## 📁 Project Structure

```text
email-analyzer/
├── analyzer.py                 # Core triage engine & CLI entry point
├── test_phish.eml              # Quick sample suspicious email for testing
├── student_lab_phish.eml       # Detailed multi-indicator malicious email for student labs
├── STUDENT_DETECTION_GUIDE.md  # Teaching guide & manual detection walkthrough
├── upgrade.txt                 # Roadmap & planned feature upgrades (Markdown-formatted)
└── README.md                   # Project documentation
```

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.8+** installed. No `pip install` required.

### Installation

Clone or download this repository:

```bash
git clone https://github.com/Cyb3rflex/email-analyzer.git
cd email-analyzer
```

---

## 💻 Usage

Run `analyzer.py` from the command line and supply the path to any target `.eml` file:

```bash
python analyzer.py <path_to_email.eml>
```

### Example: Triaging the Sample Phishing Email

```bash
python analyzer.py test_phish.eml
```

#### Expected Terminal Output

```text
🔬 Triaging: test_phish.eml
==================================================
Subject: Urgent: Action Required on Your Bank Account!
From:    security-alerts@trustedbank.com
--------------------------------------------------
🚨 DETECTED INDICATORS:
  [-] Mismatched Reply-To address! Sender: security-alerts@trustedbank.com | Reply-To: hacker-mailbox99@scamserver.net
  [-] Urgency/Phishing keyword flagged: 'verify your account'
  [-] Urgency/Phishing keyword flagged: 'login immediately'

🔗 EXTRACTED URLS:
  • http://192.168.1
--------------------------------------------------
📊 FINAL RISK SCORE: 55/100
🛡️ VERDICT: SUSPICIOUS / INVESTIGATE FURTHER 🟡
```

---

## 🔮 Roadmap & Upcoming Upgrades

Detailed upgrade plans are tracked in [`upgrade.txt`](file:///c:/Users/Cyberflex/Documents/email-analyzer/upgrade.txt):

1. **VirusTotal & Threat Intel Integration**: Query extracted URLs and domains against live reputation APIs.
2. **Attachment & File Hash Analysis**: Extract attachments, compute SHA-256 hashes, and flag double extensions (e.g. `invoice.pdf.exe`).
3. **Web Dashboard (Flask / Streamlit)**: Provide an interactive drag-and-drop web UI for seamless email analysis.
4. **Authentication Header Verification**: Automated parsing of SPF, DKIM, and DMARC `Authentication-Results` headers.

---

## ⚠️ Disclaimer

This tool is intended for security assessment, incident response triage, and educational purposes. Always analyze untrusted email files in an isolated environment and refrain from opening suspicious hyperlinks or attachments directly.
