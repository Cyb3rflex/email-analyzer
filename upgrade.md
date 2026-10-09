# 🚀 Proposed Project Upgrades & Roadmap

Enhance the **Email Phishing Analyzer** with live threat intelligence, attachment inspection, and interactive user interfaces.

---

## 📋 Planned Milestones

### 1. 🌐 Live Threat Intelligence Lookup (e.g., VirusTotal API)
- [ ] **Automated URL & Domain Reputation**: Query extracted URLs and domains against the VirusTotal API.
- [ ] **Threat Blocklist Correlation**: Check against active community threat feeds (e.g., URLhaus, PhishTank, Google Safe Browsing).
- [ ] **Dynamic Severity Adjustments**: Incorporate real-time detection ratios directly into the risk triage scoring formula.

### 2. 📎 Attachment Hash Extractor & Payload Inspection
- [ ] **MIME Attachment Extraction**: Safely decouple and extract email attachments into an isolated quarantine folder.
- [ ] **Cryptographic Hashing**: Calculate SHA-256, SHA-1, and MD5 hashes for each payload.
- [ ] **Dangerous Extension Detection**: Flag high-risk extensions (`.exe`, `.scr`, `.vbs`, `.iso`, `.hta`, `.bat`) and deceptive double extensions (e.g., `invoice.pdf.exe`).
- [ ] **Hash Lookup**: Query calculated SHA-256 hashes against malware repositories to identify known malicious samples.

### 3. 🖥️ Interactive Web UI Dashboard
- [ ] **Drag-and-Drop Interface**: Provide a web portal to drop `.eml` files for instant real-time analysis.
- [ ] **Visual Threat Breakdown**: Display responsive cards, risk meters, and color-coded flags for headers and keywords.
- [ ] **URL Defanging & Safe Previews**: Defang links automatically (e.g., `hxxp://...` / `[.]`) to eliminate accidental click risks.
- [ ] **Tech Stack**: Lightweight Python framework (Flask or FastAPI) paired with a clean, modern UI.

### 4. 🛡️ Email Authentication Verification *(Bonus)*
- [ ] **SPF, DKIM & DMARC Inspection**: Parse `Authentication-Results` and `Received-SPF` headers to flag failed email authentication.
- [ ] **Routing Hop Analysis**: Trace origin IP addresses through `Received:` header chains.

---

## 🛠️ Implementation Priority

| Priority | Feature | Complexity | Security Impact |
|:---:|:---|:---:|:---|
| **P1** | Attachment Extractor & Dangerous Extension Filter | Low | High |
| **P2** | VirusTotal API Integration (URLs & Hashes) | Medium | High |
| **P3** | Flask / Web UI Dashboard | Medium | Medium |
| **P4** | SPF / DKIM / DMARC Header Verification | High | High |
