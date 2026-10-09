# 🕵️ Student Lab Guide: Detecting Phishing Emails

This hands-on guide walks students through identifying social engineering and technical red flags in phishing emails using both **manual inspection** and the **automated [analyzer.py](file:///c:/Users/Cyberflex/Documents/email-analyzer/analyzer.py) tool**.

---

## 🎯 Lab Objectives
1. Understand the anatomy of a `.eml` (Electronic Mail Format) file.
2. Identify email header spoofing and delivery path discrepancies.
3. Recognize psychological triggers and social engineering tactics.
4. Detect high-risk URLs (raw IP addresses and unencrypted endpoints).
5. Run automated triage with `analyzer.py` to calculate risk severity.

---

## 🧪 Exercise File
- **Target Email**: [`student_lab_phish.eml`](file:///c:/Users/Cyberflex/Documents/email-analyzer/student_lab_phish.eml)

---

## 🔍 Step-by-Step Detection Workflow for Students

### Step 1: Inspect the Email Headers (The "Return Address" Test)
When inspecting an email in a text editor or mail client, examine the raw headers before trusting the display name:

1. Look at the **`From:`** header:
   ```text
   From: "Global Payroll & IT Support" <helpdesk@corporate-services.example>
   ```
   *The sender presents an authoritative, friendly display name.*
2. Check the **`Reply-To:`** header:
   ```text
   Reply-To: "Security Desk" <collector-mailbox@external-gateway.example>
   ```
3. **The Red Flag**: The domain in `Reply-To` (`external-gateway.example`) differs from `corporate-services.example`. 
   > **Why attackers do this**: If the victim hits "Reply", the response routes straight to an external mailbox controlled by the adversary rather than the internal IT team.

---

### Step 2: Scrutinize the Psychological Triggers (Social Engineering)
Phishing emails rely on cognitive pressure to bypass critical thinking. Inspect the body text for:

1. **Artificial Urgency & Coercion**:
   - *"URGENT NOTICE"*, *"ACTION REQUIRED IMMEDIATELY"*, *"within 24 hours"*
2. **Fear of Negative Consequences**:
   - *"profile will be suspended"*, *"delay payroll routing"*
3. **Call to Immediate Action**:
   - *"login immediately to verify your account"*, *"update password credentials"*
4. **The Red Flag**: Legitimate corporate IT teams rarely combine account termination deadlines with payroll delays in an unannounced email.

---

### Step 3: Analyze the Hyperlinks (The Destination Test)
Never click on email links during an investigation. Inspect their plain-text target:

1. Locate the embedded URL:
   ```text
   http://192.168.1.150/portal/auth-verify
   ```
2. **Red Flags**:
   - **Raw IP Address**: Legitimate corporate organizations use registered domain names with valid SSL/TLS certificates (e.g., `https://identity.company.com`), not bare IP addresses like `192.168.1.150`.
   - **Insecure Protocol (`http://`)**: A login or verification page should never operate over plain unencrypted HTTP.
   - **Bypassing DNS**: Attackers frequently use raw IPs to bypass domain reputation blocklists and dynamic DNS takedowns.

---

### Step 4: Run the Automated Analyzer
Open your terminal in the project directory and run the triage engine:

```bash
python analyzer.py student_lab_phish.eml
```

#### Expected Output Analysis
```text
🔬 Triaging: student_lab_phish.eml
==================================================
Subject: Urgent: Action Required - Mandatory Employee Account Verification
From:    Global Payroll & IT Support <helpdesk@corporate-services.example>
--------------------------------------------------
🚨 DETECTED INDICATORS:
  [-] Mismatched Reply-To address! Sender: Global Payroll & IT Support <helpdesk@corporate-services.example> | Reply-To: Security Desk <collector-mailbox@external-gateway.example>
  [-] Urgency/Phishing keyword flagged: 'verify your account'
  [-] Urgency/Phishing keyword flagged: 'update password'
  [-] Urgency/Phishing keyword flagged: 'urgent'
  [-] Urgency/Phishing keyword flagged: 'action required'
  [-] Urgency/Phishing keyword flagged: 'suspended'
  [-] Urgency/Phishing keyword flagged: 'login immediately'
  [-] Urgency/Phishing keyword flagged: 'bank transfer'
  [-] Suspicious IP-based URL detected: http://192.168.1.150/portal/auth-verify

🔗 EXTRACTED URLS:
  • http://192.168.1.150/portal/auth-verify
--------------------------------------------------
📊 FINAL RISK SCORE: 100/100
🛡️ VERDICT: CRITICAL / HIGH RISK MALICIOUS 🔴
```

---

## 📝 Student Review Questions

1. Why is a mismatch between `From` and `Reply-To` one of the strongest technical indicators of spoofing?
2. If an email button says *"Click Here to Sign In"* but hover text reveals an IP address, what should your immediate next action be?
3. How does the automated analyzer extract text from both `text/plain` and `text/html` parts in a multipart email?
4. What additional checks (e.g., SPF, DKIM, VirusTotal API) could you implement to catch even more sophisticated phishing attacks?

---

## 💡 Instructor Answer Key & Technical Explanations

### Question 1: Why is a mismatch between `From` and `Reply-To` one of the strongest technical indicators of spoofing?
- **Answer**: 
  - The `From:` header designates the sender shown to the recipient in standard email clients. Attackers easily forge this field with a trusted organization's brand or email address (display spoofing).
  - However, because the attacker does not actually control the victim organization's mail server, any reply sent to the spoofed `From:` address would bounce or land in the legitimate team's inbox.
  - To intercept credentials, replies, or inquiries, the attacker injects an alternate **`Reply-To:`** header pointing to their own mailbox (often hosted on a disposable, free webmail, or bulletproof domain). When the recipient clicks "Reply", the email client silently routes the message to the `Reply-To` address instead of the visible sender.

---

### Question 2: If an email button says *"Click Here to Sign In"* but hover text reveals an IP address, what should your immediate next action be?
- **Answer**:
  - **Do NOT click the button or link**: A bare IP address (e.g., `http://192.168.1.150` or a public IP) is a major indicator of an attacker trying to bypass domain registration checks, reputation blocklists, or dynamic DNS takedowns.
  - **Do NOT enter credentials or download payloads**: Even opening the page can execute client-side drive-by exploits or log reconnaissance data.
  - **Capture and Report**: 
    1. Report the email immediately to the organization's Security Operations Center (SOC) or Phishing Response Team (e.g., via a "Report Phishing" button or forwarding as an RFC 822 attachment).
    2. Defang the URL (e.g., `hxxp://192[.]168[.]1[.]150/...`) for documentation to prevent colleagues from accidentally clicking it.
    3. Block the IP on perimeter firewalls / proxy filters.

---

### Question 3: How does the automated analyzer extract text from both `text/plain` and `text/html` parts in a multipart email?
- **Answer**:
  - Using Python's built-in `email` package, the script verifies if the message is compound by calling `msg.is_multipart()`.
  - For multipart emails, it calls **`msg.walk()`**, which recursively iterates through every MIME subpart tree (payload nodes).
  - For each part, it checks the MIME content type via **`part.get_content_type()`**:
    - If the content type is either `text/plain` or `text/html`, it decodes the raw byte payload safely using **`part.get_payload(decode=True).decode(errors='ignore')`**.
  - This concatenated string is then analyzed by regex pattern matching (`re.findall`) for URLs and scanned for phishing keywords.

---

### Question 4: What additional checks could you implement to catch even more sophisticated phishing attacks?
- **Answer**:
  1. **Email Authentication Protocols (SPF / DKIM / DMARC)**:
     - **SPF (Sender Policy Framework)**: Verifies if the sending mail server IP is authorized by the domain's DNS TXT record.
     - **DKIM (DomainKeys Identified Mail)**: Validates digital cryptographic signatures in headers to ensure the message was not tampered with in transit.
     - **DMARC (Domain-based Message Authentication, Reporting, and Conformance)**: Checks header alignment between SPF/DKIM and the `From:` header, enforcing quarantine/reject policies.
  2. **Threat Intelligence Feeds (VirusTotal, URLhaus, PhishTank APIs)**:
     - Query extracted URLs, domains, and IP addresses in real time against global threat reputation databases.
  3. **Attachment Hashing & Sandboxing**:
     - Extract MIME attachments, compute SHA-256 hashes, query malware databases, and flag high-risk executables or double extensions (e.g., `.pdf.exe`, `.iso`, `.vbs`).
  4. **Lookalike / Typosquatting Domain Analysis**:
     - Compute Levenshtein distance between sender domains and genuine brands (e.g., `micros0ft.com` vs `microsoft.com`).
