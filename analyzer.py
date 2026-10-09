import email
from email import policy
import re
import sys
from urllib.parse import urlparse

# Ensure Windows terminal handles UTF-8 emoji outputs cleanly
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

class PhishingAnalyzer:
    def __init__(self):
        # High-risk urgency and financial keywords
        self.suspicious_keywords = [
            "verify your account", "update password", "urgent", "action required", 
            "suspended", "login immediately", "bank transfer", "crypto", "free gift"
        ]

    def parse_eml(self, file_path):
        """Loads and parses the raw .eml file structure."""
        try:
            with open(file_path, 'rb') as f:
                # Use standard policy to cleanly expose header pairs
                msg = email.message_from_binary_file(f, policy=policy.default)
            return msg
        except Exception as e:
            print(f"[-] Error loading file: {e}")
            return None

    def analyze_headers(self, msg):
        """Inspects identity fields for discrepancies."""
        score = 0
        flags = []
        
        sender = msg.get('From', '')
        reply_to = msg.get('Reply-To', '')
        
        # Flag 1: Mismatched identity delivery pathways
        if reply_to and (reply_to.lower() != sender.lower()):
            score += 35
            flags.append(f"Mismatched Reply-To address! Sender: {sender} | Reply-To: {reply_to}")
            
        return score, flags

    def analyze_body(self, msg):
        """Extracts text content and scrutinizes embedded hyperlinks."""
        score = 0
        flags = []
        urls = []
        
        # Safely extract text body regardless of text/plain vs text/html
        body_text = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain" or content_type == "text/html":
                    try:
                        body_text += part.get_payload(decode=True).decode(errors='ignore')
                    except Exception:
                        pass
        else:
            body_text = msg.get_payload(decode=True).decode(errors='ignore')

        # Flag 2: Keyword Scrutiny
        for kw in self.suspicious_keywords:
            if kw in body_text.lower():
                score += 10
                flags.append(f"Urgency/Phishing keyword flagged: '{kw}'")

        # Flag 3: URL Pattern Extraction
        # Regex to locate URLs in body text
        found_urls = re.findall(r'https?://[^\s<>"]+', body_text)
        for url in set(found_urls):
            urls.append(url)
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Simple check for IP addresses used as domains or overly long domain strings
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
                score += 30
                flags.append(f"Suspicious IP-based URL detected: {url}")
                
        return score, flags, urls

    def run_triage(self, file_path):
        """Aggregates security layers to calculate final severity risk."""
        msg = self.parse_eml(file_path)
        if not msg:
            return

        print(f"\n🔬 Triaging: {file_path}")
        print("="*50)
        print(f"Subject: {msg.get('Subject', '[No Subject Present]')}")
        print(f"From:    {msg.get('From', 'Unknown')}")
        print("-"*50)

        header_score, header_flags = self.analyze_headers(msg)
        body_score, body_flags, extracted_urls = self.analyze_body(msg)
        
        total_risk = min(header_score + body_score, 100) # Cap score at 100
        all_flags = header_flags + body_flags

        print("🚨 DETECTED INDICATORS:")
        if not all_flags:
            print("  [+] No obvious anomalies detected.")
        else:
            for flag in all_flags:
                print(f"  [-] {flag}")

        print("\n🔗 EXTRACTED URLS:")
        for u in extracted_urls:
            print(f"  • {u}")

        # Verdict logic
        if total_risk >= 70:
            verdict = "CRITICAL / HIGH RISK MALICIOUS 🔴"
        elif total_risk >= 35:
            verdict = "SUSPICIOUS / INVESTIGATE FURTHER 🟡"
        else:
            verdict = "LOW RISK / SAFE 🟢"

        print("-"*50)
        print(f"📊 FINAL RISK SCORE: {total_risk}/100")
        print(f"🛡️ VERDICT: {verdict}\n")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python analyzer.py <path_to_email.eml>")
    else:
        analyzer = PhishingAnalyzer()
        analyzer.run_triage(sys.argv[1])