# Matrix: Frequently Asked Questions (FAQ)

## 🟢 Trivial / General

### **What is Matrix?**
Matrix is an autonomous security scanner that uses a multi-agent system to discover and validate vulnerabilities in web applications, APIs, and code repositories.

### **How do I start a scan?**
Navigate to the "Hub" in the web interface, enter a target URL (e.g., `https://example.com`), and click "Launch Scan."

### **Can I export the results?**
Yes. Matrix supports exporting professional CISO-grade reports in **PDF**, **JSON** (for automation), and **Markdown** (for developer documentation).

---

## 🟡 Intermediate / Technical

### **What is the "Intelligence Mesh," and why is it better than a linear scanner?**
Linear scanners run a fixed sequence of checks. Matrix’s **Intelligence Mesh** allows agents to share context in real-time. For example, if the GitHub Agent finds a hardcoded API endpoint, it automatically informs the API Security Agent to prioritize testing that specific endpoint.

### **How does Matrix handle single-page applications (SPAs)?**
Matrix uses an intelligent crawler that understands modern frontend frameworks (React, Vue, etc.). It identifies client-side routes and interacts with dynamic elements to surface hidden API endpoints that traditional crawlers miss.

### **What is an "Exploitability Gate"?**
This is a deterministic validation layer. If an agent suspects a vulnerability (e.g., SQLi), the Exploitability Gate attempts a safe, validated proof of concept. If the proof fails, the finding is either downgraded or filtered out to prevent false positive fatigue.

---

## 🔴 Tricky / Expert

### **Does the use of LLMs (Groq) introduce "hallucinated" vulnerabilities?**
No. Matrix uses AI for **analysis and correlation**, not for detection. The core detection is handled by deterministic security agents. The AI (Llama 3 via Groq) then reviews the raw evidence to help explain the impact and remediation. A finding is only reported if evidence (request/response logs) exists.

### **How do you prevent Matrix from becoming a DDoS tool?**
Matrix is built with an **Adaptive Throttling Engine**. It monitors server response times and automatically backs off if the target starts showing signs of stress (e.g., 503 errors or increased latency). Users can also set strict per-minute request limits.

### **How does "WAF Evasion" actually work? Is it dangerous?**
WAF evasion techniques involve manipulating HTTP headers and payload encoding to test if defensive layers can be bypassed. It is **disabled by default** and requires explicit user consent, as these techniques can be more aggressive and may trigger security alerts in managed environments.

### **Is Matrix legal to use on any website?**
**No.** Matrix is a powerful security tool. You should **only** use it on applications and repositories you own or have explicit written permission to test. Unauthorized scanning can be illegal under various computer misuse laws (like the CFAA in the US or similar global regulations).

### **How does Matrix distinguish between a "False Positive" and a "Difficult-to-Prove" vulnerability?**
This is handled by our **Confidence Evolution** metric. A finding starts with low confidence based on a signature match. As more evidence is gathered (e.g., a time-based delay is confirmed three times with different values), the confidence score increases. If confidence stays below a certain threshold (e.g., 70%), it is flagged for "Manual Review" rather than as a "Confirmed Finding."

---

## 💎 The "Judge" Question

### **"Why shouldn't I just use a free tool like OWASP ZAP or a premium one like Burp Suite?"**
- **vs. ZAP**: Matrix is autonomous. While ZAP requires a human-in-the-loop to drive the scan and interpret results, Matrix's multi-agent system orchestrates the entire process and provides AI-backed summaries.
- **vs. Burp Suite**: Burp is the gold standard for manual testing. Matrix is designed for **autonomous scale**. It bridges the gap between simple automated "vulnerability scanners" and high-cost "penetration testing services."

---
