# 🛡️ PhishGuard: Enterprise Security Dashboard

PhishGuard is a comprehensive, multi-tool cybersecurity application designed to detect zero-day phishing threats, perform local network reconnaissance, audit endpoint vulnerabilities, and enforce strict Zero-Trust Identity Access Management (IAM).

Built with **Python**, **CustomTkinter**, and **Machine Learning (Random Forest)**.

---

## ✨ Core Features

### 1. Zero-Trust 3-Factor Authentication (IAM)
* **Factor 1 (Knowledge):** SHA-256 Hashed Password Verification.
* **Factor 2 (Possession):** SMTP-based Email OTP Verification.
* **Factor 3 (Inherence):** Cryptographic lock to the user's physical Network Card MAC Address.
* *Includes a dynamic device-transfer protocol for authorized hardware migration.*

### 2. AI Threat Intelligence (Zero-Day URL Scanner)
* Extracts 9 discrete lexical and structural features from suspected URLs.
* Scores threats using a trained Random Forest Classifier model.
* Operates entirely offline without relying on external API blacklists.

### 3. Layer-2 Network Radar
* Broadcasts raw ARP packets across the local subnet.
* Discovers hidden devices, identifying IP and physical MAC addresses.

### 4. Vulnerability Port Scanner
* Multi-threaded TCP port matrix auditor.
* Quickly maps open ports and active services on target IP addresses or domains.

### 5. OSINT & Link Interceptor
* **Link Interceptor:** Safely unrolls shortened/obfuscated URLs (e.g., bit.ly) to reveal their true destination without executing malicious payloads.
* **Domain OSINT:** Queries global WHOIS databases to extract domain creation dates and registrar identities.

---

## 💻 Technical Stack

*   **Language:** Python 3.11
*   **AI/ML Engine:** Scikit-Learn (Random Forest Classifier), Pandas, NumPy
*   **GUI Framework:** CustomTkinter (Thread-safe implementation)
*   **Networking:** Socket, Requests, Python-Whois

---

## ⚠️ Important Prerequisites

1. **For Windows Users (Network Radar):** 
   The Network Radar relies on sending raw Layer-2 ARP packets. To use this feature on Windows, the system must have the **[Npcap driver](https://npcap.com/#download)** installed (often pre-installed if you have Wireshark). 
2. **Gmail App Password (for 3FA OTP):**
   To use the Registration and Login systems, the app requires an SMTP server to send OTPs. You must generate a 16-digit Google App Password.

---

## ⚙️ Installation & Setup

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/PhishGuard.git
cd PhishGuard
```

### 2. Install required dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure the Authentication Engine
Before running the application, you must provide your SMTP credentials to allow the system to send OTPs.

1. Open `auth_manager.py` in your code editor.
2. Locate the `send_otp` function.
3. Replace the placeholder credentials with your real testing email and 16-digit App Password:

```python
sender_email = "your_actual_email@gmail.com" 
app_password = "your_16_digit_app_password"
```

### 4. Launch the Dashboard
```bash
python gui/app_gui.py
```

---

## 🚀 Usage Guide

1. **Device Enrollment:** Launch the application and click **"Register Device"** to bind your hardware MAC address and verify your email via OTP.
2. **Secure Login:** Log in using your Username, Password, and the fresh 6-digit Email OTP sent to your registered inbox.
3. **Dashboard Navigation:** Utilize the intuitive CustomTkinter sidebar navigation to switch smoothly between modules:
   * **AI Scanner:** Paste suspicious URLs to evaluate zero-day threats.
   * **Network Radar:** Scan the local subnet to audit connected assets.
   * **Port Scanner:** Audit specific IPs or domains for exposed entry points.
   * **OSINT Hub:** Investigate domain ownership timelines and safely expand short links.

---

## 🛑 Disclaimer

This tool is developed for educational and authorized enterprise auditing purposes only. Scanning networks or endpoints without prior explicit permission from the owner is illegal and unethical. Use responsibly.
