# PhishGuard | Enterprise Security Dashboard

PhishGuard is a comprehensive, AI-powered cybersecurity suite designed for real-time threat analysis, network reconnaissance, and domain intelligence. Built with a highly responsive, multi-threaded "Cyber-SOC" graphical interface.

## 🚀 Core Features

*   **AI Threat Intelligence:** Utilizes a Random Forest Machine Learning model trained on over 500,000 data points. It extracts 9 advanced architectural features from URLs to detect zero-day phishing links with high precision.
*   **Network Radar:** Performs Layer-2 ARP discovery to map out local network devices, returning IP and MAC addresses in real-time.
*   **Vulnerability Scanner:** Multi-threaded TCP port scanner that identifies open ports and exposed services on target IPs.
*   **Link Interceptor:** Safely unrolls masked short-links (e.g., bit.ly) to reveal the true destination without triggering malicious payloads.
*   **Domain OSINT:** Fetches global WHOIS metadata to verify domain registration dates, registrars, and server infrastructure.

## 💻 Technical Stack

*   **Language:** Python 3.11
*   **AI/ML Engine:** Scikit-Learn (Random Forest Classifier), Pandas, NumPy
*   **GUI Framework:** CustomTkinter (Thread-safe implementation)
*   **Networking:** Socket, Requests, Python-Whois

## ⚠️ Important Note for Windows Users

The **Network Radar** feature relies on sending raw Layer-2 ARP packets. To use this specific feature on a Windows operating system, the system must have the **[Npcap driver](https://npcap.com/#download)** installed (this is often pre-installed if you have Wireshark). 
*(Linux and macOS users do not need Npcap, but may need to run the application with `sudo` privileges).*

## ⚙️ Installation & Usage

To run this application locally, you will need Python installed on your system.

### 1. Clone the repository
```bash
git clone https://github.com/Sumitsaini101/PhishGuard-Detector.git
cd PhishGuard-Detector
```

### 2. Install the required dependencies
```bash
pip install -r requirements.txt
```

### 3. Launch the dashboard
```bash
python gui/app_gui.py
```

## 🧠 AI Model Interpretability
The phishing detection engine relies on 9 heavily engineered features. Ranked by decision impact:

1. Domain Length
2. Total URL Length
3. Total Dots (Subdomain indicator)
4. Suspicious Keyword Count
5. Hyphens in Domain
6. Subdomain Count
7. HTTPS Status
8. Raw IP Address Detection
9. Presence of '@' Symbol

---

