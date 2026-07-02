# PhishGuard | Enterprise Security Dashboard

PhishGuard is a comprehensive, AI-powered cybersecurity suite designed for real-time threat analysis, network reconnaissance, and domain intelligence. Built with a highly responsive, multi-threaded "Cyber-SOC" graphical interface.

## 🚀 Core Features

*   **Fake Link Scanner:** Utilizes a Random Forest Machine Learning model trained on over 500,000 data points. It extracts 9 advanced architectural features from URLs to detect zero-day phishing links with high precision.
*   **Network Radar:** Performs Layer-2 ARP discovery to map out local network devices, returning IP and MAC addresses in real-time.
*   **Vulnerability Scanner:** Multi-threaded TCP port scanner that identifies open ports and exposed services on target IPs.
*   **Link Interceptor:** Safely unrolls masked short-links (e.g., bit.ly) to reveal the true destination without triggering malicious payloads.
*   **Domain OSINT:** Fetches global WHOIS metadata to verify domain registration dates, registrars, and server infrastructure.

## 💻 Technical Stack

*   **Language:** Python 3.11
*   **AI/ML Engine:** Scikit-Learn (Random Forest Classifier), Pandas, NumPy
*   **GUI Framework:** CustomTkinter (Thread-safe implementation)
*   **Networking:** Socket, Scapy, Requests, Python-Whois

## ⚙️ Installation & Usage

### Option 1: Run the Standalone Executable
Navigate to the `dist/` folder and launch **`PhishGuard.exe`**. No installation required.

### Option 2: Run from Source
1. Clone the repository:
   ```bash
   git clone [https://github.com/Sumitsaini101/PhishGuard-Detector.git](https://github.com/Sumitsaini101/PhishGuard-Detector.git)