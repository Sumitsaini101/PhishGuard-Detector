import customtkinter as ctk
import sys
import os
import threading
import joblib
import socket
import traceback

# --- 1. BULLETPROOF PATH RESOLUTION (Fixes the .exe AI bug) ---
def get_resource_path(relative_path):
    """ Dynamically finds files whether running in VS Code or as a PyInstaller .exe """
    try:
        # PyInstaller creates a temporary folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    return os.path.join(base_path, relative_path)

# Ensure we can import from the 'core' folder
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.feature_extractor import extract_features
from core.network_scanner import scan_network
from core.port_scanner import scan_target
from core.url_unshortener import unroll_url
from core.whois_lookup import get_domain_intel

# Load AI Model Safely
try:
    model_path = get_resource_path("core/phishing_model.pkl")
    model = joblib.load(model_path)
except Exception as e:
    print(f"[-] AI Model Load Error: {e}")
    model = None

# UI Setup
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class PhishGuardApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("PhishGuard | Enterprise Security Dashboard")
        self.geometry("1100x700")
        self.after(0, lambda: self.state('zoomed'))

        self.accent = "#00f2ff"
        
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color="#1a1c25")
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        ctk.CTkLabel(self.sidebar, text="PHISHGUARD", font=ctk.CTkFont(size=24, weight="bold"), text_color=self.accent).pack(pady=30)

        buttons = [
            ("AI Link Scanner", self.show_phish_frame),
            ("Network Radar", self.show_net_frame),
            ("Port Scanner", self.show_port_frame),
            ("Link Interceptor", self.show_intel_frame),
            ("Domain OSINT", self.show_whois_frame)
        ]
        
        for text, cmd in buttons:
            ctk.CTkButton(self.sidebar, text=text, command=cmd, fg_color="transparent", 
                          border_width=1, border_color=self.accent, hover_color="#2a2d3e").pack(pady=10, padx=20, fill="x")

        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, padx=30, pady=30, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        
        self.show_phish_frame()

    def clear(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    # --- AI SCANNER ---
    def show_phish_frame(self):
        self.clear()
        ctk.CTkLabel(self.main_frame, text="AI Threat Intelligence", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=30)
        self.url_in = ctk.CTkEntry(self.main_frame, placeholder_text="Enter URL...", width=500)
        self.url_in.pack(pady=10)
        self.res = ctk.CTkLabel(self.main_frame, text="", font=ctk.CTkFont(size=18))
        self.res.pack(pady=20)
        ctk.CTkButton(self.main_frame, text="Analyze Link", command=self.run_ai).pack()

    def run_ai(self):
        if model is None:
            self.res.configure(text="🚨 ERROR: AI Model file not found!", text_color="red")
            return
        try:
            features = extract_features(self.url_in.get())
            pred = model.predict([features])
            is_phishing = (pred[0] == 'bad')
            self.res.configure(text="🚨 DANGER: Phishing Link!" if is_phishing else "✅ SAFE: Legitimate Link", 
                               text_color="#ff4b4b" if is_phishing else "#45f542")
        except Exception as e:
            self.res.configure(text=f"Scan Error: {str(e)}", text_color="red")

    # --- NETWORK RADAR ---
    def show_net_frame(self):
        self.clear()
        ctk.CTkLabel(self.main_frame, text="Network Reconnaissance", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=30)
        self.net_txt = ctk.CTkTextbox(self.main_frame, width=700, height=400)
        self.net_txt.pack(pady=10)
        ctk.CTkButton(self.main_frame, text="Scan Subnet", command=lambda: threading.Thread(target=self._net_work).start()).pack()

    def _net_work(self):
        self.after(0, lambda: self.net_txt.delete("1.0", "end"))
        self.after(0, lambda: self.net_txt.insert("end", "[*] Initializing Network Radar... Please wait.\n"))
        try:
            devices = scan_network()
            self.after(0, lambda: self.net_txt.delete("1.0", "end"))
            if not devices:
                self.after(0, lambda: self.net_txt.insert("end", "[-] No devices found or scan blocked by permissions.\n"))
            for d in devices:
                self.after(0, lambda: self.net_txt.insert("end", f"IP: {d['ip']} | MAC: {d['mac']}\n"))
        except Exception as e:
            self.after(0, lambda: self.net_txt.insert("end", f"\n[-] CRITICAL ERROR: {str(e)}\n"))

    # --- PORT SCANNER ---
    def show_port_frame(self):
        self.clear()
        ctk.CTkLabel(self.main_frame, text="Vulnerability Scanner", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=30)
        self.p_in = ctk.CTkEntry(self.main_frame, placeholder_text="Target IP or Domain...", width=500)
        self.p_in.pack(pady=10)
        self.p_txt = ctk.CTkTextbox(self.main_frame, width=700, height=300)
        self.p_txt.pack(pady=10)
        ctk.CTkButton(self.main_frame, text="Run Scan", command=lambda: threading.Thread(target=self._port_work, args=(self.p_in.get(),)).start()).pack()

    def _port_work(self, target):
        self.after(0, lambda: self.p_txt.delete("1.0", "end"))
        self.after(0, lambda: self.p_txt.insert("end", f"[*] Resolving {target} and scanning ports...\n"))
        try:
            ip = socket.gethostbyname(target)
            res = scan_target(ip)
            self.after(0, lambda: self.p_txt.delete("1.0", "end"))
            if not res:
                self.after(0, lambda: self.p_txt.insert("end", "[+] No open ports found (System is secure or blocking pings).\n"))
            for r in res:
                self.after(0, lambda: self.p_txt.insert("end", f"⚠️ {r['port']} OPEN ({r['service']})\n"))
        except Exception as e:
            self.after(0, lambda: self.p_txt.delete("1.0", "end"))
            self.after(0, lambda: self.p_txt.insert("end", f"[-] FAILED: Could not scan target.\nReason: {str(e)}\n"))

    # --- INTEL / WHOIS ---
    def show_intel_frame(self):
        self.clear()
        ctk.CTkLabel(self.main_frame, text="Link Interceptor", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=30)
        self.i_in = ctk.CTkEntry(self.main_frame, placeholder_text="Paste shortened link...", width=500)
        self.i_in.pack(pady=10)
        self.i_res = ctk.CTkLabel(self.main_frame, text="", font=ctk.CTkFont(size=16))
        self.i_res.pack(pady=20)
        ctk.CTkButton(self.main_frame, text="Unroll", command=lambda: threading.Thread(target=self._intel_work).start()).pack()

    def _intel_work(self):
        self.after(0, lambda: self.i_res.configure(text="Intercepting traffic...", text_color="yellow"))
        try:
            _, dest = unroll_url(self.i_in.get())
            self.after(0, lambda: self.i_res.configure(text=f"Destination: {dest}", text_color="white"))
        except Exception as e:
            self.after(0, lambda: self.i_res.configure(text=f"Failed: {str(e)}", text_color="red"))

    def show_whois_frame(self):
        self.clear()
        ctk.CTkLabel(self.main_frame, text="Domain Intelligence", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=30)
        self.w_in = ctk.CTkEntry(self.main_frame, placeholder_text="Enter Domain (e.g. google.com)...", width=500)
        self.w_in.pack(pady=10)
        self.w_res = ctk.CTkLabel(self.main_frame, text="", font=ctk.CTkFont(size=16))
        self.w_res.pack(pady=20)
        # BUG FIX: WHOIS must be threaded too!
        ctk.CTkButton(self.main_frame, text="Fetch Data", command=lambda: threading.Thread(target=self._whois_work).start()).pack()

    def _whois_work(self):
        self.after(0, lambda: self.w_res.configure(text="Querying Global Databases...", text_color="yellow"))
        try:
            success, data = get_domain_intel(self.w_in.get())
            if success: 
                self.after(0, lambda: self.w_res.configure(text=f"Created: {data.get('creation_date', 'Unknown')}\nRegistrar: {data.get('registrar', 'Unknown')}", text_color="white"))
            else:
                self.after(0, lambda: self.w_res.configure(text=f"Failed: {data}", text_color="red"))
        except Exception as e:
            self.after(0, lambda: self.w_res.configure(text=f"Error: {str(e)}", text_color="red"))
if __name__ == "__main__":
    app = PhishGuardApp()
    app.mainloop()