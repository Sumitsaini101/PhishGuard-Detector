import customtkinter as ctk
import sys
import os
import threading
import joblib
import socket

# Path configuration to import from 'core'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.feature_extractor import extract_features
from core.network_scanner import scan_network
from core.port_scanner import scan_target
from core.url_unshortener import unroll_url
from core.whois_lookup import get_domain_intel

# Load AI Model
try:
    model = joblib.load("core/phishing_model.pkl")
except:
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

        # Theme Colors
        self.accent = "#00f2ff"
        
        # Grid Layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color="#1a1c25")
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        ctk.CTkLabel(self.sidebar, text="PHISHGUARD", font=ctk.CTkFont(size=24, weight="bold"), text_color=self.accent).pack(pady=30)

        buttons = [
            ("Fake Link Scanner", self.show_phish_frame),
            ("Network Radar", self.show_net_frame),
            ("Port Scanner", self.show_port_frame),
            ("Link Interceptor", self.show_intel_frame),
            ("Domain OSINT", self.show_whois_frame)
        ]
        
        for text, cmd in buttons:
            ctk.CTkButton(self.sidebar, text=text, command=cmd, fg_color="transparent", 
                          border_width=1, border_color=self.accent, hover_color="#2a2d3e").pack(pady=10, padx=20, fill="x")

        # Main Content
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
        ctk.CTkLabel(self.main_frame, text="AI Link Scanner", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=30)
        self.url_in = ctk.CTkEntry(self.main_frame, placeholder_text="Enter URL...", width=500)
        self.url_in.pack(pady=10)
        self.res = ctk.CTkLabel(self.main_frame, text="", font=ctk.CTkFont(size=18))
        self.res.pack(pady=20)
        ctk.CTkButton(self.main_frame, text="Analyze Link", command=self.run_ai).pack()

    def run_ai(self):
        features = extract_features(self.url_in.get())
        pred = model.predict([features])
        
        is_phishing = (pred[0] == 'bad')
        
        self.res.configure(
            text="🚨 DANGER: Phishing Link!" if is_phishing else "✅ SAFE: Legitimate Link", 
            text_color="#ff4b4b" if is_phishing else "#45f542"
        )
    # --- NETWORK RADAR ---
    def show_net_frame(self):
        self.clear()
        ctk.CTkLabel(self.main_frame, text="Network Reconnaissance", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=30)
        self.net_txt = ctk.CTkTextbox(self.main_frame, width=700, height=400)
        self.net_txt.pack(pady=10)
        ctk.CTkButton(self.main_frame, text="Scan Subnet", command=lambda: threading.Thread(target=self._net_work).start()).pack()

    def _net_work(self):
        devices = scan_network()
        self.after(0, lambda: self.net_txt.delete("1.0", "end"))
        for d in devices:
            self.after(0, lambda: self.net_txt.insert("end", f"IP: {d['ip']} | MAC: {d['mac']}\n"))

    # --- PORT SCANNER ---
    def show_port_frame(self):
        self.clear()
        ctk.CTkLabel(self.main_frame, text="Vulnerability Scanner", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=30)
        self.p_in = ctk.CTkEntry(self.main_frame, placeholder_text="Target IP...", width=500)
        self.p_in.pack(pady=10)
        self.p_txt = ctk.CTkTextbox(self.main_frame, width=700, height=300)
        self.p_txt.pack(pady=10)
        ctk.CTkButton(self.main_frame, text="Run Scan", command=lambda: threading.Thread(target=self._port_work, args=(self.p_in.get(),)).start()).pack()

    def _port_work(self, target):
        ip = socket.gethostbyname(target)
        res = scan_target(ip)
        self.after(0, lambda: self.p_txt.delete("1.0", "end"))
        for r in res:
            self.after(0, lambda: self.p_txt.insert("end", f"⚠️ {r['port']} OPEN ({r['service']})\n"))

    # --- INTEL / WHOIS ---
    def show_intel_frame(self):
        self.clear()
        ctk.CTkLabel(self.main_frame, text="Link Interceptor", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=30)
        self.i_in = ctk.CTkEntry(self.main_frame, placeholder_text="Paste link...", width=500)
        self.i_in.pack(pady=10)
        self.i_res = ctk.CTkLabel(self.main_frame, text="", font=ctk.CTkFont(size=16))
        self.i_res.pack(pady=20)
        ctk.CTkButton(self.main_frame, text="Unroll", command=lambda: threading.Thread(target=self._intel_work).start()).pack()

    def _intel_work(self):
        _, dest = unroll_url(self.i_in.get())
        self.after(0, lambda: self.i_res.configure(text=f"Destination: {dest}"))

    def show_whois_frame(self):
        self.clear()
        ctk.CTkLabel(self.main_frame, text="Domain Intelligence", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=30)
        self.w_in = ctk.CTkEntry(self.main_frame, placeholder_text="Domain...", width=500)
        self.w_in.pack(pady=10)
        self.w_res = ctk.CTkLabel(self.main_frame, text="", font=ctk.CTkFont(size=16))
        self.w_res.pack(pady=20)
        ctk.CTkButton(self.main_frame, text="Fetch Data", command=self.run_whois).pack()

    def run_whois(self):
        success, data = get_domain_intel(self.w_in.get())
        if success: self.w_res.configure(text=f"Created: {data['creation_date']}\nRegistrar: {data['registrar']}")

if __name__ == "__main__":
    app = PhishGuardApp()
    app.mainloop()