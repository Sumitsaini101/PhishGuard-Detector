import customtkinter as ctk
from tkinter import messagebox
import threading
import socket
import time
import sys
import os
import joblib
import traceback


# --- 1. PATH RESOLUTION (Fixes the .exe AI bug) ---
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


from core.auth_manager import AuthManager
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


# Set application global visuals
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class PhishGuardApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("PhishGuard | Enterprise Security Dashboard")
        self.geometry("1100x700")
        self.after(0, lambda: self.state('zoomed'))
        
        self.accent = "#00f2ff"
        
        # Initialize Core Auth System
        self.auth = AuthManager()
        
        # State Tracking variables
        self.current_user = None
        self.current_email = None
        self.expected_otp = None
        self.temp_reg_data = None
        
        # Run the Identity Gatekeeper instantly on execution
        self.show_login_screen()

    def clear_screen(self):
        """Wipes the entire window clean."""
        for widget in self.winfo_children():
            widget.destroy()

    def clear_main_frame(self):
        """Wipes only the dashboard workspace, leaving the sidebar intact."""
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    # =========================================================================
    # PHASE 1: IDENTITY ACCESS MANAGEMENT (LOGIN & SIGNUP OVERLAYS)
    # =========================================================================
    
    def show_login_screen(self):
        self.clear_screen()
        
        # Remove grid layout if it was set by the dashboard previously
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=0)
        self.grid_rowconfigure(0, weight=0)
        
        frame = ctk.CTkFrame(self, width=420, height=480, corner_radius=12)
        frame.place(relx=0.5, rely=0.5, anchor="center")
        
        ctk.CTkLabel(frame, text="PhishGuard Enterprise", font=("Arial", 24, "bold")).pack(pady=(35, 5))
        ctk.CTkLabel(frame, text="Sign in to your security profile", text_color="gray", font=("Arial", 13)).pack(pady=(0, 25))
        
        self.username_entry = ctk.CTkEntry(frame, placeholder_text="Username", width=280, height=35)
        self.username_entry.pack(pady=10)
        
        self.password_entry = ctk.CTkEntry(frame, placeholder_text="Password", show="*", width=280, height=35)
        self.password_entry.pack(pady=10)
        
        login_btn = ctk.CTkButton(frame, text="Authenticate (Factor 1 & 3)", width=280, height=40, font=("Arial", 13, "bold"), command=self.process_login)
        login_btn.pack(pady=(25, 12))
        transfer_btn = ctk.CTkButton(frame, text="Lost/Changed Device? Recover Account", width=280, height=35, fg_color="transparent", text_color="#ff9900", hover_color="#2a2d3e", command=self.process_device_transfer)
        transfer_btn.pack(pady=(5, 10))
        
        register_btn = ctk.CTkButton(frame, text="Register Device", width=280, height=35, fg_color="transparent", border_width=1, font=("Arial", 12), command=self.show_register_screen)
        register_btn.pack(pady=5)

    def show_register_screen(self):
        self.clear_screen()
        
        frame = ctk.CTkFrame(self, width=420, height=520, corner_radius=12)
        frame.place(relx=0.5, rely=0.5, anchor="center")
        
        ctk.CTkLabel(frame, text="Device Provisioning", font=("Arial", 24, "bold")).pack(pady=(35, 5))
        ctk.CTkLabel(frame, text="Create account and bind hardware signature", text_color="gray", font=("Arial", 13)).pack(pady=(0, 25))
        
        self.reg_user = ctk.CTkEntry(frame, placeholder_text="Username", width=280, height=35)
        self.reg_user.pack(pady=10)
        
        self.reg_email = ctk.CTkEntry(frame, placeholder_text="Email Address", width=280, height=35)
        self.reg_email.pack(pady=10)
        
        self.reg_pass = ctk.CTkEntry(frame, placeholder_text="Security Password", show="*", width=280, height=35)
        self.reg_pass.pack(pady=10)
        
        warning_lbl = ctk.CTkLabel(frame, text="🔒 SECURITY WARNING:\nThis profile will be cryptographically locked\nto this machine's physical network hardware MAC.", text_color="#ff9900", font=("Arial", 11, "italic"))
        warning_lbl.pack(pady=12)

        reg_btn = ctk.CTkButton(frame, text="Initialize Email Verification", width=280, height=40, font=("Arial", 13, "bold"), command=self.process_registration)
        reg_btn.pack(pady=(15, 10))
        
        back_btn = ctk.CTkButton(frame, text="Abort & Return to Login", width=280, height=35, fg_color="transparent", command=self.show_login_screen)
        back_btn.pack(pady=5)

    def process_registration(self):
        u, e, p = self.reg_user.get().strip(), self.reg_email.get().strip(), self.reg_pass.get()
        if not u or not e or not p:
            messagebox.showerror("Validation Error", "All fields are mandatory for device configuration.")
            return
            
        self.temp_reg_data = {"user": u, "email": e, "pass": p}
        self.show_registration_otp_screen()

    def process_login(self):
        u, p = self.username_entry.get().strip(), self.password_entry.get()
        if not u or not p:
            messagebox.showerror("Validation Error", "Please provide identification credentials.")
            return
            
        success, message, email = self.auth.verify_factor_1_and_3(u, p)
        
        if success:
            self.current_user = u
            self.current_email = email
            self.show_login_otp_screen()
        else:
            messagebox.showerror("Access Denied", message)
    
    def process_device_transfer(self):
        u, p = self.username_entry.get().strip(), self.password_entry.get()
        if not u or not p:
            messagebox.showerror("Validation Error", "Please enter your Username and Password first to initiate a device transfer.")
            return
            
        # Verify only the password, ignore the MAC address for now
        success, message, email = self.auth.verify_credentials_only(u, p)
        
        if success:
            self.current_user = u
            self.current_email = email
            # Warn the user before sending the OTP
            msg = f"Security Warning: You are about to transfer your profile to this new computer.\n\nAn authorization code will be sent to:\n{email}"
            if messagebox.askyesno("Device Transfer Authorization", msg):
                self.show_transfer_otp_screen()
        else:
            messagebox.showerror("Access Denied", message)

    def show_transfer_otp_screen(self):
        self.clear_screen()
        
        frame = ctk.CTkFrame(self, width=420, height=380, corner_radius=12)
        frame.place(relx=0.5, rely=0.5, anchor="center")
        
        ctk.CTkLabel(frame, text="Authorize New Hardware", font=("Arial", 22, "bold"), text_color="#ff9900").pack(pady=(35, 10))
        ctk.CTkLabel(frame, text=f"Input the 6-digit access key sent to:\n{self.current_email}", font=("Arial", 12), text_color="gray").pack(pady=5)
        
        self.transfer_otp_entry = ctk.CTkEntry(frame, placeholder_text="######", width=180, height=40, justify="center", font=("Arial", 20, "bold"))
        self.transfer_otp_entry.pack(pady=25)
        
        self.verify_transfer_btn = ctk.CTkButton(frame, text="Verify & Bind New Device", width=280, height=40, font=("Arial", 13, "bold"), command=self.verify_transfer_otp)
        self.verify_transfer_btn.pack(pady=10)
        
        cancel_btn = ctk.CTkButton(frame, text="Cancel", width=280, height=35, fg_color="transparent", command=self.show_login_screen)
        cancel_btn.pack(pady=5)

        threading.Thread(target=self._send_transfer_otp_thread, daemon=True).start()

    def _send_transfer_otp_thread(self):
        self.verify_transfer_btn.configure(state="disabled", text="Dispatching Authorization Token...")
        success, result = self.auth.send_otp(self.current_email)
        
        if success:
            self.expected_otp = result
            self.verify_transfer_btn.configure(state="normal", text="Verify & Bind New Device")
        else:
            messagebox.showerror("Network Alert", f"SMTP Transmission Failure: {result}")
            self.show_login_screen()

    def verify_transfer_otp(self):
        if self.transfer_otp_entry.get().strip() == self.expected_otp:
            # Identity proven! Update the database to trust THIS computer's MAC address
            self.auth.update_device_mac(self.current_user)
            messagebox.showinfo("Hardware Bound", "Your new device has been authorized and bound to your profile.")
            self.show_main_dashboard()
        else:
            messagebox.showerror("Security Flag", "Access token validation failed.")

    # =========================================================================
    # PHASE 2: OUT-OF-BAND MULTI-FACTOR CHALLENGES (SMTP DISPATCH ENGINE)
    # =========================================================================
    
    def show_registration_otp_screen(self):
        self.clear_screen()
        
        frame = ctk.CTkFrame(self, width=420, height=380, corner_radius=12)
        frame.place(relx=0.5, rely=0.5, anchor="center")
        
        ctk.CTkLabel(frame, text="Verify Email Identity", font=("Arial", 22, "bold")).pack(pady=(35, 10))
        ctk.CTkLabel(frame, text=f"A verification transmission has been queued for:\n{self.temp_reg_data['email']}", font=("Arial", 12), text_color="gray").pack(pady=5)
        
        self.reg_otp_entry = ctk.CTkEntry(frame, placeholder_text="######", width=180, height=40, justify="center", font=("Arial", 20, "bold"))
        self.reg_otp_entry.pack(pady=25)
        
        self.verify_reg_btn = ctk.CTkButton(frame, text="Confirm & Bind Account", width=280, height=40, font=("Arial", 13, "bold"), command=self.verify_registration_otp)
        self.verify_reg_btn.pack(pady=10)
        
        cancel_btn = ctk.CTkButton(frame, text="Cancel", width=280, height=35, fg_color="transparent", command=self.show_register_screen)
        cancel_btn.pack(pady=5)

        threading.Thread(target=self._send_registration_otp_thread, daemon=True).start()

    def _send_registration_otp_thread(self):
        self.verify_reg_btn.configure(state="disabled", text="Dispatching Token...")
        success, result = self.auth.send_otp(self.temp_reg_data['email'])
        
        if success:
            self.expected_otp = result
            self.verify_reg_btn.configure(state="normal", text="Confirm & Bind Account")
        else:
            messagebox.showerror("Network Alert", f"SMTP Transmission Failure: {result}")
            self.show_register_screen()

    def verify_registration_otp(self):
        if self.reg_otp_entry.get().strip() == self.expected_otp:
            u = self.temp_reg_data["user"]
            p = self.temp_reg_data["pass"]
            e = self.temp_reg_data["email"]
            
            success, message = self.auth.register_user(u, p, e)
            if success:
                messagebox.showinfo("Identity Confirmed", "Email verified. System signature bound successfully.")
                self.temp_reg_data = None
                self.show_login_screen()
            else:
                messagebox.showerror("Database Exception", message)
                self.show_register_screen()
        else:
            messagebox.showerror("Security Flag", "Invalid validation parameters provided.")

    def show_login_otp_screen(self):
        self.clear_screen()
        
        frame = ctk.CTkFrame(self, width=420, height=380, corner_radius=12)
        frame.place(relx=0.5, rely=0.5, anchor="center")
        
        ctk.CTkLabel(frame, text="Factor-2 Challenge", font=("Arial", 22, "bold")).pack(pady=(35, 10))
        ctk.CTkLabel(frame, text=f"Input the 6-digit access key sent to:\n{self.current_email}", font=("Arial", 12), text_color="gray").pack(pady=5)
        
        self.login_otp_entry = ctk.CTkEntry(frame, placeholder_text="######", width=180, height=40, justify="center", font=("Arial", 20, "bold"))
        self.login_otp_entry.pack(pady=25)
        
        self.verify_login_btn = ctk.CTkButton(frame, text="Complete 3FA Authentication", width=280, height=40, font=("Arial", 13, "bold"), command=self.verify_login_otp)
        self.verify_login_btn.pack(pady=10)

        threading.Thread(target=self._send_login_otp_thread, daemon=True).start()

    def _send_login_otp_thread(self):
        self.verify_login_btn.configure(state="disabled", text="Generating OTP Challenge...")
        success, result = self.auth.send_otp(self.current_email)
        
        if success:
            self.expected_otp = result
            self.verify_login_btn.configure(state="normal", text="Complete 3FA Authentication")
        else:
            messagebox.showerror("Network Alert", f"SMTP Transmission Failure: {result}")
            self.show_login_screen()

    def verify_login_otp(self):
        if self.login_otp_entry.get().strip() == self.expected_otp:
            self.show_main_dashboard()
        else:
            messagebox.showerror("Security Flag", "Access token validation failed.")

    # =========================================================================
    # PHASE 3: MAIN CYBER-SOC DASHBOARD (SIDEBAR & TOOLS)
    # =========================================================================
    
    def show_main_dashboard(self):
        self.clear_screen()
        
        # Re-establish grid layout for the Sidebar Architecture
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- Sidebar ---
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color="#1a1c25")
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        ctk.CTkLabel(self.sidebar, text="PHISHGUARD", font=ctk.CTkFont(size=24, weight="bold"), text_color=self.accent).pack(pady=(30, 5))
        
        # Display authenticated user dynamically
        ctk.CTkLabel(self.sidebar, text=f"Logged in: {self.current_user}", font=("Arial", 12), text_color="#00ffcc").pack(pady=(0, 20))

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

        # --- Main Workspace Frame ---
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, padx=30, pady=30, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        
        # Load the default tool
        self.show_phish_frame()

    # --- TOOL 1: AI SCANNER ---
    def show_phish_frame(self):
        self.clear_main_frame()
        ctk.CTkLabel(self.main_frame, text="AI Threat Intelligence", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=30)
        self.url_in = ctk.CTkEntry(self.main_frame, placeholder_text="Enter URL...", width=500)
        self.url_in.pack(pady=10)
        self.res = ctk.CTkLabel(self.main_frame, text="", font=ctk.CTkFont(size=18))
        self.res.pack(pady=20)
        ctk.CTkButton(self.main_frame, text="Analyze Link", command=self.run_ai).pack()

    def run_ai(self):
        # NOTE: Ensure 'model' and 'extract_features' are imported at the top of this file
        try:
            if 'model' not in globals() or model is None:
                self.res.configure(text="🚨 ERROR: AI Model file not found!", text_color="red")
                return
                
            features = extract_features(self.url_in.get())
            pred = model.predict([features])
            is_phishing = (pred[0] == 'bad')
            self.res.configure(text="🚨 DANGER: Phishing Link!" if is_phishing else "✅ SAFE: Legitimate Link", 
                               text_color="#ff4b4b" if is_phishing else "#45f542")
        except Exception as e:
            self.res.configure(text=f"Scan Error: {str(e)}", text_color="red")

    # --- TOOL 2: NETWORK RADAR ---
    def show_net_frame(self):
        self.clear_main_frame()
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
                self.after(0, lambda dev=d: self.net_txt.insert("end", f"IP: {dev['ip']} | MAC: {dev['mac']}\n"))
        except Exception as e:
            self.after(0, lambda: self.net_txt.insert("end", f"\n[-] CRITICAL ERROR: {str(e)}\n"))

    # --- TOOL 3: PORT SCANNER ---
    def show_port_frame(self):
        self.clear_main_frame()
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
                self.after(0, lambda port_data=r: self.p_txt.insert("end", f"⚠️ {port_data['port']} OPEN ({port_data['service']})\n"))
        except Exception as e:
            self.after(0, lambda: self.p_txt.delete("1.0", "end"))
            self.after(0, lambda: self.p_txt.insert("end", f"[-] FAILED: Could not scan target.\nReason: {str(e)}\n"))

    # --- TOOL 4: LINK INTERCEPTOR ---
    def show_intel_frame(self):
        self.clear_main_frame()
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

    # --- TOOL 5: DOMAIN OSINT ---
    def show_whois_frame(self):
        self.clear_main_frame()
        ctk.CTkLabel(self.main_frame, text="Domain Intelligence", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=30)
        self.w_in = ctk.CTkEntry(self.main_frame, placeholder_text="Enter Domain (e.g. google.com)...", width=500)
        self.w_in.pack(pady=10)
        self.w_res = ctk.CTkLabel(self.main_frame, text="", font=ctk.CTkFont(size=16))
        self.w_res.pack(pady=20)
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