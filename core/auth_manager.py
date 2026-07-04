import sqlite3
import hashlib
import uuid
import smtplib
import random
from email.message import EmailMessage

class AuthManager:
    def __init__(self):
        self.db_name = "phishguard_users.db"
        self._initialize_db()

    def _initialize_db(self):
        """Creates the database and users table if they don't exist."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT NOT NULL,
                mac_address TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()

    def get_mac_address(self):
        """Grabs the physical hardware MAC address of the current computer."""
        return ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0,2*6,2)][::-1])

    def hash_password(self, password):
        """Encrypts the password using SHA-256."""
        return hashlib.sha256(password.encode()).hexdigest()

    def register_user(self, username, password, email):
        """Registers a new user and binds their account to this specific computer."""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            
            mac = self.get_mac_address()
            hashed_pw = self.hash_password(password)
            
            cursor.execute("INSERT INTO users (username, password_hash, email, mac_address) VALUES (?, ?, ?, ?)", 
                           (username, hashed_pw, email, mac))
            conn.commit()
            conn.close()
            return True, "Registration successful!"
        except sqlite3.IntegrityError:
            return False, "Username already exists."

    def verify_factor_1_and_3(self, username, password):
        """Checks Password (Factor 1) and Device MAC Address (Factor 3)."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        hashed_pw = self.hash_password(password)
        current_mac = self.get_mac_address()
        
        cursor.execute("SELECT password_hash, mac_address, email FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return False, "User not found.", None
            
        db_pw, db_mac, email = result
        
        if db_pw != hashed_pw:
            return False, "Incorrect password.", None
            
        if db_mac != current_mac:
            return False, "SECURITY ALERT: Unrecognized device. Access Denied.", None
            
        return True, "Factors 1 & 3 passed.", email

    def send_otp(self, receiver_email):
        """Sends a 6-digit OTP (Factor 2) via Email."""
        otp = str(random.randint(100000, 999999))
        
        # NOTE: You will need to put your actual Gmail address and an 'App Password' here
        sender_email = "your_project_email@gmail.com" 
        app_password = "your_16_digit_app_password"
        
        msg = EmailMessage()
        msg['Subject'] = "PhishGuard - Your Login OTP"
        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg.set_content(f"Your PhishGuard authentication code is: {otp}\n\nDo not share this with anyone.")

        try:
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
                smtp.login(sender_email, app_password)
                smtp.send_message(msg)
            return True, otp
        except Exception as e:
            return False, str(e)
    
    def verify_credentials_only(self, username, password):
        """Checks Factor 1 (Password) only, used for Account Recovery/Device Transfer."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        hashed_pw = self.hash_password(password)
        cursor.execute("SELECT password_hash, email FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return False, "User not found.", None
            
        db_pw, email = result
        
        if db_pw != hashed_pw:
            return False, "Incorrect password.", None
            
        return True, "Credentials valid.", email

    def update_device_mac(self, username):
        """Overwrites the old MAC address with the current computer's MAC address."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        new_mac = self.get_mac_address()
        
        cursor.execute("UPDATE users SET mac_address = ? WHERE username = ?", (new_mac, username))
        conn.commit()
        conn.close()
        