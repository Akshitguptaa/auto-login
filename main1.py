import os
import requests
from sqlalchemy import create_engine, Column, Integer, String
import bcrypt
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from cryptography.fernet import Fernet
import time
import threading
import xml.etree.ElementTree as ET
import tkinter as tk
from tkinter import ttk, messagebox
import subprocess

Base=declarative_base()

class Credential(Base):
    __tablename__ = 'credentials'
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, unique=True, nullable=False)
    hpass = Column(String, nullable=False)
    encryptPass = Column(String, nullable=False)

class DataManager:
    def __init__(self, db_path="sqlite:///credentials.db"):
        self.db_path = db_path
        self.key_path = "encryption.key"
        self.initialize_encryption()
        self.setup_database()

    def initialize_encryption(self):
        if not os.path.exists(self.key_path):
            key = Fernet.generate_key()
            with open(self.key_path, "wb") as key_file:
                key_file.write(key)
        else:
            with open(self.key_path, "rb") as key_file:
                self.key = key_file.read()
        self.fernet = Fernet(self.key)

    def setup_database(self):
        self.engine = create_engine(self.db_path, echo=False) 
        Base.metadata.create_all(self.engine)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()

    def add_credential(self, username, password):
        # handing checks
        check=self.session.query(Credential).filter_by(username=username).first()
        if check:
            return
        
        salt = bcrypt.gensalt()
        hpass = bcrypt.hashpw(password.encode('utf-8'), salt)

        # password encryption 
        # aie
        encryptPass = self.fernet.encrypt(password.encode('utf-8')).decode('utf-8')

        try:
            new_credential = Credential(username=username, hpass=hpass.decode('utf-8'), encryptPass=encryptPass)
            self.session.add(new_credential)
            self.session.commit()
        except Exception as e:
            messagebox.showerror("Error", f"Could not add credentials for '{username}'!")

    def get_credentials(self):
        data = self.session.query(Credential).all()
        cred = []
        
        for i in data:
            # password decryption 
            decrypt = self.fernet.decrypt(i.encryptPass.encode('utf-8')).decode('utf-8')
            cred.append({
                'username': i.username,
                'password': decrypt
            })
        return cred


class AutoLoginApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Auto Login ka lauda lassan")
        self.root.geometry("400x600")
        self.credential_manager = DataManager()
        self.auto_login_thread = None
        self.running = False
        self.credentials = []
        self.start_time = time.time()

        self.setup_ui()

    def setup_ui(self):
        self.style = ttk.Style()
        self.style.configure("TButton",
                             font=("Arial", 12, "bold"),
                             padding=10,
                             background="#4CAF50", 
                             foreground="white",
                             focuscolor="#45a049",
                             relief="flat")
        self.style.configure("TLabel",
                             font=("Arial", 12),
                             background="#f4f4f4",
                             foreground="black")
        self.style.configure("TLabelFrame",
                             font=("Arial", 14, "bold"),
                             background="#f4f4f4",
                             foreground="black")
        self.style.configure("TFrame",
                             background="#f4f4f4")

        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self.credentials_frame = ttk.LabelFrame(self.main_frame, text="Credentials", padding="10")
        self.credentials_frame.pack(fill=tk.X, pady=10)

        # data input

        ttk.Label(self.credentials_frame, text="Username:").pack(anchor="w")
        self.username_entry = ttk.Entry(self.credentials_frame, font=("Arial", 12))
        self.username_entry.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(self.credentials_frame, text="Password:").pack(anchor="w")
        self.password_entry = ttk.Entry(self.credentials_frame, show="*", font=("Arial", 12))
        self.password_entry.pack(fill=tk.X, pady=(0, 10))

        # add data
        self.add_button = ttk.Button(self.credentials_frame, text="Add Credential", command=self.add_credential)
        self.add_button.pack(fill=tk.X, pady=5)

        self.control_frame = ttk.LabelFrame(self.main_frame, text="Control", padding="10")
        self.control_frame.pack(fill=tk.X, pady=10)

        # auto login 
        self.toggle_button = ttk.Button(self.control_frame, text="Start Auto Login", command=self.toggle_auto_login)
        self.toggle_button.pack(fill=tk.X, pady=5)

        # logout
        self.logout_button = ttk.Button(self.control_frame, text="Logout", command=self.logout)
        self.logout_button.pack(fill=tk.X, pady=5)

        self.status_label = ttk.Label(self.control_frame, text="Status: Stopped")
        self.status_label.pack(pady=10)

        # time spent label
        self.timer_label = ttk.Label(self.root, text="Time Elapsed: 0s", anchor="w", font=("Arial", 12))
        self.timer_label.pack(fill=tk.X, side=tk.BOTTOM, padx=10, pady=10)

        # auto time updating 
        self.updateTimer()

    def add_credential(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if username and password:
            self.credential_manager.add_credential(username, password)
            print("added new data")
            messagebox.showinfo("Success", f"Credential for '{username}' added successfully!")
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
        else:
            messagebox.showerror("Error", "Please enter both username and password.")

    def toggle_auto_login(self):
        if self.running:
            self.running = False
            self.toggle_button.configure(text="Start Auto Login")
            self.status_label.configure(text="Status: Stopped")
        else:
            self.running = True
            self.toggle_button.configure(text="Stop Auto Login")
            self.status_label.configure(text="Status: Running")
            self.start_auto_login()

    def start_auto_login(self):
        self.credentials = self.credential_manager.get_credentials()
        if not self.credentials:
            messagebox.showerror("Error", "No credentials available for login.")
            return

        self.auto_login_thread = threading.Thread(target=self.auto_login_loop)
        self.auto_login_thread.start()

        self.ping_thread = threading.Thread(target=self.ping_check)
        self.ping_thread.start()

    def auto_login_loop(self):
        # chutiya wifi...

        maxx = 3  #retry limit for auto login
        c = 0
        while self.running and c<len(self.credentials):
            username=self.credentials[c]['username']
            password=self.credentials[c]['password']
            count = 0

            while count<maxx and self.running:
                success = self.login(username, password)

                if success:
                    self.status_label.configure(text=f"Logged in as {username}")
                    time.sleep(120)   #cing login again 
                    break
                else:
                    count += 1
                    self.status_label.configure(text=f"Login failed for {username}. Retry {count}/{maxx}.")
                    time.sleep(5)

            # for multiple credential available 
            # after max count
            if count >= maxx:
                self.status_label.configure(text=f"Failed to login with {username}. Moving to next.")
                c += 1

            if self.running and count < maxx:
                time.sleep(120)

        if not self.running:
            print("login stopped")
            self.status_label.configure(text="Status: Stopped")

    def login(self, username, password):
        """Simulate login request"""
        payload = {
            'mode': '191',
            'username': username,
            'password': password,
            'a': '1661062428616'
        }
        url = 'http://172.16.68.6:8090/httpclient.html'
        response = requests.post(url, data=payload)

        if response.status_code == 200:
            content = response.content
            root = ET.fromstring(content)
            message = root.find('message')
            if message is not None:
                if "You are signed in as" in message.text:
                    print("login successfull");
                    return True
                elif "Invalid username or password" in message.text:
                    messagebox.showerror("Login Failed", f"Invalid credentials for {username}.")
                    
                #adding few more error checks 
                #                 
                elif "Data limit reached" in message.text:
                    messagebox.showerror("Login Failed", f"Data limit reached for {username}.")
                elif "Maximum login cs exceeded" in message.text:
                    messagebox.showerror("Login Failed", f"Maximum login cs exceeded for {username}.")
        return False

    def logout(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if username and password:
            
            payload={'mode': '193',
                       'username': username, 
                       'password': password
            }

            url = 'http://172.16.68.6:8090/httpclient.html'
            response = requests.post(url, data=payload)

            if response.status_code == 200:
                content = response.content
                root = ET.fromstring(content)
                message = root.find('message')
                if message is not None:
                    message_text = message.text.strip()


                                                                            # betichod....
                    if "You are logged out" in message_text or "You&#39;ve signed out" in message_text or "You've signed out" in message_text:
                        messagebox.showinfo("Logout Successful", f"Successfully logged out as {username}.")
                        print("logout successfully")


        # more error checks added 
        # unable to fix the error for logout 
                    else:
                        messagebox.showerror("Logout Failed", f"Logout failed for {username}.")
            else:
                messagebox.showerror("Error", "Failed to communicate with the server.")
        else:
            messagebox.showerror("Error", "Please enter a valid username and password.")

    def ping_check(self):
        # pinging in the background
        while self.running:
            result = subprocess.run(['ping','-c','1','jiit.ac.in'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            if result.returncode != 0:
                # if ping fails, attempt to reconnect or re-login
                self.status_label.configure(text="Disconnected. Attempting to reconnect...")
                self.start_auto_login()  # restart login attempts if disconnected
            else:
                self.status_label.configure(text="Connection is stable.")


            # self.root.after(0, self.update_status_label, success)
            
            time.sleep(10)  # 10 second delay

    def updateTimer(self):
        samay=time.time()-self.start_time
        minutes,seconds = divmod(int(samay),60)
        time_str=f"Time spent-> {minutes:02}:{seconds:02}"
        self.timer_label.config(text=time_str)
        
        self.root.after(1000, self.updateTimer)

if __name__ == "__main__":
    app = AutoLoginApp()
    app.root.mainloop()
