import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.ttk import Combobox
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import re

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Encryption Tool")
        
        self.file_path = tk.StringVar()
        self.algorithm = tk.StringVar(value="AES")
        self.password = tk.StringVar()
        
        self.create_widgets()
    
    def create_widgets(self):
        tk.Label(self.root, text="Select File:").grid(row=0, column=0, padx=10, pady=10)
        tk.Entry(self.root, textvariable=self.file_path, width=50).grid(row=0, column=1, padx=10, pady=10)
        tk.Button(self.root, text="Browse", command=self.browse_file).grid(row=0, column=2, padx=10, pady=10)
        
        tk.Label(self.root, text="Select Algorithm:").grid(row=1, column=0, padx=10, pady=10)
        self.algorithm_combobox = Combobox(self.root, textvariable=self.algorithm, values=["AES", "DES"], state="readonly")
        self.algorithm_combobox.grid(row=1, column=1, padx=10, pady=10)
        
        tk.Label(self.root, text="Enter Password:").grid(row=2, column=0, padx=10, pady=10)
        tk.Entry(self.root, textvariable=self.password, show="*", width=50).grid(row=2, column=1, padx=10, pady=10)
        
        tk.Button(self.root, text="Encrypt", command=self.encrypt_file).grid(row=3, column=0, padx=10, pady=10)
        tk.Button(self.root, text="Decrypt", command=self.decrypt_file).grid(row=3, column=1, padx=10, pady=10)
    
    def browse_file(self):
        self.file_path.set(filedialog.askopenfilename())
    
    def validate_password(self, password):
        if len(password) < 8:
            return False, "Password must be at least 8 characters long."
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter."
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter."
        if not re.search(r"[0-9]", password):
            return False, "Password must contain at least one digit."
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False, "Password must contain at least one special character."
        return True, ""
    
    def encrypt_file(self):
        file_path = self.file_path.get()
        algorithm = self.algorithm.get()
        password = self.password.get()
        
        if not file_path or not password:
            messagebox.showerror("Error", "Please select a file and enter a password.")
            return
        
        is_valid, msg = self.validate_password(password)
        if not is_valid:
            messagebox.showerror("Error", msg)
            return
        
        password = password.encode()
        
        try:
            with open(file_path, "rb") as file:
                data = file.read()
            
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password)
            
            if algorithm == "AES":
                iv = os.urandom(16)
                cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            elif algorithm == "DES":
                key = key[:8]  # DES key must be 8 bytes long
                iv = os.urandom(8)
                cipher = Cipher(algorithms.DES(key), modes.CFB(iv), backend=default_backend())
            
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(data) + encryptor.finalize()
            
            encrypted_file_path = file_path + ".enc"
            with open(encrypted_file_path, "wb") as encrypted_file:
                encrypted_file.write(salt + iv + encrypted_data)
            
            messagebox.showinfo("Success", f"File encrypted successfully: {encrypted_file_path}")
        
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_file(self):
        file_path = self.file_path.get()
        algorithm = self.algorithm.get()
        password = self.password.get()
        
        if not file_path or not password:
            messagebox.showerror("Error", "Please select a file and enter a password.")
            return
        
        is_valid, msg = self.validate_password(password)
        if not is_valid:
            messagebox.showerror("Error", msg)
            return
        
        password = password.encode()
        
        try:
            with open(file_path, "rb") as encrypted_file:
                salt = encrypted_file.read(16)
                if algorithm == "AES":
                    iv = encrypted_file.read(16)
                elif algorithm == "DES":
                    iv = encrypted_file.read(8)
                encrypted_data = encrypted_file.read()
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password)
            
            if algorithm == "AES":
                cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            elif algorithm == "DES":
                key = key[:8]
                cipher = Cipher(algorithms.DES(key), modes.CFB(iv), backend=default_backend())
            
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            decrypted_file_path = file_path.replace(".enc", ".dec")
            with open(decrypted_file_path, "wb") as decrypted_file:
                decrypted_file.write(decrypted_data)
            
            messagebox.showinfo("Success", f"File decrypted successfully: {decrypted_file_path}")
        
        except Exception as e:
            messagebox.showerror("Error", str(e))

def main():
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
