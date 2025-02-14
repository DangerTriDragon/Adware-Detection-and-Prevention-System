import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from ttkthemes import ThemedTk
import sqlite3
import bcrypt
import re  # For email & password validation
import subprocess

# Database Setup
conn = sqlite3.connect("users.db")
cursor = conn.cursor()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
""")
conn.commit()

class LoginApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Login Form")
        self.root.geometry("400x350")
        self.root.resizable(False, False)
        self.create_login_ui()

    def create_login_ui(self):
        """Creates the login UI."""
        for widget in self.root.winfo_children():
            widget.destroy()

        self.frame = tk.Frame(self.root, bg="white", padx=20, pady=20, relief=tk.RIDGE, bd=2)
        self.frame.pack(expand=True)

        tk.Label(self.frame, text="Login", font=("Arial", 16, "bold"), bg="white").grid(row=0, column=0, columnspan=2, pady=10)

        tk.Label(self.frame, text="Email:", font=("Arial", 12), bg="white").grid(row=1, column=0, sticky="w", pady=5)
        self.email_entry = ttk.Entry(self.frame)
        self.email_entry.grid(row=1, column=1, pady=5)

        tk.Label(self.frame, text="Password:", font=("Arial", 12), bg="white").grid(row=2, column=0, sticky="w", pady=5)
        self.password_entry = ttk.Entry(self.frame, show="*")
        self.password_entry.grid(row=2, column=1, pady=5)

        self.show_var = tk.BooleanVar()
        self.show_checkbox = tk.Checkbutton(self.frame, text="Show Password", bg="white", variable=self.show_var, command=self.toggle_password)
        self.show_checkbox.grid(row=3, column=0, columnspan=2, pady=5)

        self.login_button = ttk.Button(self.frame, text="Login", command=self.validate_login)
        self.login_button.grid(row=4, column=0, columnspan=2, pady=10)

        self.register_button = ttk.Button(self.frame, text="Create Account", command=self.create_register_ui)
        self.register_button.grid(row=5, column=0, columnspan=2, pady=5)

    def create_register_ui(self):
        """Creates the registration UI."""
        for widget in self.root.winfo_children():
            widget.destroy()

        self.frame = tk.Frame(self.root, bg="white", padx=20, pady=20, relief=tk.RIDGE, bd=2)
        self.frame.pack(expand=True)

        tk.Label(self.frame, text="Register", font=("Arial", 16, "bold"), bg="white").grid(row=0, column=0, columnspan=2, pady=10)

        tk.Label(self.frame, text="Email:", font=("Arial", 12), bg="white").grid(row=1, column=0, sticky="w", pady=5)
        self.reg_email_entry = ttk.Entry(self.frame)
        self.reg_email_entry.grid(row=1, column=1, pady=5)

        tk.Label(self.frame, text="Password:", font=("Arial", 12), bg="white").grid(row=2, column=0, sticky="w", pady=5)
        self.reg_password_entry = ttk.Entry(self.frame, show="*")
        self.reg_password_entry.grid(row=2, column=1, pady=5)

        self.reg_show_var = tk.BooleanVar()
        self.reg_show_checkbox = tk.Checkbutton(self.frame, text="Show Password", bg="white", variable=self.reg_show_var, command=self.toggle_register_password)
        self.reg_show_checkbox.grid(row=3, column=0, columnspan=2, pady=5)

        self.register_button = ttk.Button(self.frame, text="Register", command=self.register_user)
        self.register_button.grid(row=4, column=0, columnspan=2, pady=10)

        self.back_button = ttk.Button(self.frame, text="Back to Login", command=self.create_login_ui)
        self.back_button.grid(row=5, column=0, columnspan=2, pady=5)

    def toggle_password(self):
        """Show/Hide password in the login form."""
        if self.show_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def toggle_register_password(self):
        """Show/Hide password in the register form."""
        if self.reg_show_var.get():
            self.reg_password_entry.config(show="")
        else:
            self.reg_password_entry.config(show="*")

    def hash_password(self, password):
        """Hash a password using bcrypt."""
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    def verify_password(self, password, hashed_password):
        """Verify a password against its hash."""
        return bcrypt.checkpw(password.encode(), hashed_password.encode())

    def validate_email(email):
        regex = r"^(?!.*\.\.)[a-zA-Z0-9][a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,6}$"
        return bool(re.match(regex, email))

    COMMON_PASSWORDS = ["password", "123456", "qwerty", "abc123", "letmein", "welcome"]

    def validate_password(password):
        # Check length
        if len(password) < 8:
            return False, "Password must be at least 8 characters long."
    
        # Check complexity (Uppercase, Lowercase, Digit, Special Character)
        if not re.search(r"[A-Z]", password):
            return False, "Password must have at least one uppercase letter."
        if not re.search(r"[a-z]", password):
            return False, "Password must have at least one lowercase letter."
        if not re.search(r"\d", password):
            return False, "Password must have at least one digit."
        if not re.search(r"[@$!%*?&]", password):
            return False, "Password must have at least one special character (@$!%*?&)."
    
        # Check for spaces
        if " " in password:
            return False, "Password must not contain spaces."
    
        # Check for repeating characters (aaaa, 1111)
        if re.search(r"(.)\1{3,}", password):
            return False, "Password must not contain more than 3 repeating characters."
    
        # Check for common passwords
        if password.lower() in LoginApp.COMMON_PASSWORDS:
            return False, "Password is too common. Choose a stronger one."
    
        # Check for simple sequences (abcd, 1234)
        if re.search(r"(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def)", password, re.IGNORECASE):
            return False, "Password must not contain common sequences."

        return True, "Password is strong!"

    def register_user(self):
        """Register a new user into the database."""
        email = self.reg_email_entry.get().strip()
        password = self.reg_password_entry.get().strip()

        if not email or not password:
            messagebox.showerror("Error", "Both fields are required!")
            return
        if not self.validate_email(email):
            messagebox.showerror("Error", "Invalid email format!")
            return
        if not self.validate_password(password):
            messagebox.showerror("Error", "Password must be at least 8 characters, include an uppercase, lowercase, digit, and special character!")
            return

        try:
            hashed_password = self.hash_password(password)
            conn = sqlite3.connect("users.db")
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed_password))
            conn.commit()
            conn.close()
            messagebox.showinfo("Success", "Account created successfully!")
            self.create_login_ui()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Email already registered!")

    def validate_login(self):
        """Validate user credentials and login."""
        email = self.email_entry.get().strip()
        password = self.password_entry.get().strip()

        if not email or not password:
            messagebox.showerror("Error", "Both fields are required!")
            return

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE email=?", (email,))
        result = cursor.fetchone()
        conn.close()

        if result and self.verify_password(password, result[0]):
            messagebox.showinfo("Success", "Login Successful!")

            # Close login window
            self.root.destroy()

            # Run main.py
            subprocess.Popen(["python", "main.py"])

        else:
            messagebox.showerror("Error", "Invalid Email or Password")

# Run Application
if __name__ == "__main__":
    root = ThemedTk(theme="breeze")
    app = LoginApp(root)
    root.mainloop()
