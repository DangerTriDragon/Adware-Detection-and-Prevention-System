import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from ttkthemes import ThemedTk
import sqlite3
import bcrypt
import re
import subprocess
import os
import secrets
import string
from datetime import datetime, timedelta
from PIL import Image, ImageTk  

os.makedirs("data", exist_ok=True)
# Database Setup
conn = sqlite3.connect("data/users.db")
cursor = conn.cursor()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
""")
cursor.execute("""
    CREATE TABLE IF NOT EXISTS reset_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        token TEXT NOT NULL,
        expiry TIMESTAMP NOT NULL
    )
""")
conn.commit()

class LoginApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Login System")
        
        # Configure window size
        win_width = 1200
        win_height = 850
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x_pos = (screen_width - win_width) // 2
        y_pos = (screen_height - win_height) // 2
        self.root.geometry(f"{win_width}x{win_height}+{x_pos}+{y_pos}")
        
        # Set theme colors
        self.bg_color = "#f0f2f5"  # Light blue-gray background
        self.accent_color = "#1877f2"  # Facebook blue as accent
        self.text_color = "#050505"  # Near black for text
        self.root.configure(bg=self.bg_color)
        
        # Create a style for buttons and widgets
        self.style = ttk.Style()
        self.style.configure('Custom.TButton', 
                            font=('Arial', 12, 'bold'),
                            background=self.accent_color,
                            foreground='white')
        self.style.map('Custom.TButton',
                      background=[('active', '#166fe5')])
        
        self.create_login_ui()

    def create_login_ui(self):
        """Creates the enhanced login UI."""
        for widget in self.root.winfo_children():
            widget.destroy()
            
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        # Create main container that fills the screen
        main_container = tk.Frame(self.root, bg=self.bg_color)
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Left side - could contain a logo or image (60% of width)
        left_frame = tk.Frame(main_container, bg=self.accent_color)
        left_frame.place(relx=0, rely=0, relwidth=0.6, relheight=1)
        
        # Add app title/logo to left side
        logo_frame = tk.Frame(left_frame, bg=self.accent_color)
        logo_frame.place(relx=0.5, rely=0.4, anchor="center")
        
        app_title = tk.Label(logo_frame, text="Welcome", 
                            font=("Arial", 36, "bold"),
                            fg="white", bg=self.accent_color)
        app_title.pack()
        
        app_slogan = tk.Label(logo_frame, text="Ths is your secure gateway to our application",
                             font=("Arial", 18),
                             fg="white", bg=self.accent_color)
        app_slogan.pack(pady=20)
        
        # Right side - login form (40% of width)
        form_frame = tk.Frame(main_container, bg="white")
        form_frame.place(relx=0.6, rely=0, relwidth=0.4, relheight=1)
        
        # Login form container with padding
        self.frame = tk.Frame(form_frame, bg="white", padx=40, pady=40)
        self.frame.place(relx=0.5, rely=0.5, anchor="center")
        
        # Welcome message
        tk.Label(self.frame, text="Welcome Back", 
                font=("Arial", 24, "bold"), bg="white", 
                fg=self.text_color).pack(pady=(0, 30))
                
        # Email field with label
        email_frame = tk.Frame(self.frame, bg="white")
        email_frame.pack(fill="x", pady=10)
        
        tk.Label(email_frame, text="Email Address", 
                font=("Arial", 12), bg="white", 
                fg=self.text_color, anchor="w").pack(fill="x", pady=(0, 5))
                
        self.email_entry = ttk.Entry(email_frame, font=("Arial", 12), width=30)
        self.email_entry.pack(fill="x", ipady=8)
        
        # Password field with label
        pass_frame = tk.Frame(self.frame, bg="white")
        pass_frame.pack(fill="x", pady=10)
        
        tk.Label(pass_frame, text="Password", 
                font=("Arial", 12), bg="white", 
                fg=self.text_color, anchor="w").pack(fill="x", pady=(0, 5))
                
        self.password_entry = ttk.Entry(pass_frame, show="*", font=("Arial", 12), width=30)
        self.password_entry.pack(fill="x", ipady=8)
        
        # Show password checkbox
        show_frame = tk.Frame(self.frame, bg="white")
        show_frame.pack(fill="x", pady=5)
        
        self.show_var = tk.BooleanVar()
        self.show_checkbox = tk.Checkbutton(show_frame, text="Show Password", 
                                          bg="white", variable=self.show_var, 
                                          command=self.toggle_password,
                                          font=("Arial", 10))
        self.show_checkbox.pack(anchor="w")
        
        # Login button with custom style
        button_frame = tk.Frame(self.frame, bg="white")
        button_frame.pack(fill="x", pady=20)
        
        login_button = tk.Button(button_frame, text="Log In", 
                               bg=self.accent_color, fg="white",
                               font=("Arial", 14, "bold"),
                               padx=10, pady=10,
                               command=self.validate_login,
                               activebackground="#166fe5",
                               relief=tk.FLAT)
        login_button.pack(fill="x")
        
        # Forgot password link
        forgot_frame = tk.Frame(self.frame, bg="white")
        forgot_frame.pack(fill="x", pady=10)
        
        forgot_link = tk.Label(forgot_frame, text="Forgot Password?",
                             font=("Arial", 10, "underline"),
                             fg=self.accent_color, bg="white",
                             cursor="hand2")
        forgot_link.pack()
        forgot_link.bind("<Button-1>", lambda e: self.create_forgot_password_ui())
        
        # Divider line
        divider_frame = tk.Frame(self.frame, bg="#dadde1", height=1)
        divider_frame.pack(fill="x", pady=20)
        
        # Create account button (in different style)
        create_button = tk.Button(self.frame, text="Create New Account",
                                bg="#42b72a", fg="white",
                                font=("Arial", 12, "bold"),
                                padx=10, pady=8,
                                command=self.create_register_ui,
                                activebackground="#36a420",
                                relief=tk.FLAT)
        create_button.pack(pady=10)

    def create_register_ui(self):
        """Creates the enhanced registration UI."""
        for widget in self.root.winfo_children():
            widget.destroy()
            
        # Create main container
        main_container = tk.Frame(self.root, bg=self.bg_color)
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Left side - image/branding
        left_frame = tk.Frame(main_container, bg=self.accent_color)
        left_frame.place(relx=0, rely=0, relwidth=0.6, relheight=1)
        
        brand_frame = tk.Frame(left_frame, bg=self.accent_color)
        brand_frame.place(relx=0.5, rely=0.4, anchor="center")
        
        app_title = tk.Label(brand_frame, text="CREATE ACCOUNT", 
                           font=("Arial", 36, "bold"),
                           fg="white", bg=self.accent_color)
        app_title.pack()
        
        app_slogan = tk.Label(brand_frame, text="Join our secure platform",
                            font=("Arial", 18),
                            fg="white", bg=self.accent_color)
        app_slogan.pack(pady=20)
        
        # Right side - registration form
        form_frame = tk.Frame(main_container, bg="white")
        form_frame.place(relx=0.6, rely=0, relwidth=0.4, relheight=1)
        
        # Form container
        self.frame = tk.Frame(form_frame, bg="white", padx=40, pady=40)
        self.frame.place(relx=0.5, rely=0.5, anchor="center")
        
        # Title
        tk.Label(self.frame, text="Sign Up", 
               font=("Arial", 24, "bold"), bg="white", 
               fg=self.text_color).pack(pady=(0, 30))
        
        # Email field
        email_frame = tk.Frame(self.frame, bg="white")
        email_frame.pack(fill="x", pady=10)
        
        tk.Label(email_frame, text="Email Address", 
               font=("Arial", 12), bg="white", 
               fg=self.text_color, anchor="w").pack(fill="x", pady=(0, 5))
        
        self.reg_email_entry = ttk.Entry(email_frame, font=("Arial", 12), width=30)
        self.reg_email_entry.pack(fill="x", ipady=8)
        
        # Password field
        pass_frame = tk.Frame(self.frame, bg="white")
        pass_frame.pack(fill="x", pady=10)
        
        tk.Label(pass_frame, text="Password", 
               font=("Arial", 12), bg="white", 
               fg=self.text_color, anchor="w").pack(fill="x", pady=(0, 5))
        
        self.reg_password_entry = ttk.Entry(pass_frame, show="*", font=("Arial", 12), width=30)
        self.reg_password_entry.pack(fill="x", ipady=8)
        
        # Password requirements hint
        hint_text = "Password must contain at least 8 characters including uppercase, lowercase, digit and special character."
        hint_label = tk.Label(self.frame, text=hint_text, 
                            font=("Arial", 9), bg="white", fg="gray",
                            wraplength=400, justify="left")
        hint_label.pack(fill="x", pady=5, anchor="w")
        
        # Show password
        self.reg_show_var = tk.BooleanVar()
        self.reg_show_checkbox = tk.Checkbutton(self.frame, text="Show Password", 
                                              bg="white", variable=self.reg_show_var, 
                                              command=self.toggle_register_password,
                                              font=("Arial", 10))
        self.reg_show_checkbox.pack(anchor="w", pady=5)
        
        # Register button
        register_button = tk.Button(self.frame, text="Sign Up",
                                   bg="#42b72a", fg="white",
                                   font=("Arial", 14, "bold"),
                                   padx=10, pady=10,
                                   command=self.register_user,
                                   activebackground="#36a420",
                                   relief=tk.FLAT)
        register_button.pack(fill="x", pady=20)
        
        # Back to login link
        back_link = tk.Label(self.frame, text="Already have an account? Log In",
                           font=("Arial", 10, "underline"),
                           fg=self.accent_color, bg="white",
                           cursor="hand2")
        back_link.pack(pady=10)
        back_link.bind("<Button-1>", lambda e: self.create_login_ui())

    def create_forgot_password_ui(self):
        """Creates the enhanced forgot password UI."""
        for widget in self.root.winfo_children():
            widget.destroy()
            
        # Create main container
        main_container = tk.Frame(self.root, bg=self.bg_color)
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Left side - image/branding
        left_frame = tk.Frame(main_container, bg=self.accent_color)
        left_frame.place(relx=0, rely=0, relwidth=0.6, relheight=1)
        
        brand_frame = tk.Frame(left_frame, bg=self.accent_color)
        brand_frame.place(relx=0.5, rely=0.4, anchor="center")
        
        app_title = tk.Label(brand_frame, text="RESET PASSWORD", 
                           font=("Arial", 36, "bold"),
                           fg="white", bg=self.accent_color)
        app_title.pack()
        
        app_slogan = tk.Label(brand_frame, text="We'll help you recover your account",
                            font=("Arial", 18),
                            fg="white", bg=self.accent_color)
        app_slogan.pack(pady=20)
        
        # Right side - reset form
        form_frame = tk.Frame(main_container, bg="white")
        form_frame.place(relx=0.6, rely=0, relwidth=0.4, relheight=1)
        
        # Form container
        self.frame = tk.Frame(form_frame, bg="white", padx=40, pady=40)
        self.frame.place(relx=0.5, rely=0.5, anchor="center")
        
        # Title and instruction
        tk.Label(self.frame, text="Forgot Password?", 
               font=("Arial", 24, "bold"), bg="white", 
               fg=self.text_color).pack(pady=(0, 10))
               
        instruction = "Enter your email address and we'll send you a link to reset your password."
        tk.Label(self.frame, text=instruction, 
               font=("Arial", 12), bg="white", fg="gray",
               wraplength=400).pack(pady=(0, 30))
        
        # Email field
        email_frame = tk.Frame(self.frame, bg="white")
        email_frame.pack(fill="x", pady=10)
        
        tk.Label(email_frame, text="Email Address", 
               font=("Arial", 12), bg="white", 
               fg=self.text_color, anchor="w").pack(fill="x", pady=(0, 5))
        
        self.reset_email_entry = ttk.Entry(email_frame, font=("Arial", 12), width=30)
        self.reset_email_entry.pack(fill="x", ipady=8)
        
        # Submit button
        submit_button = tk.Button(self.frame, text="Send Reset Link",
                                 bg=self.accent_color, fg="white",
                                 font=("Arial", 14, "bold"),
                                 padx=10, pady=10,
                                 command=self.send_reset_token,
                                 activebackground="#166fe5",
                                 relief=tk.FLAT)
        submit_button.pack(fill="x", pady=20)
        
        # Back to login link
        back_link = tk.Label(self.frame, text="Return to Login",
                           font=("Arial", 10, "underline"),
                           fg=self.accent_color, bg="white",
                           cursor="hand2")
        back_link.pack(pady=10)
        back_link.bind("<Button-1>", lambda e: self.create_login_ui())
 
    def create_reset_password_ui(self, email, token):
        """Creates the enhanced reset password UI."""
        for widget in self.root.winfo_children():
            widget.destroy()
            
        # Store email and token
        self.reset_email = email
        self.reset_token = token
            
        # Create main container
        main_container = tk.Frame(self.root, bg=self.bg_color)
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Left side - image/branding
        left_frame = tk.Frame(main_container, bg=self.accent_color)
        left_frame.place(relx=0, rely=0, relwidth=0.6, relheight=1)
        
        brand_frame = tk.Frame(left_frame, bg=self.accent_color)
        brand_frame.place(relx=0.5, rely=0.4, anchor="center")
        
        app_title = tk.Label(brand_frame, text="NEW PASSWORD", 
                           font=("Arial", 36, "bold"),
                           fg="white", bg=self.accent_color)
        app_title.pack()
        
        app_slogan = tk.Label(brand_frame, text="Create a strong new password",
                            font=("Arial", 18),
                            fg="white", bg=self.accent_color)
        app_slogan.pack(pady=20)
        
        # Right side - reset password form
        form_frame = tk.Frame(main_container, bg="white")
        form_frame.place(relx=0.6, rely=0, relwidth=0.4, relheight=1)
        
        # Form container
        self.frame = tk.Frame(form_frame, bg="white", padx=40, pady=40)
        self.frame.place(relx=0.5, rely=0.5, anchor="center")
        
        # Title
        tk.Label(self.frame, text="Set New Password", 
               font=("Arial", 24, "bold"), bg="white", 
               fg=self.text_color).pack(pady=(0, 30))
        
        # New password field
        pass_frame = tk.Frame(self.frame, bg="white")
        pass_frame.pack(fill="x", pady=10)
        
        tk.Label(pass_frame, text="New Password", 
               font=("Arial", 12), bg="white", 
               fg=self.text_color, anchor="w").pack(fill="x", pady=(0, 5))
        
        self.new_password_entry = ttk.Entry(pass_frame, show="*", font=("Arial", 12), width=30)
        self.new_password_entry.pack(fill="x", ipady=8)
        
        # Confirm password field
        confirm_frame = tk.Frame(self.frame, bg="white")
        confirm_frame.pack(fill="x", pady=10)
        
        tk.Label(confirm_frame, text="Confirm New Password", 
               font=("Arial", 12), bg="white", 
               fg=self.text_color, anchor="w").pack(fill="x", pady=(0, 5))
        
        self.confirm_password_entry = ttk.Entry(confirm_frame, show="*", font=("Arial", 12), width=30)
        self.confirm_password_entry.pack(fill="x", ipady=8)
        
        # Password hint
        hint_text = "Password must contain at least 8 characters including uppercase, lowercase, digit and special character."
        hint_label = tk.Label(self.frame, text=hint_text, 
                            font=("Arial", 9), bg="white", fg="gray",
                            wraplength=400, justify="left")
        hint_label.pack(fill="x", pady=5, anchor="w")
        
        # Show passwords
        self.new_show_var = tk.BooleanVar()
        self.new_show_checkbox = tk.Checkbutton(self.frame, text="Show Passwords", 
                                              bg="white", variable=self.new_show_var, 
                                              command=self.toggle_new_passwords,
                                              font=("Arial", 10))
        self.new_show_checkbox.pack(anchor="w", pady=5)
        
        # Reset button
        reset_button = tk.Button(self.frame, text="Reset Password",
                               bg=self.accent_color, fg="white",
                               font=("Arial", 14, "bold"),
                               padx=10, pady=10,
                               command=self.reset_password,
                               activebackground="#166fe5",
                               relief=tk.FLAT)
        reset_button.pack(fill="x", pady=20)
        
        # Back to login link
        back_link = tk.Label(self.frame, text="Return to Login",
                           font=("Arial", 10, "underline"),
                           fg=self.accent_color, bg="white",
                           cursor="hand2")
        back_link.pack(pady=10)
        back_link.bind("<Button-1>", lambda e: self.create_login_ui())

    # The rest of the methods remain the same as in your original code
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

    def toggle_new_passwords(self):
        """Show/Hide passwords in the reset password form."""
        if self.new_show_var.get():
            self.new_password_entry.config(show="")
            self.confirm_password_entry.config(show="")
        else:
            self.new_password_entry.config(show="*")
            self.confirm_password_entry.config(show="*")

    def hash_password(self, password):
        """Hash a password using bcrypt."""
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    def verify_password(self, password, hashed_password):
        try:
            return bcrypt.checkpw(password.encode(), hashed_password.encode())
        except ValueError:
            return False

    @staticmethod
    def validate_email(email):
        regex = r"^(?!.*\.\.)[a-zA-Z0-9][a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,6}$"
        return bool(re.match(regex, email))

    COMMON_PASSWORDS = ["password", "123456", "qwerty", "abc123", "letmein", "welcome"]

    @staticmethod
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

    def generate_token(self, length=32):
        """Generate a secure random token for password reset."""
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def send_reset_token(self):
        """Generate and store a reset token, then simulate sending it via email."""
        email = self.reset_email_entry.get().strip()
        
        if not email:
            messagebox.showerror("Error", "Email is required!")
            return
            
        if not self.validate_email(email):
            messagebox.showerror("Error", "Invalid email format!")
            return
            
        # Check if email exists in database
        conn = sqlite3.connect("data/users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email=?", (email,))
        user = cursor.fetchone()
        
        if not user:
            # Don't reveal that email doesn't exist for security
            messagebox.showinfo("Success", "If your email is registered, you will receive reset instructions shortly.")
            conn.close()
            self.create_login_ui()
            return
            
        # Generate token and expiry date (24 hours from now)
        token = self.generate_token()
        expiry = datetime.now() + timedelta(hours=24)
        
        # Delete any existing tokens for this email
        cursor.execute("DELETE FROM reset_tokens WHERE email=?", (email,))
        
        # Store new token
        cursor.execute(
            "INSERT INTO reset_tokens (email, token, expiry) VALUES (?, ?, ?)",
            (email, token, expiry)
        )
        conn.commit()
        conn.close()
        
        # In a real application, you would send an email here
        # For demonstration, we'll show the token and go to reset form
        messagebox.showinfo("Demo Mode", f"Token: {token}\n\nIn a real app, this would be emailed to {email}")
        self.create_reset_password_ui(email, token)

    def verify_reset_token(self, email, token):
        """Verify if a reset token is valid and not expired."""
        conn = sqlite3.connect("data/users.db")
        cursor = conn.cursor()
        cursor.execute(
            "SELECT expiry FROM reset_tokens WHERE email=? AND token=? AND expiry > ?",
            (email, token, datetime.now())
        )
        result = cursor.fetchone()
        conn.close()
        return result is not None

    def reset_password(self):
        """Reset the user's password if token is valid."""
        new_password = self.new_password_entry.get().strip()
        confirm_password = self.confirm_password_entry.get().strip()
        
        # Validate passwords
        if not new_password or not confirm_password:
            messagebox.showerror("Error", "Both fields are required!")
            return
            
        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            return
            
        is_valid, msg = self.validate_password(new_password)
        if not is_valid:
            messagebox.showerror("Error", msg)
            return
            
        # Verify token
        if not self.verify_reset_token(self.reset_email, self.reset_token):
            messagebox.showerror("Error", "Invalid or expired reset link. Please request a new one.")
            self.create_forgot_password_ui()
            return
            
        # Update password
        hashed_password = self.hash_password(new_password)
        conn = sqlite3.connect("data/users.db")
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password=? WHERE email=?", (hashed_password, self.reset_email))
        
        # Delete used token
        cursor.execute("DELETE FROM reset_tokens WHERE email=?", (self.reset_email,))
        conn.commit()
        conn.close()
        
        messagebox.showinfo("Success", "Password has been reset successfully!")
        self.create_login_ui()

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
        
        is_valid, msg = self.validate_password(password)
        if not is_valid:  # Check the boolean value
            messagebox.showerror("Error", msg)  # Show actual validation message
            return

        try:
            hashed_password = self.hash_password(password)
            conn = sqlite3.connect("data/users.db")
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

        conn = sqlite3.connect("data/users.db")
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