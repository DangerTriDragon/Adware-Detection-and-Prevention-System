# main.py
import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
from scanner import ScannerTab
from protection import ProtectionTab
from quarantine import QuarantineTab
from logs import LogsTab

class AdwareDetectionSystem:
    def __init__(self, root):
        self.root = root
        self.root.title("Adware Detection System")
        
        # Configure window
        win_width = 1200
        win_height = 850
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x_pos = (screen_width - win_width) // 2
        y_pos = (screen_height - win_height) // 2
        self.root.geometry(f"{win_width}x{win_height}+{x_pos}+{y_pos}")
        
        # Set theme and styling
        ctk.set_appearance_mode("system")  # Will follow system theme
        ctk.set_default_color_theme("blue")
        
        # Create main frame
        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Create header
        self.header = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.header.pack(fill="x", padx=20, pady=(0, 20))
        
        self.title_label = ctk.CTkLabel(
            self.header,
            text="Adware Detection System",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        self.title_label.pack(side="left")
        
        # Create theme toggle
        self.theme_button = ctk.CTkButton(
            self.header,
            text="Toggle Theme",
            width=120,
            command=self.toggle_theme
        )
        self.theme_button.pack(side="right")
        
        # Create custom tabview
        self.tabview = ctk.CTkTabview(self.main_frame)
        self.tabview.pack(fill="both", expand=True, padx=10)
        
        # Add tabs
        self.tabview.add("Scanner")
        self.tabview.add("Protection")
        self.tabview.add("Quarantine")
        self.tabview.add("Logs")
        
        # Initialize tabs without the 'master' keyword argument
        scanner_tab_frame = self.tabview.tab("Scanner")
        protection_tab_frame = self.tabview.tab("Protection")
        quarantine_tab_frame = self.tabview.tab("Quarantine")
        logs_tab_frame = self.tabview.tab("Logs")
        
        self.scanner_tab = ScannerTab(scanner_tab_frame)
        self.scanner_tab.pack(fill="both", expand=True)
        
        self.protection_tab = ProtectionTab(protection_tab_frame)
        self.protection_tab.pack(fill="both", expand=True)
        
        self.quarantine_tab = QuarantineTab(quarantine_tab_frame)
        self.quarantine_tab.pack(fill="both", expand=True)
        
        self.logs_tab = LogsTab(logs_tab_frame)
        self.logs_tab.pack(fill="both", expand=True)
        
        # Set default tab
        self.tabview.set("Scanner")
        
        # Create status bar
        self.status_bar = ctk.CTkFrame(self.main_frame, height=30)
        self.status_bar.pack(fill="x", pady=(20, 0))
        
        self.status_label = ctk.CTkLabel(
            self.status_bar,
            text="System Status: Protected",
            font=ctk.CTkFont(size=12)
        )
        self.status_label.pack(side="left", padx=10)
        
        self.version_label = ctk.CTkLabel(
            self.status_bar,
            text="Version 1.0.0",
            font=ctk.CTkFont(size=12)
        )
        self.version_label.pack(side="right", padx=10)
    
    def toggle_theme(self):
        current_theme = ctk.get_appearance_mode()
        new_theme = "Light" if current_theme == "Dark" else "Dark"
        ctk.set_appearance_mode(new_theme)

if __name__ == "__main__":
    root = tk.Tk()
    app = AdwareDetectionSystem(root)
    root.mainloop()