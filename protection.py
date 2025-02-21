# protection.py
import customtkinter as ctk
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
import yara
from logger import Logger
import threading
import time

class AdwareEventHandler(FileSystemEventHandler):
    def __init__(self, protection_tab):
        self.protection_tab = protection_tab
        self.rules = protection_tab.rules
        self.processing_files = set()  # Track files being processed
        
    def on_created(self, event):
        if event.is_directory:
            return
        self.scan_file(event.src_path)
        
    def on_modified(self, event):
        if event.is_directory:
            return
        self.scan_file(event.src_path)
        
    def scan_file(self, file_path):
        # Normalize file path
        file_path = os.path.normpath(file_path)
        
        # Check if file is already being processed
        if file_path in self.processing_files:
            return
            
        self.processing_files.add(file_path)
        
        try:
            # Wait briefly for file to be fully written
            time.sleep(0.5)
            
            # Check if file still exists and is readable
            if not os.path.exists(file_path) or not os.access(file_path, os.R_OK):
                return
                
            # Try to scan the file
            matches = self.rules.match(file_path)
            if matches:
                message = f"⚠️ Adware Detected!\nFile: {file_path}\nRules Matched: {[match.rule for match in matches]}"
                self.protection_tab.update_activity(message)
                self.protection_tab.logger.log(f"Real-time protection: Adware detected in {file_path}")
                
                # Add to quarantine
                from quarantine import QuarantineTab
                if QuarantineTab.add_quarantined_item(file_path):
                    self.protection_tab.update_activity(f"✅ File has been quarantined: {file_path}")
                else:
                    self.protection_tab.update_activity(f"❌ Failed to quarantine file: {file_path}")
                    
        except Exception as e:
            # Only log errors, don't show them in the activity feed
            self.protection_tab.logger.log(f"Error scanning {file_path}: {str(e)}")
        finally:
            self.processing_files.remove(file_path)

class ProtectionTab(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.logger = Logger()
        self.protection_enabled = False
        self.observer = None
        self.setup_yara_rules()
        self.setup_ui()
        
    def setup_yara_rules(self):
        # Load YARA rules from rules directory
        rules_dir = "yara_rules"
        if not os.path.exists(rules_dir):
            os.makedirs(rules_dir)
            
        # Compile all rules
        rules_files = {}
        for rule_file in os.listdir(rules_dir):
            if rule_file.endswith('.yar'):
                rules_files[rule_file] = os.path.join(rules_dir, rule_file)
        self.rules = yara.compile(filepaths=rules_files)
        
    def setup_ui(self):
        # Protection status frame
        self.status_frame = ctk.CTkFrame(self)
        self.status_frame.pack(pady=20, padx=20, fill="x")
        
        # Protection toggle button
        self.protection_btn = ctk.CTkSwitch(
            self.status_frame,
            text="Real-time Protection",
            command=self.toggle_protection
        )
        self.protection_btn.pack(pady=10)
        
        # Status label
        self.status_label = ctk.CTkLabel(
            self.status_frame,
            text="Protection Status: Disabled",
            font=("Arial", 14)
        )
        self.status_label.pack(pady=10)
        
        # Activity label
        self.activity_label = ctk.CTkLabel(
            self,
            text="Adware Detection Alerts:",
            font=("Arial", 12, "bold")
        )
        self.activity_label.pack(pady=(20,5), padx=20, anchor="w")
        
        # Activity log
        self.activity_text = ctk.CTkTextbox(self, height=300)
        self.activity_text.pack(pady=(0,20), padx=20, fill="both", expand=True)
        
    def toggle_protection(self):
        self.protection_enabled = not self.protection_enabled
        status = "Enabled" if self.protection_enabled else "Disabled"
        self.status_label.configure(text=f"Protection Status: {status}")
        
        if self.protection_enabled:
            self.start_monitoring()
        else:
            self.stop_monitoring()
            
        self.activity_text.insert("end", f"Real-time protection {status.lower()}\n")
        self.logger.log(f"Real-time protection {status.lower()}")
        
    def start_monitoring(self):
        if not self.observer:
            # Monitor common adware locations
            paths_to_monitor = [
                os.path.expanduser("~/Downloads"),
                os.path.expanduser("~/Desktop"),
                os.path.expanduser("~/AppData/Local/Temp"),
                # Add more paths as needed
            ]
            
            self.observer = Observer()
            event_handler = AdwareEventHandler(self)
            
            for path in paths_to_monitor:
                if os.path.exists(path):
                    self.observer.schedule(event_handler, path, recursive=False)
                    self.activity_text.insert("end", f"Monitoring: {path}\n")
            
            self.observer.start()
            
    def stop_monitoring(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
            
    def update_activity(self, message):
        def update():
            # Add timestamp to the message
            timestamp = time.strftime("%H:%M:%S")
            formatted_message = f"[{timestamp}] {message}\n"
            
            self.activity_text.insert("end", formatted_message)
            self.activity_text.see("end")
        
        # Ensure UI updates happen in main thread
        if threading.current_thread() is threading.main_thread():
            update()
        else:
            self.after(0, update)