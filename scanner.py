# scanner.py
import tkinter as tk
from tkinter import ttk, filedialog
import customtkinter as ctk
import threading
import yara
import os
from logger import Logger

class ScannerTab(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.logger = Logger()
        self.scanning = False
        self.detected_files = []
        self.setup_yara_rules()
        self.setup_ui()
        
    def setup_yara_rules(self):
        """Load and compile YARA rules from the rules directory"""
        rules_dir = "yara_rules"
        if not os.path.exists(rules_dir):
            os.makedirs(rules_dir)
    
        # Compile all rules
        rules_files = {}
        for rule_file in os.listdir(rules_dir):
            if rule_file.endswith('.yar'):
                rule_path = os.path.join(rules_dir, rule_file)
                rules_files[rule_file] = rule_path
                self.logger.log(f"Loaded YARA rules from: {rule_file}")
    
        if not rules_files:
            self.logger.log("Warning: No YARA rules found in rules directory")
            return
        
        try:
            self.rules = yara.compile(filepaths=rules_files)
            self.logger.log(f"Successfully compiled {len(rules_files)} YARA rule files")
        except Exception as e:
            self.logger.log(f"Error compiling YARA rules: {str(e)}")
            raise
    
    def setup_ui(self):
        # Create main container
        self.main_container = ctk.CTkFrame(self)
        self.main_container.pack(expand=True, fill="both", padx=20, pady=20)
        
        # Scan buttons frame
        self.buttons_frame = ctk.CTkFrame(self.main_container)
        self.buttons_frame.pack(pady=(0, 10), fill="x")
        
        # Scan File button
        self.scan_file_btn = ctk.CTkButton(
            self.buttons_frame,
            text="Scan Files & Folders",
            command=self.toggle_file_folder_scan
        )
        self.scan_file_btn.pack(side="left", padx=10)
        
        # Scan System button
        self.scan_system_btn = ctk.CTkButton(
            self.buttons_frame,
            text="Scan System",
            command=self.toggle_system_scan
        )
        self.scan_system_btn.pack(side="left", padx=10)
        
        # Progress frame
        self.progress_frame = ctk.CTkFrame(self.main_container)
        self.progress_frame.pack(pady=10, fill="x")
        
        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(self.progress_frame)
        self.progress_bar.pack(pady=5, fill="x")
        self.progress_bar.set(0)
        
        # Progress label
        self.progress_label = ctk.CTkLabel(self.progress_frame, text="Ready to scan")
        self.progress_label.pack(pady=5)
        
        # Create a frame to hold both results and detected files
        self.content_frame = ctk.CTkFrame(self.main_container)
        self.content_frame.pack(expand=True, fill="both", pady=(10, 0))
        
        # Configure grid weights for content frame
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_rowconfigure(0, weight=3)  # Results gets more space
        self.content_frame.grid_rowconfigure(1, weight=2)  # Detected files gets less space
        
        # Results text area with scroll
        self.results_text = ctk.CTkTextbox(self.content_frame, height=200)
        self.results_text.grid(row=0, column=0, sticky="nsew", padx=10, pady=(0, 10))
        
        # Detected files section
        self.detected_frame = ctk.CTkScrollableFrame(
            self.content_frame,
            label_text="Detected Files",
            height=150
        )
        self.detected_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        
        # Options frame at the bottom
        self.options_frame = ctk.CTkFrame(self.main_container)
        self.options_frame.pack(fill="x", pady=(10, 0))
        
        # Auto-quarantine checkbox
        self.auto_quarantine_var = ctk.BooleanVar(value=False)
        self.auto_quarantine_check = ctk.CTkCheckBox(
            self.options_frame,
            text="Auto-quarantine detected files",
            variable=self.auto_quarantine_var
        )
        self.auto_quarantine_check.pack(side="left", padx=10)
        
        # Quarantine selected button
        self.quarantine_selected_btn = ctk.CTkButton(
            self.options_frame,
            text="Quarantine Selected",
            command=self.quarantine_selected,
            state="disabled"
        )
        self.quarantine_selected_btn.pack(side="right", padx=10)
        
        # Dictionary to store checkboxes for detected files
        self.detection_checkboxes = {}

    def update_progress(self, progress, message=""):
        self.progress_bar.set(progress)
        if message:
            self.progress_label.configure(text=message)
        
    def scan_file_for_adware(self, file_path):
        try:
            matches = self.rules.match(file_path)
            if matches:
                result_parts = [f"⚠️ ADWARE DETECTED in {file_path}"]
                result_parts.append("\nDetected Rules:")
                
                for match in matches:
                    severity = match.meta.get('severity', 'unknown')
                    description = match.meta.get('description', 'No description available')
                    
                    severity_emoji = {
                        'low': '🟡',
                        'medium': '🟠',
                        'high': '🔴',
                        'critical': '⛔'
                    }.get(severity.lower(), '⚠️')
                    
                    result_parts.append(f"\n{severity_emoji} Rule: {match.rule}")
                    result_parts.append(f"   Severity: {severity.upper()}")
                    result_parts.append(f"   Description: {description}")
                
                result = "\n".join(result_parts)
                self.logger.log(f"Adware detected in {file_path}")
                
                # Add to detected files if not auto-quarantining
                if not self.auto_quarantine_var.get():
                    self.add_detected_file(file_path)
                else:
                    # Auto-quarantine for real-time protection
                    from quarantine import QuarantineTab
                    QuarantineTab.add_quarantined_item(file_path)
                
                return True, result
            else:
                result = f"✅ No adware detected in {file_path}"
                return False, result
        except Exception as e:
            result = f"Error scanning {file_path}: {str(e)}"
            self.logger.log(result)
            return False, result
    
    def toggle_file_folder_scan(self):
        if not self.scanning:
            # Allow selection of both files and folders
            paths = filedialog.askdirectory(title="Select folder to scan")
            if paths:  # If a folder was selected
                self.scanning = True
                self.scan_file_btn.configure(text="Stop Scanning")
                self.start_file_folder_scan([paths])
            else:  # Try file selection if folder selection was cancelled
                files = filedialog.askopenfilenames(title="Select files to scan")
                if files:
                    self.scanning = True
                    self.scan_file_btn.configure(text="Stop Scanning")
                    self.start_file_folder_scan(files)
        else:
            self.scanning = False
            self.scan_file_btn.configure(text="Scan Files & Folders")
    
    def toggle_system_scan(self):
        if not self.scanning:
            self.scanning = True
            self.scan_system_btn.configure(text="Stop Scanning")
            self.start_system_scan()
        else:
            self.scanning = False
            self.scan_system_btn.configure(text="Scan System")
    
    def start_file_folder_scan(self, paths):
        def scan():
            try:
                total_items = 0
                scanned_items = 0
                
                # First, count total items to scan
                for path in paths:
                    if os.path.isfile(path):
                        total_items += 1
                    else:
                        for _, _, files in os.walk(path):
                            total_items += len(files)
                
                self.results_text.insert("end", "Starting scan...\n")
                self.results_text.see("end")
                
                # Scan each path
                for path in paths:
                    if not self.scanning:
                        break
                        
                    if os.path.isfile(path):
                        # Single file scan
                        self.update_progress(
                            scanned_items / total_items,
                            f"Scanning file: {os.path.basename(path)}"
                        )
                        is_adware, result = self.scan_file_for_adware(path)
                        if is_adware:
                            self.results_text.insert("end", f"{result}\n")
                            self.results_text.see("end")
                        scanned_items += 1
                    else:
                        # Folder scan
                        self.results_text.insert("end", f"\nScanning folder: {path}...\n")
                        self.results_text.see("end")
                        
                        for root, _, files in os.walk(path):
                            if not self.scanning:
                                break
                                
                            for file in files:
                                file_path = os.path.join(root, file)
                                try:
                                    # Update progress
                                    self.update_progress(
                                        scanned_items / total_items,
                                        f"Scanning: {scanned_items}/{total_items} items"
                                    )
                                    
                                    # Scan file
                                    is_adware, result = self.scan_file_for_adware(file_path)
                                    if is_adware:
                                        self.results_text.insert("end", f"{result}\n")
                                        self.results_text.see("end")
                                    
                                    scanned_items += 1
                                        
                                except Exception as e:
                                    self.logger.log(f"Error scanning {file_path}: {str(e)}")
                
                self.results_text.insert("end", "\nScan completed.\n")
                self.update_progress(1, "Scan complete")
                
            except Exception as e:
                self.results_text.insert("end", f"Error during scan: {str(e)}\n")
                self.update_progress(1, "Scan failed")
                
            finally:
                self.scanning = False
                self.scan_file_btn.configure(text="Scan Files & Folders")
                # Reset progress after a delay
                self.after(2000, lambda: self.update_progress(0, "Ready to scan"))
            
        thread = threading.Thread(target=scan)
        thread.start()
    
    def start_system_scan(self):
        def scan():
            try:
                common_paths = [
                    os.path.expanduser("~/Downloads"),
                    os.path.expanduser("~/Desktop"),
                    os.path.expanduser("~/AppData/Local/Temp"),
                ]
                
                self.results_text.insert("end", "Starting system scan...\n")
                total_files = 0
                scanned_files = 0
                
                # First, count total files
                for path in common_paths:
                    if os.path.exists(path):
                        for _, _, files in os.walk(path):
                            total_files += len(files)
                
                # Now scan files
                for path in common_paths:
                    if not self.scanning:
                        break
                        
                    if os.path.exists(path):
                        self.results_text.insert("end", f"\nScanning {path}...\n")
                        self.results_text.see("end")
                        
                        for root, _, files in os.walk(path):
                            for file in files:
                                if not self.scanning:
                                    break
                                    
                                file_path = os.path.join(root, file)
                                try:
                                    # Update progress
                                    scanned_files += 1
                                    progress = scanned_files / total_files
                                    self.update_progress(
                                        progress,
                                        f"Scanning: {scanned_files}/{total_files} files"
                                    )
                                    
                                    # Scan file
                                    is_adware, result = self.scan_file_for_adware(file_path)
                                    if is_adware:
                                        self.results_text.insert("end", f"{result}\n")
                                        self.results_text.see("end")
                                        
                                except Exception as e:
                                    self.logger.log(f"Error scanning {file_path}: {str(e)}")
                
                self.results_text.insert("end", "\nSystem scan completed.\n")
                self.update_progress(1, "Scan complete")
                
            except Exception as e:
                self.results_text.insert("end", f"Error during system scan: {str(e)}\n")
                self.update_progress(1, "Scan failed")
                
            finally:
                self.scanning = False
                self.scan_system_btn.configure(text="Scan System")
                # Reset progress after a delay
                self.after(2000, lambda: self.update_progress(0, "Ready to scan"))
            
        thread = threading.Thread(target=scan)
        thread.start()
        
    def add_detected_file(self, file_path):
        """Add a detected file to the list with checkbox"""
        if file_path not in self.detected_files:
            self.detected_files.append(file_path)
            
            # Create checkbox for the file
            var = ctk.BooleanVar()
            checkbox = ctk.CTkCheckBox(
                self.detected_frame,
                text=file_path,
                variable=var
            )
            checkbox.pack(anchor="w", pady=2, padx=5, fill="x")
            self.detection_checkboxes[file_path] = var
            
            # Enable the quarantine button
            self.quarantine_selected_btn.configure(state="normal")
    
    def quarantine_selected(self):
        """Quarantine selected detected files"""
        files_to_quarantine = [
            file_path for file_path, var in self.detection_checkboxes.items()
            if var.get()
        ]
        
        if not files_to_quarantine:
            return
            
        from quarantine import QuarantineTab
        for file_path in files_to_quarantine:
            if QuarantineTab.add_quarantined_item(file_path):
                # Remove from detected list and UI
                self.detected_files.remove(file_path)
                for widget in self.detected_frame.winfo_children():
                    if isinstance(widget, ctk.CTkCheckBox) and widget.cget("text") == file_path:
                        widget.destroy()
                del self.detection_checkboxes[file_path]
        
        # Update quarantine button state
        if not self.detected_files:
            self.quarantine_selected_btn.configure(state="disabled")

        # Update results text
        self.results_text.insert("end", f"\nQuarantined {len(files_to_quarantine)} files.\n")
        self.results_text.see("end")