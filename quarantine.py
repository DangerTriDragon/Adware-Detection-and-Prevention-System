# quarantine.py
import customtkinter as ctk
from logger import Logger
import os
import shutil

class QuarantineTab(ctk.CTkFrame):
    _instance = None
    
    def __init__(self, parent):
        super().__init__(parent)
        QuarantineTab._instance = self
        self.logger = Logger()
        self.quarantined_items = []
        self.checkboxes = {}  # Dictionary to store checkboxes
        self.setup_quarantine_folder()
        self.setup_ui()
        
    def setup_quarantine_folder(self):
        self.quarantine_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine")
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)
    
    def setup_ui(self):
        # Main container
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.pack(pady=20, padx=20, fill="both", expand=True)
        
        self.header_frame = ctk.CTkFrame(self.main_frame)
        self.header_frame.pack(pady=10, fill="x")
        
        # Title
        self.title_label = ctk.CTkLabel(
            self.main_frame,
            text="Quarantined Items",
            font=("Arial", 16, "bold")
        )
        self.title_label.pack(side="left", pady=10, padx=10)
        
        # Refresh button
        self.refresh_btn = ctk.CTkButton(
            self.header_frame,
            text="↻ Refresh",
            width=100,
            command=self.refresh_quarantine
        )
        self.refresh_btn.pack(side="right", pady=10, padx=10)
        
        # Scrollable frame for quarantined items
        self.scrollable_frame = ctk.CTkScrollableFrame(self.main_frame, height=300)
        self.scrollable_frame.pack(pady=10, padx=10, fill="both", expand=True)
        
        # Action buttons frame
        self.action_frame = ctk.CTkFrame(self)
        self.action_frame.pack(pady=10, padx=20, fill="x")
        
        # Select all checkbox
        self.select_all_var = ctk.BooleanVar()
        self.select_all_checkbox = ctk.CTkCheckBox(
            self.action_frame,
            text="Select All",
            variable=self.select_all_var,
            command=self.toggle_all
        )
        self.select_all_checkbox.pack(side="left", padx=5)
        
        # Delete button
        self.delete_btn = ctk.CTkButton(
            self.action_frame,
            text="Delete Selected",
            command=self.delete_selected
        )
        self.delete_btn.pack(side="right", padx=5)
        
        # Restore button
        self.restore_btn = ctk.CTkButton(
            self.action_frame,
            text="Restore Selected",
            command=self.restore_selected
        )
        self.restore_btn.pack(side="right", padx=5)
    
    @classmethod
    def add_quarantined_item(cls, file_path):
        if cls._instance is None:
            return False
            
        try:
            file_path = os.path.normpath(file_path)
            quarantine_name = f"quarantined_{os.path.basename(file_path)}"
            quarantine_path = os.path.join(cls._instance.quarantine_dir, quarantine_name)
            
            shutil.move(file_path, quarantine_path)
            
            cls._instance.quarantined_items.append({
                'original_path': file_path,
                'quarantine_path': quarantine_path
            })
            
            cls._instance.update_quarantine_list()
            cls._instance.logger.log(f"File quarantined: {file_path}")
            return True
            
        except Exception as e:
            if cls._instance:
                cls._instance.logger.log(f"Error quarantining file {file_path}: {str(e)}")
            return False
    
    def update_quarantine_list(self):
        """Update the quarantine list display with checkboxes"""
        # Clear existing items
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        self.checkboxes.clear()
        
        # Add items with checkboxes
        for i, item in enumerate(self.quarantined_items):
            # Create frame for each item
            item_frame = ctk.CTkFrame(self.scrollable_frame)
            item_frame.pack(pady=5, padx=5, fill="x")
            
            # Create checkbox
            var = ctk.BooleanVar()
            checkbox = ctk.CTkCheckBox(
                item_frame,
                text="",
                variable=var
            )
            checkbox.pack(side="left", padx=5)
            self.checkboxes[item['quarantine_path']] = var
            
            # Create labels for file info
            info_frame = ctk.CTkFrame(item_frame)
            info_frame.pack(side="left", fill="x", expand=True, padx=5)
            
            ctk.CTkLabel(info_frame, text=f"Original: {item['original_path']}").pack(anchor="w")
            ctk.CTkLabel(info_frame, text=f"Quarantined: {item['quarantine_path']}").pack(anchor="w")

    def refresh_quarantine(self):
        """Refresh the quarantine list by checking the quarantine directory"""
        try:
            # Clear current items
            self.quarantined_items.clear()
        
            # Scan quarantine directory for files
            for filename in os.listdir(self.quarantine_dir):
                if filename.startswith("quarantined_"):
                    quarantine_path = os.path.join(self.quarantine_dir, filename)
                    original_name = filename.replace("quarantined_", "", 1)
                
                    # Try to reconstruct original path from our naming convention
                    # This is a basic implementation - you might want to store original paths in a separate file
                    original_path = os.path.join(os.path.expanduser("~"), original_name)
                
                    self.quarantined_items.append({
                    'original_path': original_path,
                    'quarantine_path': quarantine_path
                    })
        
            # Update the display
            self.update_quarantine_list()
            self.logger.log("Quarantine list refreshed")
        
        except Exception as e:
            self.logger.log(f"Error refreshing quarantine list: {str(e)}")

    
    def toggle_all(self):
        """Toggle all checkboxes based on select all checkbox"""
        state = self.select_all_var.get()
        for var in self.checkboxes.values():
            var.set(state)
    
    def get_selected_items(self):
        """Get list of selected items"""
        return [path for path, var in self.checkboxes.items() if var.get()]
    
    def delete_selected(self):
        """Delete selected quarantined items permanently"""
        try:
            selected_paths = self.get_selected_items()
            if not selected_paths:
                return
                
            items_to_remove = []
            for item in self.quarantined_items:
                if item['quarantine_path'] in selected_paths:
                    try:
                        if os.path.exists(item['quarantine_path']):
                            os.remove(item['quarantine_path'])
                        items_to_remove.append(item)
                        self.logger.log(f"Deleted quarantined file: {item['quarantine_path']}")
                    except Exception as e:
                        self.logger.log(f"Error deleting file {item['quarantine_path']}: {str(e)}")
            
            # Remove deleted items from the list
            for item in items_to_remove:
                self.quarantined_items.remove(item)
                
            # Update the display
            self.update_quarantine_list()
            
        except Exception as e:
            self.logger.log(f"Error in delete_selected: {str(e)}")
    
    def restore_selected(self):
        """Restore selected items to their original locations"""
        try:
            selected_paths = self.get_selected_items()
            if not selected_paths:
                return
                
            items_to_remove = []
            for item in self.quarantined_items:
                if item['quarantine_path'] in selected_paths:
                    try:
                        original_path = item['original_path']
                        original_dir = os.path.dirname(original_path)
                        
                        if not os.path.exists(original_dir):
                            os.makedirs(original_dir)
                        
                        if os.path.exists(item['quarantine_path']):
                            shutil.move(item['quarantine_path'], original_path)
                            items_to_remove.append(item)
                            self.logger.log(f"Restored file from {item['quarantine_path']} to {original_path}")
                        else:
                            self.logger.log(f"Quarantined file not found: {item['quarantine_path']}")
                            
                    except Exception as e:
                        self.logger.log(f"Error restoring file {item['quarantine_path']}: {str(e)}")
            
            # Remove restored items from the list
            for item in items_to_remove:
                self.quarantined_items.remove(item)
                
            # Update the display
            self.update_quarantine_list()
            
        except Exception as e:
            self.logger.log(f"Error in restore_selected: {str(e)}")