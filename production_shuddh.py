"""
Shuddh - The destroyer

PRODUCTION VERSION - ALL SAFETY FEATURES REMOVED
This version performs ACTUAL data destruction operations.

!!! WARNING: to all the devs who will read this code !!!
This file is the production build of the Shuddh application.
It is designed to permanently erase data from drives.
DO NOT run this script or the resulting executable on your main system as it will destroy data permanently.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import os
import sys
from pathlib import Path
from datetime import datetime
from production_system_core import SystemCore
from production_wipe_engine import WipeEngine
from production_verification_engine import VerificationEngine
from emergency_handler import emergency_handler


class ShuddApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Shuddh - Data Purification Tool")
        self.root.geometry("800x600")
        self.root.configure(bg='#2c3e50')
        
        #  engines
        self.system_core = SystemCore(development_mode=False)#agar development_mode True hoga to ye sirf testing karega bina kuch delete kiye
        self.wipe_engine = WipeEngine(development_mode=False)
        self.verification_engine = VerificationEngine(development_mode=False)
        
        self.boot_drive = None
        self.wipe_decision = None
        self.wipe_in_progress = False
        
        self.current_screen = "warning"
        
        # Setup emergency handling
        self.setup_emergency_handling()
        
        # Check admin privileges immediately
        if not self.system_core.check_admin():
            messagebox.showerror("Admin Required", "This application requires administrator privileges.")#admin rights ctypes use karke check karenge
            self.system_core.elevate_privileges()
        
        # Setup emergency handling
        self.setup_emergency_handling()
        
        self.setup_ui()
    
    def setup_emergency_handling(self):
        """Setup emergency quit functionality"""
        # Register cleanup functions
        emergency_handler.register_cleanup(self.emergency_cleanup)
        
        # Bind Escape key for emergency quit
        self.root.bind('<Escape>', lambda e: self.emergency_quit())
        
        # Override window close to check for active operations
        self.root.protocol("WM_DELETE_WINDOW", self.on_window_close)
    
    def emergency_cleanup(self):
        """Emergency cleanup function"""
        try:
            if self.wipe_in_progress:
                # Signal wipe engine to stop
                if hasattr(self.wipe_engine, 'abort_flag'):
                    self.wipe_engine.abort_flag.set()
                    
                # Force cleanup of any open file handles
                if hasattr(self.wipe_engine, '_cleanup_resources'):
                    self.wipe_engine._cleanup_resources()
        except Exception as e:
            # Log error but don't raise - emergency cleanup should not fail
            print(f"Emergency cleanup error: {e}")
    
    def emergency_quit(self):
        """Trigger emergency quit"""
        if self.wipe_in_progress:
            result = messagebox.askyesno(
                "Emergency Quit", 
                "Wipe operation is in progress!\n\nForce quit may leave drive in inconsistent state.\n\nAre you sure?"
            )
            if not result:
                return
        
        emergency_handler.trigger_emergency_quit("User requested emergency quit")
    
    def on_window_close(self):
        """Handle window close event"""
        if self.wipe_in_progress:
            result = messagebox.askyesno(
                "Operation in Progress", 
                "Data wipe is currently running.\n\nClosing now may leave your drive in an inconsistent state.\n\nAre you sure you want to quit?"
            )
            if not result:
                return
        
        self.root.quit()
        
    def setup_ui(self):
        #Setup the main UI
        for widget in self.root.winfo_children():
            widget.destroy()
            
        if self.current_screen == "warning":
            self.show_warning_screen()
        elif self.current_screen == "progress":
            self.show_progress_screen()
        elif self.current_screen == "success":
            self.show_success_screen()
    
    def show_warning_screen(self):
        """Screen 1: Warning & Consent Screen   consent is important 😂"""
        try:
            drives = self.system_core.get_drive_info()
            if not drives:
                raise Exception("No drives detected or invalid drive data")
                
            self.boot_drive = drives[0]
            
            # Validate drive data
            if not isinstance(self.boot_drive, dict):
                raise Exception("Invalid drive information format")
                
            required_fields = ['Index', 'Model', 'SerialNumber', 'Size']
            for field in required_fields:
                if field not in self.boot_drive:
                    raise Exception(f"Missing required drive field: {field}")
            
            self.wipe_decision = self.system_core.determine_wipe_method(self.boot_drive)
            
            if not self.wipe_decision or not isinstance(self.wipe_decision, dict):
                raise Exception("Failed to determine wipe method")
                
        except Exception as e:
            error_msg = f"Drive detection failed: {str(e)}"
            messagebox.showerror("Drive Detection Error", error_msg)
            self.root.quit()
            return
        
        
        main_frame = tk.Frame(self.root, bg='#2c3e50', padx=40, pady=40)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        
        title_label = tk.Label(main_frame, text="SHUDDH - THE DESTROYER", 
                              font=('Arial', 24, 'bold'), fg='#e74c3c', bg='#2c3e50')
        title_label.pack(pady=(0, 30))
        
        
        warning_frame = tk.Frame(main_frame, bg='#e74c3c', padx=3, pady=3)
        warning_frame.pack(fill=tk.X, pady=(0, 20))
        
        inner_frame = tk.Frame(warning_frame, bg='#34495e', padx=20, pady=20)
        inner_frame.pack(fill=tk.BOTH, expand=True)
        
        
        warning_text = f"""WARNING: This tool will PERMANENTLY ERASE USER DATA
on the following drive:

    Drive: {self.boot_drive.get('DeviceID', 'Unknown')}
    Model: {self.boot_drive.get('Model', 'Unknown')}
    Serial: {self.boot_drive.get('SerialNumber', 'Unknown')}
    Size: {self.boot_drive.get('SizeGB', 0)} GB

Will wipe: User files, downloads, temp files, installed programs
Will preserve: Windows OS, system files, boot partition

This action cannot be undone."""
        
        warning_label = tk.Label(inner_frame, text=warning_text, 
                               font=('Arial', 12, 'bold'), fg='white', bg='#34495e',
                               justify=tk.LEFT)
        warning_label.pack()
        
        # Checkboxes
        self.backup_var = tk.BooleanVar()
        self.understand_var = tk.BooleanVar()
        
        checkbox_frame = tk.Frame(main_frame, bg='#2c3e50')
        checkbox_frame.pack(pady=20)
        
        backup_check = tk.Checkbutton(checkbox_frame, text="I have backed up all my important data.",
                                    variable=self.backup_var, font=('Arial', 11),
                                    fg='white', bg='#2c3e50', selectcolor='#34495e',
                                    command=self.check_consent)
        backup_check.pack(anchor=tk.W, pady=5)
        
        understand_check = tk.Checkbutton(checkbox_frame, text="I understand this is irreversible.",
                                        variable=self.understand_var, font=('Arial', 11),
                                        fg='white', bg='#2c3e50', selectcolor='#34495e',
                                        command=self.check_consent)
        understand_check.pack(anchor=tk.W, pady=5)
        
        # Start button
        self.start_button = tk.Button(main_frame, text="I AGREE, START PURIFICATION",
                                    font=('Arial', 14, 'bold'), fg='white', bg='#e74c3c',
                                    padx=30, pady=10, state=tk.DISABLED,
                                    command=self.start_purification)
        self.start_button.pack(pady=30)
    
    def check_consent(self):
        """Enable start  only when both checkboxes are checked"""
        if self.backup_var.get() and self.understand_var.get():
            self.start_button.config(state=tk.NORMAL)
        else:
            self.start_button.config(state=tk.DISABLED)
    
    def start_purification(self):
        """Start the purification process"""
    
        result = messagebox.askyesno("Final Confirmation", 
                                   "Are you absolutely sure you want to permanently erase all data?\n\nThis cannot be undone!")
        if not result:
            return
        
        self.current_screen = "progress"
        self.setup_ui()
        
        # Start process in thread with proper exception handling
        def safe_execute_purification():
            try:
                self.execute_purification()
            except Exception as e:
                sanitized_error = str(e).replace('\n', ' ').replace('\r', '')
                self.root.after(0, lambda: messagebox.showerror("Purification Error", f"Critical error: {sanitized_error}"))
                self.root.after(0, self.root.quit)
        
        threading.Thread(target=safe_execute_purification, daemon=True).start()
    
    def show_progress_screen(self):
        """Screen 2: Progress Screen"""
        main_frame = tk.Frame(self.root, bg='#2c3e50', padx=40, pady=40)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        title_label = tk.Label(main_frame, text="USER DATA WIPE IN PROGRESS", 
                              font=('Arial', 24, 'bold'), fg='#f39c12', bg='#2c3e50')
        title_label.pack(pady=(0, 30))
        
        warning_label = tk.Label(main_frame, 
                               text="Please do not turn off your computer or disconnect power.",
                               font=('Arial', 12), fg='#e74c3c', bg='#2c3e50')
        warning_label.pack(pady=(0, 30))
        
        # Progress stages
        self.stage_frame = tk.Frame(main_frame, bg='#2c3e50')
        self.stage_frame.pack(pady=20)
        
        self.stages = [
            ("Analyzing drive...", "processing"),
            ("Executing secure erase...", "processing"),
            ("Verifying wipe...", "processing"),
            ("Generating certificate...", "processing")
        ]
        
        self.stage_labels = []
        for i, (stage_text, status) in enumerate(self.stages):
            stage_label = tk.Label(self.stage_frame, text=f"Current Stage: {stage_text}",
                                 font=('Arial', 12), fg='white', bg='#2c3e50')
            stage_label.pack(anchor=tk.W, pady=5)
            self.stage_labels.append(stage_label)
        
        # Time estimate
        method = self.wipe_decision.get('primary_method', 'AES_128_CTR') if self.wipe_decision else 'AES_128_CTR'
        time_estimate = self.estimate_time(method)
        
        self.time_label = tk.Label(main_frame, text=f"Estimated Time Remaining: {time_estimate}",
                                 font=('Arial', 12), fg='#3498db', bg='#2c3e50')
        self.time_label.pack(pady=20)
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, length=400, mode='determinate')
        self.progress.pack(pady=20)
    
    def estimate_time(self, method):
        """Estimate completion time"""
        if method == "NVME_FORMAT_NVM": #for nvme
            return "~30 seconds"
        elif method == "ATA_SECURE_ERASE":  #for ssd
            return "~2 minutes"
        else:
            size_gb = self.boot_drive.get('SizeGB', 500) if self.boot_drive else 500
            hours = size_gb / 360  
            if hours < 1:
                return f"~{int(hours * 60)} minutes"
            else:
                return f"~{int(hours)} hours"
    
    def update_stage(self, stage_index, status):
        """Update stage status"""
        if stage_index < len(self.stage_labels):
            stage_text, _ = self.stages[stage_index]
            if status == "active":
                symbol = "🏃🏻‍➡️"
                color = "#f39c12"
            elif status == "complete":
                symbol = "✓"
                color = "#27ae60"
            else:
                symbol = ""
                color = "white"
            
            self.stage_labels[stage_index].config(
                text=f"Current Stage: {stage_text} {symbol}",
                fg=color
            )
    
    def execute_purification(self):
        """Execute the actual purification process"""
        self.wipe_in_progress = True
        emergency_handler.set_current_operation("Data purification")
        
        try:
            # Validate drive info before starting
            if not self.boot_drive or not isinstance(self.boot_drive, dict):
                raise Exception("Invalid drive information")
                
            drive_index = self.boot_drive.get('Index')
            if drive_index is None or not isinstance(drive_index, int) or drive_index < 0:
                raise Exception(f"Invalid drive index: {drive_index}")
            
            #1: Analyzing drive
            def update_stage_0():
                self.update_stage(0, "active")
                self.progress.config(value=10)
            self.root.after(0, update_stage_0)
            
            # Validate drive access
            if not self.system_core.validate_drive_access(drive_index):
                raise Exception(f"Cannot access drive {drive_index}")
            
            #2: Execute wipe
            def update_stage_1():
                self.update_stage(0, "complete")
                self.update_stage(1, "active")
                self.progress.config(value=25)
            self.root.after(0, update_stage_1)
            
            # Validate wipe decision
            if not self.wipe_decision or not isinstance(self.wipe_decision, dict):
                raise Exception("Invalid wipe method decision")
            
            wipe_result = self.wipe_engine.execute_wipe(self.boot_drive, self.wipe_decision)
            
            if not wipe_result or not wipe_result.get('success', False):
                error_msg = wipe_result.get('error', 'Unknown wipe error') if wipe_result else 'Wipe returned no result'
                raise Exception(f"Wipe failed: {error_msg}")
            
            #3: Verification
            def update_stage_2():
                self.progress.config(value=70)
                self.update_stage(1, "complete")
                self.update_stage(2, "active")
            self.root.after(0, update_stage_2)
            
            verification_result = self.verification_engine.run_phase3_verification(self.boot_drive, wipe_result)
            
            if not verification_result or not verification_result.get('success', False):
                error_msg = verification_result.get('error', 'Unknown verification error') if verification_result else 'Verification returned no result'
                raise Exception(f"Verification failed: {error_msg}")
            
            #4: Certificate generation
            def update_stage_3():
                self.progress.config(value=90)
                self.update_stage(2, "complete")
                self.update_stage(3, "active")
            self.root.after(0, update_stage_3)
            
            # Store results for success screen
            self.verification_result = verification_result
            
            def update_final():
                self.progress.config(value=100)
                self.update_stage(3, "complete")
            self.root.after(0, update_final)
            
            # Move to success screen
            self.root.after(1000, self.show_success_screen_transition)
            
        except Exception as e:
            error_msg = f"Purification failed: {str(e)}"
            self.root.after(0, lambda: messagebox.showerror("Purification Failed", error_msg))
            self.root.after(0, self.root.quit)
        finally:
            self.wipe_in_progress = False
            emergency_handler.set_current_operation(None)
    
    def show_success_screen_transition(self):
        """Transition to success screen"""
        self.current_screen = "success"
        self.setup_ui()
    
    def show_success_screen(self):
        """Screen 3: Success & Results Screen"""
        main_frame = tk.Frame(self.root, bg='#2c3e50', padx=40, pady=40)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = tk.Label(main_frame, text="USER DATA WIPE SUCCESSFUL!", 
                              font=('Arial', 24, 'bold'), fg='#27ae60', bg='#2c3e50')
        title_label.pack(pady=(0, 30))
        
        serial = self.boot_drive.get('SerialNumber', 'Unknown') if self.boot_drive else 'Unknown'
        success_text = f"""User data on drive ({serial}) has been securely wiped.
Windows OS and system files have been preserved.

Your tamper-proof certificate has been saved to your Desktop."""
        
        success_label = tk.Label(main_frame, text=success_text,
                               font=('Arial', 12), fg='white', bg='#2c3e50',
                               justify=tk.CENTER)
        success_label.pack(pady=(0, 30))
        
        # Certificate files
        if hasattr(self, 'verification_result') and self.verification_result:
            export_result = self.verification_result.get('export_result', {})
            if export_result:
                json_path = export_result.get('json_certificate_path', '')
                pdf_path = export_result.get('pdf_certificate_path', '')
                
                if json_path:
                    json_filename = Path(json_path).name
                    json_label = tk.Label(main_frame, text=json_filename,
                                        font=('Arial', 11, 'bold'), fg='#3498db', bg='#2c3e50')
                    json_label.pack()
                
                if pdf_path:
                    pdf_filename = Path(pdf_path).name
                    pdf_label = tk.Label(main_frame, text=pdf_filename,
                                       font=('Arial', 11, 'bold'), fg='#3498db', bg='#2c3e50')
                    pdf_label.pack()
        
 
        final_label = tk.Label(main_frame, 
                             text="You have successfully deleted all the data on your drive (the data is not recoverable). Stay secure!",
                             font=('Arial', 12), fg='white', bg='#2c3e50')
        final_label.pack(pady=30)
        
     
        exit_button = tk.Button(main_frame, text="EXIT",
                              font=('Arial', 14, 'bold'), fg='white', bg='#27ae60',
                              padx=30, pady=10, command=self.root.quit)
        exit_button.pack()
    
    def run(self):
        """Run the application"""
        self.root.mainloop()


if __name__ == "__main__":
    app = ShuddApp()
    app.run()