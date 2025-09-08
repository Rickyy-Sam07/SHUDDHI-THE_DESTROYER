"""
Shuddh - The destroyer

PRODUCTION VERSION - ALL SAFETY FEATURES REMOVED
This version performs ACTUAL data destruction operations.

!!! WARNING: to all the devs who will read this code !!!
This file is the production build of the Shuddh application.
It is designed to permanently erase data from drives.
DO NOT run this script or the resulting executable on your main system as it will destroy data permanently.

File Structure:
- ShuddApp: Main application class handling GUI and workflow
- Three-screen workflow: Warning/Consent → Progress → Success
- Emergency handling system for safe abort operations
- Integration with system core, wipe engine, and verification engine
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
    """Main application class for Shuddh data wiper GUI
    
    Manages the complete user workflow from warning screen to completion.
    Integrates with all backend engines for drive detection, wiping, and verification.
    """
    
    def __init__(self):
        """Initialize the main application window and components"""
        # Initialize main Tkinter window
        self.root = tk.Tk()
        self.root.title("Shuddh - Data Purification Tool")
        self.root.geometry("800x600")
        self.root.configure(bg='#2c3e50')  # Dark blue-gray theme
        
        # Initialize backend engines (development_mode=False for production)
        # These engines handle hardware detection, data wiping, and verification
        self.system_core = SystemCore(development_mode=False)  # Hardware detection and admin management
        self.wipe_engine = WipeEngine(development_mode=False)   # Data destruction engine
        self.verification_engine = VerificationEngine(development_mode=False)  # Certificate generation
        
        # Application state variables
        self.boot_drive = None          # Selected drive information
        self.wipe_decision = None       # Determined wipe method (NVMe/ATA/AES)
        self.wipe_in_progress = False   # Flag to track active wipe operations
        
        # UI state management - controls which screen is displayed
        self.current_screen = "warning"  # Start with warning/consent screen
        
        # Setup emergency quit system before any operations
        self.setup_emergency_handling()
        
        # Verify administrator privileges are available
        # This is critical as drive operations require admin rights
        if not self.system_core.check_admin():
            messagebox.showerror("Admin Required", "This application requires administrator privileges.")
            self.system_core.elevate_privileges()  # Attempt UAC elevation
        
        # Setup emergency handling (duplicate call removed in production)
        self.setup_emergency_handling()
        
        # Initialize the user interface
        self.setup_ui()
    
    def setup_emergency_handling(self):
        """Setup comprehensive emergency quit functionality
        
        Provides multiple ways for users to safely abort operations:
        - ESC key for immediate emergency quit
        - Window close button with confirmation
        - Ctrl+C signal handling (via emergency_handler)
        """
        # Register our cleanup function with the global emergency handler
        # This ensures proper resource cleanup during emergency exits
        emergency_handler.register_cleanup(self.emergency_cleanup)
        
        # Bind ESC key to emergency quit - fastest abort method
        self.root.bind('<Escape>', lambda e: self.emergency_quit())
        
        # Override default window close behavior to check for active operations
        # Prevents accidental data loss during wipe operations
        self.root.protocol("WM_DELETE_WINDOW", self.on_window_close)
    
    def emergency_cleanup(self):
        """Emergency cleanup function called during abort operations
        
        Safely terminates any active wipe operations and cleans up resources.
        This function must never raise exceptions as it's called during emergency exits.
        """
        try:
            if self.wipe_in_progress:
                # Signal the wipe engine to abort current operations
                # This sets a threading.Event that the wipe engine checks periodically
                if hasattr(self.wipe_engine, 'abort_flag'):
                    self.wipe_engine.abort_flag.set()
                    
                # Force cleanup of any open file handles or system resources
                # This prevents file locks or drive access issues
                if hasattr(self.wipe_engine, '_cleanup_resources'):
                    self.wipe_engine._cleanup_resources()
        except Exception as e:
            # Log error but don't raise - emergency cleanup should never fail
            # During emergency situations, we prioritize safe exit over error reporting
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
        """Screen 1: Warning & Consent Screen
        
        This is the first screen users see. It:
        1. Detects available drives using WMI
        2. Identifies the boot drive (where Windows is installed)
        3. Determines the optimal wipe method based on drive type
        4. Displays warnings and requires user consent
        5. Shows drive information and wipe method details
        """
        try:
            # Get list of all physical drives using WMI (Windows Management Instrumentation)
            drives = self.system_core.get_drive_info()
            if not drives or not isinstance(drives, list):
                raise Exception("No drives detected or invalid drive data")
            
            # Find the actual boot drive (where Windows OS is installed)
            # This is critical to ensure we're wiping the correct drive
            self.boot_drive = self._find_boot_drive(drives)
            if not self.boot_drive:
                # Fallback to first drive if boot drive detection fails
                self.boot_drive = drives[0]
            
            # Validate that we have complete drive information
            if not isinstance(self.boot_drive, dict):
                raise Exception("Invalid drive information format")
                
            # Ensure all required fields are present for safe operation
            required_fields = ['Index', 'Model', 'SerialNumber', 'Size']
            for field in required_fields:
                if field not in self.boot_drive:
                    raise Exception(f"Missing required drive field: {field}")
            
            # Determine the best wipe method based on drive characteristics
            # NVMe drives use FORMAT_NVM, SATA SSDs use SECURE_ERASE, others use AES overwrite
            self.wipe_decision = self.system_core.determine_wipe_method(self.boot_drive)
            
            if not self.wipe_decision or not isinstance(self.wipe_decision, dict):
                raise Exception("Failed to determine wipe method")
                
        except Exception as e:
            # Sanitize error messages to prevent injection attacks in UI
            sanitized_error = str(e).replace('\n', ' ').replace('\r', '')
            error_msg = f"Drive detection failed: {sanitized_error}"
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
    
    def _find_boot_drive(self, drives):
        """Find the actual boot drive using Windows system directory
        
        This method identifies which physical drive contains the Windows OS installation.
        It uses WMI to map logical drives (C:, D:, etc.) to physical drives.
        
        Args:
            drives: List of physical drive information from get_drive_info()
            
        Returns:
            dict: Drive information for the boot drive, or first drive as fallback
        """
        try:
            import wmi
            c = wmi.WMI()
            
            # Get the system drive letter (usually C:) from environment
            system_drive = os.environ.get('SYSTEMDRIVE', 'C:').replace(':', '')
            
            # Map logical drives to physical drives using WMI associations
            for drive in drives:
                try:
                    # Check each partition on this physical drive
                    for partition in c.Win32_DiskPartition():
                        if partition.DiskIndex == drive.get('Index'):
                            # Check each logical disk (drive letter)
                            for logical_disk in c.Win32_LogicalDisk():
                                if (logical_disk.DeviceID.replace(':', '') == system_drive and
                                    logical_disk.DriveType == 3):  # DriveType 3 = Fixed disk
                                    # Verify the logical disk is on this partition
                                    partition_to_logical = c.Win32_LogicalDiskToPartition()
                                    for assoc in partition_to_logical:
                                        if (assoc.Antecedent.DeviceID == partition.DeviceID and 
                                            assoc.Dependent.DeviceID == logical_disk.DeviceID):
                                            return drive
                except Exception:
                    # Skip drives that can't be accessed or have errors
                    continue
            
            # Fallback: return first drive if boot drive detection fails
            return drives[0] if drives else None
            
        except Exception:
            # If WMI fails entirely, return first drive as safe fallback
            return drives[0] if drives else None
    
    def check_consent(self):
        """Enable start only when both checkboxes are checked"""
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
            # Assume 360 GB/hour write speed for estimation
            ASSUMED_WRITE_SPEED_GB_PER_HOUR = 360
            hours = size_gb / ASSUMED_WRITE_SPEED_GB_PER_HOUR  
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
        """Execute the actual purification process
        
        This is the core function that orchestrates the complete data wipe workflow:
        1. Drive analysis and validation
        2. Data wipe execution using determined method
        3. Verification of wipe completion
        4. Certificate generation for audit trail
        
        Runs in a separate thread to prevent UI freezing during long operations.
        Updates progress bar and stage indicators throughout the process.
        """
        # Set global state flags for emergency handling
        self.wipe_in_progress = True
        emergency_handler.set_current_operation("Data purification")
        
        try:
            # STAGE 1: Pre-flight validation
            # Ensure we have valid drive information before starting destructive operations
            if not self.boot_drive or not isinstance(self.boot_drive, dict):
                raise Exception("Invalid drive information")
                
            drive_index = self.boot_drive.get('Index')
            if drive_index is None or not isinstance(drive_index, int) or drive_index < 0:
                raise Exception(f"Invalid drive index: {drive_index}")
            
            # Update UI: Stage 1 - Analyzing drive
            def update_stage_0():
                self.update_stage(0, "active")
                self.progress.config(value=10)
            self.root.after(0, update_stage_0)
            
            # Validate that we can actually access the target drive
            # This prevents errors during the actual wipe operation
            if not self.system_core.validate_drive_access(drive_index):
                raise Exception(f"Cannot access drive {drive_index}")
            
            # STAGE 2: Execute data wipe
            def update_stage_1():
                self.update_stage(0, "complete")
                self.update_stage(1, "active")
                self.progress.config(value=25)
            self.root.after(0, update_stage_1)
            
            # Validate wipe method decision before execution
            if not self.wipe_decision or not isinstance(self.wipe_decision, dict):
                raise Exception("Invalid wipe method decision")
            
            # Execute the actual data wipe using the determined method
            # This is where the destructive operation happens
            wipe_result = self.wipe_engine.execute_wipe(self.boot_drive, self.wipe_decision)
            
            # Verify wipe completed successfully
            if not wipe_result or not wipe_result.get('success', False):
                error_msg = wipe_result.get('error', 'Unknown wipe error') if wipe_result else 'Wipe returned no result'
                raise Exception(f"Wipe failed: {error_msg}")
            
            # STAGE 3: Verification of wipe completion
            def update_stage_2():
                self.progress.config(value=70)
                self.update_stage(1, "complete")
                self.update_stage(2, "active")
            self.root.after(0, update_stage_2)
            
            # Run verification to confirm data was actually destroyed
            verification_result = self.verification_engine.run_phase3_verification(self.boot_drive, wipe_result)
            
            if not verification_result or not verification_result.get('success', False):
                error_msg = verification_result.get('error', 'Unknown verification error') if verification_result else 'Verification returned no result'
                raise Exception(f"Verification failed: {error_msg}")
            
            # STAGE 4: Certificate generation for audit trail
            def update_stage_3():
                self.progress.config(value=90)
                self.update_stage(2, "complete")
                self.update_stage(3, "active")
            self.root.after(0, update_stage_3)
            
            # Store verification results for display on success screen
            self.verification_result = verification_result
            
            # Final progress update
            def update_final():
                self.progress.config(value=100)
                self.update_stage(3, "complete")
            self.root.after(0, update_final)
            
            # Transition to success screen after brief delay
            self.root.after(1000, self.show_success_screen_transition)
            
        except Exception as e:
            # Handle any errors during the purification process
            sanitized_error = str(e).replace('\n', ' ').replace('\r', '')
            error_msg = f"Purification failed: {sanitized_error}"
            self.root.after(0, lambda: messagebox.showerror("Purification Failed", error_msg))
            self.root.after(0, self.root.quit)
        finally:
            # Always clean up state flags, even if operation failed
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