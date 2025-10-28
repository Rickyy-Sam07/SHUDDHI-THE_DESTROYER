"""
Shuddh - OS-Safe Data Wiper GUI
===============================

Streamlined GUI with comprehensive error handling and display.
Shows all errors clearly with copy functionality for troubleshooting.
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import traceback
import sys
from datetime import datetime
from pathlib import Path

try:
    from production_system_core import SystemCore, AdminPrivilegeError, HardwareDetectionError
    from production_wipe_engine import WipeEngine, WipeExecutionError
    from production_verification_engine import VerificationEngine
    from emergency_handler import EmergencyHandler
    from report_generator import ReportGenerator
    from checksum_verifier import ChecksumVerifier
except ImportError as e:
    print(f"Import Error: {e}")
    sys.exit(1)


class ErrorDisplay:
    """Centralized error display with copy functionality"""
    
    def __init__(self, parent):
        self.parent = parent
        self.errors = []
        
    def log_error(self, error_type: str, message: str, details: str = ""):
        """Log an error with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        error_entry = {
            'timestamp': timestamp,
            'type': error_type,
            'message': message,
            'details': details,
            'full_text': f"[{timestamp}] {error_type}: {message}\n{details}".strip()
        }
        self.errors.append(error_entry)
        
    def show_errors_window(self):
        """Show all errors in a copyable window"""
        if not self.errors:
            messagebox.showinfo("No Errors", "No errors have been logged.")
            return
            
        error_window = tk.Toplevel(self.parent)
        error_window.title("Error Log - Shuddh")
        error_window.geometry("800x600")
        
        # Error text display
        text_area = scrolledtext.ScrolledText(error_window, wrap=tk.WORD, font=('Consolas', 10))
        text_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Populate with all errors
        all_errors = "\n" + "="*80 + "\n"
        all_errors += f"SHUDDH ERROR LOG - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        all_errors += "="*80 + "\n\n"
        
        for error in self.errors:
            all_errors += error['full_text'] + "\n\n"
            
        text_area.insert(tk.END, all_errors)
        text_area.config(state=tk.DISABLED)
        
        # Copy button
        def copy_errors():
            error_window.clipboard_clear()
            error_window.clipboard_append(all_errors)
            messagebox.showinfo("Copied", "Error log copied to clipboard!")
            
        copy_btn = ttk.Button(error_window, text="Copy All Errors", command=copy_errors)
        copy_btn.pack(pady=5)


class ShuddGUI:
    """Streamlined Shuddh GUI with comprehensive error handling"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Shuddh - OS-Safe Data Wiper")
        self.root.geometry("800x700")
        
        # Initialize components
        self.error_display = ErrorDisplay(self.root)
        self.system_core = None
        self.wipe_engine = None
        self.verification_engine = None
        self.emergency_handler = EmergencyHandler()
        self.report_generator = ReportGenerator()
        
        # State tracking
        self.selected_drive = None
        self.drives_data = []
        self.wipe_result = None
        self.wipe_complete_flag = False
        self.selected_method = None
        self.available_methods = []
        
        self.setup_gui()
        self.initialize_system()
        
    def setup_gui(self):
        """Create the main GUI layout"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="Shuddh - OS-Safe Data Wiper", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Status display
        self.status_var = tk.StringVar(value="Initializing...")
        status_label = ttk.Label(main_frame, textvariable=self.status_var, 
                                font=('Arial', 10))
        status_label.grid(row=1, column=0, columnspan=2, pady=(0, 10))
        
        # Drive selection frame
        drive_frame = ttk.LabelFrame(main_frame, text="Select Drive to Wipe", padding="10")
        drive_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Drive listbox
        self.drive_listbox = tk.Listbox(drive_frame, height=6, font=('Consolas', 9))
        self.drive_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 10))
        self.drive_listbox.bind('<<ListboxSelect>>', self.on_drive_select)
        
        # Drive info display
        self.drive_info_text = scrolledtext.ScrolledText(drive_frame, width=40, height=6, 
                                                        font=('Consolas', 8))
        self.drive_info_text.grid(row=0, column=1, sticky=(tk.W, tk.E))
        
        # Wipe method selection frame
        method_frame = ttk.LabelFrame(main_frame, text="Select Wipe Method", padding="10")
        method_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))
        
        self.method_var = tk.StringVar()
        self.method_listbox = tk.Listbox(method_frame, height=4, font=('Consolas', 9))
        self.method_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 10))
        self.method_listbox.bind('<<ListboxSelect>>', self.on_method_select)
        
        # Method info display
        self.method_info_text = scrolledtext.ScrolledText(method_frame, width=40, height=4, 
                                                         font=('Consolas', 8))
        self.method_info_text.grid(row=0, column=1, sticky=(tk.W, tk.E))
        
        method_frame.columnconfigure(0, weight=1)
        method_frame.columnconfigure(1, weight=1)
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=2, pady=10)
        
        # Action buttons
        self.refresh_btn = ttk.Button(button_frame, text="Refresh Drives", 
                                     command=self.refresh_drives)
        self.refresh_btn.grid(row=0, column=0, padx=5)
        
        self.wipe_btn = ttk.Button(button_frame, text="Start Wipe", 
                                  command=self.start_wipe, state=tk.DISABLED)
        self.wipe_btn.grid(row=0, column=1, padx=5)
        
        self.errors_btn = ttk.Button(button_frame, text="View Errors", 
                                    command=self.error_display.show_errors_window)
        self.errors_btn.grid(row=0, column=2, padx=5)
        
        self.footprint_btn = ttk.Button(button_frame, text="Clean Footprints", 
                                       command=self.clean_footprints, state=tk.DISABLED)
        self.footprint_btn.grid(row=0, column=3, padx=5)
        
        # Progress frame
        progress_frame = ttk.LabelFrame(main_frame, text="Operation Progress", padding="10")
        progress_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))
        
        self.progress_var = tk.StringVar(value="Ready")
        progress_label = ttk.Label(progress_frame, textvariable=self.progress_var)
        progress_label.grid(row=0, column=0, sticky=tk.W)
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='indeterminate')
        self.progress_bar.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(5, 0))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        drive_frame.columnconfigure(0, weight=1)
        drive_frame.columnconfigure(1, weight=1)
        progress_frame.columnconfigure(0, weight=1)
        
    def initialize_system(self):
        """Initialize system components with error handling"""
        try:
            self.system_core = SystemCore()
            self.wipe_engine = WipeEngine()
            self.verification_engine = VerificationEngine()
            
            # Check admin privileges
            if not self.system_core.check_admin():
                self.error_display.log_error("PRIVILEGE_ERROR", 
                    "Administrator privileges required",
                    "Shuddh requires administrator privileges to access drives directly.")
                self.status_var.set("ERROR: Administrator privileges required")
                messagebox.showerror("Admin Required", 
                    "Shuddh requires administrator privileges.\nPlease run as administrator.")
                return
                
            self.status_var.set("System initialized successfully")
            self.refresh_drives()
            
        except Exception as e:
            error_details = traceback.format_exc()
            self.error_display.log_error("INITIALIZATION_ERROR", str(e), error_details)
            self.status_var.set("ERROR: System initialization failed")
            messagebox.showerror("Initialization Error", 
                f"Failed to initialize system:\n{str(e)}\n\nClick 'View Errors' for details.")
    
    def refresh_drives(self):
        """Refresh the drive list with error handling"""
        try:
            self.status_var.set("Scanning drives...")
            self.drive_listbox.delete(0, tk.END)
            self.drive_info_text.delete(1.0, tk.END)
            
            if not self.system_core:
                raise Exception("System core not initialized")
                
            self.drives_data = self.system_core.get_drive_info()
            
            if not self.drives_data:
                self.status_var.set("No drives detected")
                self.drive_listbox.insert(tk.END, "No drives found")
                return
                
            for drive in self.drives_data:
                drive_text = f"Drive {drive['Index']}: {drive['Model']} ({drive['SizeGB']} GB)"
                self.drive_listbox.insert(tk.END, drive_text)
                
            self.status_var.set(f"Found {len(self.drives_data)} drives")
            
        except HardwareDetectionError as e:
            self.error_display.log_error("HARDWARE_DETECTION_ERROR", str(e), 
                "Failed to detect system drives. This may be due to WMI issues or missing dependencies.")
            self.status_var.set("ERROR: Drive detection failed")
            messagebox.showerror("Drive Detection Error", 
                f"Failed to detect drives:\n{str(e)}\n\nClick 'View Errors' for details.")
        except Exception as e:
            error_details = traceback.format_exc()
            self.error_display.log_error("DRIVE_SCAN_ERROR", str(e), error_details)
            self.status_var.set("ERROR: Drive scan failed")
            messagebox.showerror("Drive Scan Error", 
                f"Failed to scan drives:\n{str(e)}\n\nClick 'View Errors' for details.")
    
    def on_drive_select(self, event):
        """Handle drive selection"""
        try:
            selection = self.drive_listbox.curselection()
            if not selection or not self.drives_data:
                return
                
            drive_index = selection[0]
            if drive_index >= len(self.drives_data):
                return
                
            self.selected_drive = self.drives_data[drive_index]
            
            # Display drive information
            self.drive_info_text.delete(1.0, tk.END)
            drive_info = f"""Drive Information:
Index: {self.selected_drive['Index']}
Model: {self.selected_drive['Model']}
Size: {self.selected_drive['SizeGB']} GB
Interface: {self.selected_drive['InterfaceType']}
Type: {self.selected_drive['DriveType']}
Serial: {self.selected_drive['SerialNumber']}
Status: {self.selected_drive['Status']}
Partitions: {self.selected_drive['Partitions']}"""
            
            self.drive_info_text.insert(tk.END, drive_info)
            
            # Check if it's the system drive
            if self.system_core.is_system_drive(self.selected_drive['Index']):
                self.drive_info_text.insert(tk.END, "\n\n⚠️ SYSTEM DRIVE - OS-safe wipe only")
            else:
                self.drive_info_text.insert(tk.END, "\n\n✓ Safe to wipe")
            
            # Load compatible wipe methods
            self.load_compatible_methods()
            self.wipe_btn.config(state=tk.DISABLED)
                
        except Exception as e:
            error_details = traceback.format_exc()
            self.error_display.log_error("DRIVE_SELECT_ERROR", str(e), error_details)
            self.status_var.set("ERROR: Drive selection failed")
    
    def load_compatible_methods(self):
        """Load wipe methods compatible with selected drive"""
        try:
            self.method_listbox.delete(0, tk.END)
            self.method_info_text.delete(1.0, tk.END)
            
            if not self.selected_drive:
                return
            
            # Get compatible methods from wipe engine
            self.available_methods = self.wipe_engine.get_compatible_methods(self.selected_drive)
            
            for method in self.available_methods:
                method_text = f"{method['name']} ({method['passes']} pass{'es' if method['passes'] > 1 else ''})"
                self.method_listbox.insert(tk.END, method_text)
            
            # Select first method by default
            if self.available_methods:
                self.method_listbox.selection_set(0)
                self.on_method_select(None)
                
        except Exception as e:
            error_details = traceback.format_exc()
            self.error_display.log_error("METHOD_LOAD_ERROR", str(e), error_details)
    
    def on_method_select(self, event):
        """Handle wipe method selection"""
        try:
            selection = self.method_listbox.curselection()
            if not selection or not self.available_methods:
                return
            
            method_index = selection[0]
            if method_index >= len(self.available_methods):
                return
            
            self.selected_method = self.available_methods[method_index]
            
            # Display method information
            self.method_info_text.delete(1.0, tk.END)
            detected_type = self.selected_method.get('detected_type', 'Unknown')
            method_info = f"""Method: {self.selected_method['name']}
Passes: {self.selected_method['passes']}
Detected Type: {detected_type}
Compatible: {', '.join(self.selected_method['compatible'])}
Description: {self.selected_method['description']}"""
            
            if 'note' in self.selected_method:
                method_info += f"\n\nNote: {self.selected_method['note']}"
            
            self.method_info_text.insert(tk.END, method_info)
            
            # Enable wipe button and footprint cleaning
            method_name = self.selected_method['name']
            self.wipe_btn.config(text=f"Start {method_name}", state=tk.NORMAL)
            self.footprint_btn.config(state=tk.NORMAL)
            
        except Exception as e:
            error_details = traceback.format_exc()
            self.error_display.log_error("METHOD_SELECT_ERROR", str(e), error_details)
    
    def start_wipe(self):
        """Start the wipe operation in a separate thread"""
        if not self.selected_drive:
            messagebox.showwarning("No Drive Selected", "Please select a drive to wipe.")
            return
        
        if not self.selected_method:
            messagebox.showwarning("No Method Selected", "Please select a wipe method.")
            return
            
        # Confirmation dialog
        drive_name = f"Drive {self.selected_drive['Index']}: {self.selected_drive['Model']}"
        method_name = self.selected_method['name']
        if not messagebox.askyesno("Confirm Wipe", 
            f"Are you sure you want to wipe {drive_name}\nusing {method_name}?\n\nThis action cannot be undone!"):
            return
            
        # Disable UI during wipe
        self.wipe_btn.config(state=tk.DISABLED)
        self.refresh_btn.config(state=tk.DISABLED)
        self.footprint_btn.config(state=tk.DISABLED)
        self.progress_bar.start()
        self.progress_var.set("Starting wipe operation...")
        
        # Initialize result tracking
        self.wipe_result = None
        self.wipe_complete_flag = False
        
        # Start wipe in separate thread
        wipe_thread = threading.Thread(target=self.perform_wipe, daemon=True)
        wipe_thread.start()
        
        # Monitor completion
        self.monitor_wipe_completion()
    
    def perform_wipe(self):
        """Perform the actual wipe operation"""
        try:
            # Validate drive access
            if not self.system_core.validate_drive_access(self.selected_drive['Index']):
                raise Exception("Cannot access selected drive for wiping")
            
            # Determine wipe method
            wipe_method = self.system_core.determine_wipe_method(self.selected_drive)
            
            # === REPORT GENERATION: Collect data BEFORE wipe ===
            print(f"\n📊 Collecting drive information before wipe...")
            self.report_generator.collect_drive_info_before(self.selected_drive)
            
            # Get drive letter from the collected data
            drive_letter = self.report_generator.report_data.get("drive_info_before", {}).get("drive_letter")
            
            if drive_letter:
                print(f"📍 Detected drive letter: {drive_letter}")
            else:
                print(f"⚠️  No drive letter found in drive info")
            
            # Calculate pre-wipe checksum (if possible for the drive type)
            print(f"🔐 Calculating pre-wipe checksum...")
            pre_wipe_checksum = None
            post_wipe_checksum = None
            checksum_verifier = None
            
            if drive_letter:
                try:
                    checksum_verifier = ChecksumVerifier(drive_letter)
                    pre_wipe_checksum = checksum_verifier.calculate_pre_wipe_checksum()
                    print(f"✓ Pre-wipe checksum calculated successfully")
                except Exception as e:
                    print(f"⚠️  Could not calculate pre-wipe checksum: {str(e)[:100]}")
                    pre_wipe_checksum = {
                        'checksum': 'N/A',
                        'timestamp': datetime.now().isoformat(),
                        'status': 'FAILED',
                        'error': str(e)
                    }
            else:
                print(f"⚠️  No drive letter found, skipping checksum calculation")
                pre_wipe_checksum = {
                    'checksum': 'N/A',
                    'timestamp': datetime.now().isoformat(),
                    'status': 'SKIPPED'
                }
            
            # Execute wipe using selected method
            drive_path = self.selected_drive['DeviceID']
            method_id = self.selected_method['method_id']
            result = self.wipe_engine.execute_wipe_method(method_id, drive_path, self.selected_drive)
            
            if result['success']:
                # === REPORT GENERATION: Collect data AFTER wipe ===
                print(f"\n📊 Collecting drive information after wipe...")
                self.report_generator.collect_drive_info_after(self.selected_drive)
                
                # Calculate post-wipe checksum
                print(f"🔐 Calculating post-wipe checksum...")
                if drive_letter and checksum_verifier:
                    try:
                        post_wipe_checksum = checksum_verifier.calculate_post_wipe_checksum()
                        print(f"✓ Post-wipe checksum calculated successfully")
                    except Exception as e:
                        print(f"⚠️  Could not calculate post-wipe checksum: {str(e)[:100]}")
                        post_wipe_checksum = {
                            'checksum': 'N/A',
                            'timestamp': datetime.now().isoformat(),
                            'status': 'FAILED',
                            'error': str(e)
                        }
                else:
                    post_wipe_checksum = {
                        'checksum': 'N/A',
                        'timestamp': datetime.now().isoformat(),
                        'status': 'SKIPPED'
                    }
                
                # Add checksum verification to report
                self.report_generator.add_checksum_verification(pre_wipe_checksum, post_wipe_checksum)
                
                # Add wipe process information
                self.report_generator.add_wipe_process_info(
                    result, 
                    self.selected_method['name'],
                    method_id
                )
                
                # Generate deletion proof
                print(f"📊 Generating data deletion proof...")
                self.report_generator.generate_data_deletion_proof()
                
                # Save report
                print(f"📝 Generating comprehensive report...")
                report_path = self.report_generator.save_report(self.selected_drive)
                
                # Print report location to console
                print(f"\n✅ ═══════════════════════════════════════════════════════")
                print(f"✅ Comprehensive report saved to:")
                print(f"✅ {report_path}")
                print(f"✅ ═══════════════════════════════════════════════════════\n")
                
                # Get Desktop path
                desktop_path = str(Path.home() / "Desktop")
                
                # Always show desktop path regardless of certificate generation
                success_msg = (f"Wipe operation completed successfully!\n\n"
                              f"Files wiped: {result['files_wiped']:,}\n"
                              f"Data destroyed: {result['bytes_written']:,} bytes\n\n"
                              f"Report saved to:\n{report_path}\n\n"
                              f"Certificate Location:\n"
                              f"Desktop: {desktop_path}\n\n")
                
                try:
                    # Generate verification certificate
                    verification_result = self.verification_engine.run_phase3_verification(
                        self.selected_drive, result)
                    
                    if verification_result and verification_result.get('success'):
                        # Get certificate information
                        export_result = verification_result.get('export_result', {})
                        cert_id = export_result.get('certificate_id', 'Unknown')
                        json_path = export_result.get('json_certificate_path', '')
                        pdf_path = export_result.get('pdf_certificate_path', '')
                        
                        # Add certificate details to message
                        success_msg += f"Certificate ID: {cert_id}\n\n"
                        
                        # Build certificate file list
                        cert_files = []
                        if json_path:
                            cert_files.append(Path(json_path).name)
                        if pdf_path:
                            cert_files.append(Path(pdf_path).name)
                        
                        if cert_files:
                            cert_list = "\n".join([f"  • {file}" for file in cert_files])
                            success_msg += f"Certificate Files:\n{cert_list}"
                        else:
                            success_msg += "Certificate files generated"
                    else:
                        success_msg += "Note: Certificate generation failed"
                        
                except Exception as cert_error:
                    success_msg += f"Note: Certificate error - {str(cert_error)[:50]}"
                
                self.wipe_result = ('success', success_msg)
            else:
                raise WipeExecutionError("Wipe operation failed")
                
        except WipeExecutionError as e:
            self.error_display.log_error("WIPE_EXECUTION_ERROR", str(e),
                "The wipe operation failed during execution. Drive may be locked or inaccessible.")
            self.wipe_result = ('error', f"Wipe operation failed:\n{str(e)}\n\nClick 'View Errors' for details.")
        except Exception as e:
            error_details = traceback.format_exc()
            self.error_display.log_error("WIPE_ERROR", str(e), error_details)
            self.wipe_result = ('error', f"Wipe operation failed:\n{str(e)}\n\nClick 'View Errors' for details.")
        finally:
            # Signal completion
            self.wipe_complete_flag = True
    
    def monitor_wipe_completion(self):
        """Monitor wipe completion and update UI"""
        if self.wipe_complete_flag:
            self.progress_bar.stop()
            self.wipe_btn.config(state=tk.NORMAL)
            self.refresh_btn.config(state=tk.NORMAL)
            self.footprint_btn.config(state=tk.NORMAL if self.selected_drive else tk.DISABLED)
            
            if self.wipe_result:
                result_type, message = self.wipe_result
                if result_type == 'success':
                    self.progress_var.set("Wipe completed successfully")
                    messagebox.showinfo("Wipe Complete", message)
                else:
                    self.progress_var.set("ERROR: Wipe operation failed")
                    messagebox.showerror("Wipe Failed", message)
            return
            
        # Check again in 100ms
        self.root.after(100, self.monitor_wipe_completion)
        
    def clean_footprints(self):
        """Clean digital footprints for selected drive"""
        if not self.selected_drive:
            messagebox.showwarning("No Drive Selected", "Please select a drive to clean footprints for.")
            return
        
        # Get drive letter
        try:
            partitions = self.wipe_engine._get_partition_info_for_drive(self.selected_drive['Index'])
            if partitions:
                drive_letter = partitions[0]['drive_letter']
            else:
                drive_letter = "C"
        except Exception:
            drive_letter = "C"
        
        # Confirmation dialog
        if not messagebox.askyesno("Clean Footprints", 
            f"Clean digital footprints for drive {drive_letter}:\\?\n\n"
            "This will remove:\n"
            "• Registry entries\n"
            "• Recent file references\n"
            "• Prefetch files\n"
            "• Jump lists\n"
            "• Event logs\n"
            "• Temp files\n\n"
            "WARNING: This action cannot be undone!"):
            return
        
        try:
            self.progress_var.set("Cleaning digital footprints...")
            self.progress_bar.start()
            
            # Perform footprint cleaning
            result = self.wipe_engine.scan_and_clean_footprints(drive_letter)
            
            self.progress_bar.stop()
            
            if result['success']:
                messagebox.showinfo("Footprints Cleaned", 
                    f"Digital footprint cleanup completed!\n\n"
                    f"Total findings: {result['total_findings']}\n"
                    f"Cleaned traces: {result['cleaned_count']}\n\n"
                    f"Status: {result['status']}")
                self.progress_var.set("Footprint cleanup completed")
            else:
                messagebox.showerror("Cleanup Failed", 
                    f"Footprint cleanup failed:\n{result.get('error', 'Unknown error')}")
                self.progress_var.set("ERROR: Footprint cleanup failed")
                
        except Exception as e:
            self.progress_bar.stop()
            error_details = traceback.format_exc()
            self.error_display.log_error("FOOTPRINT_CLEANUP_ERROR", str(e), error_details)
            messagebox.showerror("Cleanup Error", 
                f"Failed to clean footprints:\n{str(e)}\n\nClick 'View Errors' for details.")
            self.progress_var.set("ERROR: Footprint cleanup failed")
    
    def run(self):
        """Start the GUI application"""
        # Setup emergency handler
        self.root.bind('<Escape>', lambda e: self.emergency_handler.trigger_emergency_quit("ESC key pressed"))
        
        # Start the main loop
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            self.emergency_handler.trigger_emergency_quit("Keyboard interrupt")


def main():
    """Main entry point"""
    try:
        app = ShuddGUI()
        app.run()
    except Exception as e:
        print(f"Fatal error: {e}")
        traceback.print_exc()
        input("Press Enter to exit...")


if __name__ == "__main__":
    main()