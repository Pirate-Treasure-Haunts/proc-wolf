#!/usr/bin/env python3
"""
proc-wolf-background: Hidden window version of proc-wolf
-------------------------------------------------------
Runs proc-wolf in the background without a console window
"""

import os
import sys
import time
import logging
import subprocess
import threading
from PIL import Image, ImageDraw
import pystray
import tkinter as tk
from tkinter import simpledialog, messagebox, ttk

# Ensure we can import from proc-wolf
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
try:
    from proc_wolf import (
        Database, monitor_processes, init_database,
        add_to_whitelist, remove_from_whitelist, get_whitelist_entries
    )
    import psutil
except ImportError as e:
    print(f"Error: Could not import from proc_wolf module: {e}")
    sys.exit(1)

# Configure logging
log_dir = os.path.join(os.environ.get('LOCALAPPDATA', os.path.expanduser('~')), 'proc-wolf')
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, 'proc-wolf-background.log')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename=log_file,
    filemode='a'
)

class WhitelistManager:
    def __init__(self, parent=None):
        self.root = tk.Toplevel(parent) if parent else tk.Tk()
        self.root.title("proc-wolf Whitelist Manager")
        self.root.geometry("600x500")
        self.root.resizable(True, True)
        self.setup_ui()
        
    def setup_ui(self):
        """Create the UI elements"""
        # Frame for the list and buttons
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Top info section
        info_frame = ttk.LabelFrame(main_frame, text="Information", padding=10)
        info_frame.pack(fill=tk.X, expand=False, pady=(0, 10))
        
        info_text = ttk.Label(
            info_frame, 
            text=("Applications and directories in the whitelist are trusted and will never be flagged as threats.\n"
                 "You can add applications by name or full paths to trusted directories.\n"
                 "The whitelist is securely signed to prevent tampering."),
            wraplength=550, 
            justify='left'
        )
        info_text.pack(fill=tk.X, expand=True)
        
        # Current running processes frame
        processes_frame = ttk.LabelFrame(main_frame, text="Current Processes", padding=10)
        processes_frame.pack(fill=tk.BOTH, expand=True, side=tk.LEFT, padx=(0, 5))
        
        # Whitelist frame
        whitelist_frame = ttk.LabelFrame(main_frame, text="Whitelist", padding=10)
        whitelist_frame.pack(fill=tk.BOTH, expand=True, side=tk.RIGHT, padx=(5, 0))
        
        # Process list
        process_list_frame = ttk.Frame(processes_frame)
        process_list_frame.pack(fill=tk.BOTH, expand=True)
        
        self.process_listbox = tk.Listbox(process_list_frame, selectmode=tk.SINGLE)
        self.process_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        process_scrollbar = ttk.Scrollbar(process_list_frame, orient=tk.VERTICAL, command=self.process_listbox.yview)
        process_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.process_listbox.config(yscrollcommand=process_scrollbar.set)
        
        # Process list buttons
        process_btn_frame = ttk.Frame(processes_frame)
        process_btn_frame.pack(fill=tk.X, pady=(5, 0))
        
        ttk.Button(process_btn_frame, text="Refresh Process List", command=self.refresh_process_list).pack(side=tk.LEFT, padx=2)
        ttk.Button(process_btn_frame, text="Add Process to Whitelist", command=self.add_process).pack(side=tk.LEFT, padx=2)
        
        # Whitelist
        whitelist_list_frame = ttk.Frame(whitelist_frame)
        whitelist_list_frame.pack(fill=tk.BOTH, expand=True)
        
        self.whitelist_listbox = tk.Listbox(whitelist_list_frame, selectmode=tk.SINGLE)
        self.whitelist_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        whitelist_scrollbar = ttk.Scrollbar(whitelist_list_frame, orient=tk.VERTICAL, command=self.whitelist_listbox.yview)
        whitelist_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.whitelist_listbox.config(yscrollcommand=whitelist_scrollbar.set)
        
        # Whitelist buttons
        whitelist_btn_frame = ttk.Frame(whitelist_frame)
        whitelist_btn_frame.pack(fill=tk.X, pady=(5, 0))
        
        ttk.Button(whitelist_btn_frame, text="Refresh Whitelist", command=self.refresh_whitelist).pack(side=tk.LEFT, padx=2)
        ttk.Button(whitelist_btn_frame, text="Add Custom Entry", command=self.add_custom_entry).pack(side=tk.LEFT, padx=2)
        ttk.Button(whitelist_btn_frame, text="Remove Selected", command=self.remove_entry).pack(side=tk.LEFT, padx=2)
        
        # Bottom buttons
        bottom_frame = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        bottom_frame.pack(fill=tk.X, expand=False)
        
        ttk.Button(bottom_frame, text="Close", command=self.root.destroy).pack(side=tk.RIGHT, padx=5)
        
        # Load initial data
        self.refresh_process_list()
        self.refresh_whitelist()
    
    def refresh_process_list(self):
        """Refresh the list of running processes"""
        self.process_listbox.delete(0, tk.END)
        
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    processes.append((proc.info['name'], proc.info['exe']))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Sort by name
            processes.sort(key=lambda x: x[0].lower())
            
            # Add to listbox
            unique_names = sorted(list(set(name for name, _ in processes)))
            for name in unique_names:
                self.process_listbox.insert(tk.END, name)
                
        except Exception as e:
            messagebox.showerror("Error", f"Error refreshing process list: {e}")
    
    def refresh_whitelist(self):
        """Refresh the whitelist display"""
        self.whitelist_listbox.delete(0, tk.END)
        
        try:
            entries = get_whitelist_entries()
            for entry in entries:
                self.whitelist_listbox.insert(tk.END, entry)
        except Exception as e:
            messagebox.showerror("Error", f"Error refreshing whitelist: {e}")
    
    def add_process(self):
        """Add selected process to whitelist"""
        selection = self.process_listbox.curselection()
        if not selection:
            messagebox.showinfo("Info", "Please select a process to add")
            return
            
        index = selection[0]
        process_name = self.process_listbox.get(index)
        
        # Find the executable path
        try:
            process_path = None
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    if proc.info['name'] == process_name:
                        process_path = proc.info['exe']
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Add to whitelist
            add_to_whitelist(process_name, process_path)
            messagebox.showinfo("Success", f"Added '{process_name}' to whitelist")
            
            # Refresh whitelist display
            self.refresh_whitelist()
            
        except Exception as e:
            messagebox.showerror("Error", f"Error adding process to whitelist: {e}")
    
    def add_custom_entry(self):
        """Add a custom entry to the whitelist"""
        entry = simpledialog.askstring(
            "Add Custom Entry", 
            "Enter process name (e.g., chrome.exe) or directory path (e.g., C:\\Program Files\\App\\):"
        )
        
        if not entry:
            return
            
        try:
            # Check if it's a directory path
            path = os.path.normpath(entry)
            if os.path.exists(path) and os.path.isdir(path):
                # Ensure directory ends with slash
                if not entry.endswith('\\') and not entry.endswith('/'):
                    entry = entry + '/'
                    
            # Add to whitelist
            add_to_whitelist(entry)
            messagebox.showinfo("Success", f"Added '{entry}' to whitelist")
            
            # Refresh whitelist display
            self.refresh_whitelist()
            
        except Exception as e:
            messagebox.showerror("Error", f"Error adding entry to whitelist: {e}")
    
    def remove_entry(self):
        """Remove selected entry from whitelist"""
        selection = self.whitelist_listbox.curselection()
        if not selection:
            messagebox.showinfo("Info", "Please select an entry to remove")
            return
            
        index = selection[0]
        entry = self.whitelist_listbox.get(index)
        
        # Confirm removal
        confirm = messagebox.askyesno("Confirm", f"Remove '{entry}' from whitelist?")
        if not confirm:
            return
            
        try:
            # Remove from whitelist
            remove_from_whitelist(entry)
            messagebox.showinfo("Success", f"Removed '{entry}' from whitelist")
            
            # Refresh whitelist display
            self.refresh_whitelist()
            
        except Exception as e:
            messagebox.showerror("Error", f"Error removing entry from whitelist: {e}")

class ProcWolfBackground:
    """Background process for proc-wolf with system tray icon"""
    
    def __init__(self):
        self.running = False
        self.monitor_thread = None
        self.icon = None
        # *** FIX: Use a threading.Event for graceful shutdown ***
        self.stop_event = threading.Event()
    
    def create_icon(self):
        """Create a system tray icon"""
        # Create a simple wolf icon
        image = Image.new('RGBA', (64, 64), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)
        
        # Draw a simple wolf head shape (very simplified)
        # Head
        draw.ellipse((10, 10, 54, 54), fill=(128, 128, 128, 255))
        # Ears
        draw.polygon([(10, 20), (5, 5), (20, 15)], fill=(100, 100, 100, 255))
        draw.polygon([(54, 20), (59, 5), (44, 15)], fill=(100, 100, 100, 255))
        # Eyes
        draw.ellipse((20, 25, 30, 35), fill=(255, 255, 255, 255))
        draw.ellipse((34, 25, 44, 35), fill=(255, 255, 255, 255))
        draw.ellipse((23, 28, 27, 32), fill=(0, 0, 0, 255))
        draw.ellipse((37, 28, 41, 32), fill=(0, 0, 0, 255))
        # Nose
        draw.ellipse((29, 35, 35, 41), fill=(0, 0, 0, 255))
        
        # Store the image for later use
        self.tray_icon_image = image
        
        # Create the system tray icon with menu
        self.icon = pystray.Icon(
            "proc-wolf",
            self.tray_icon_image,
            "Proc-Wolf Monitor",
            menu=pystray.Menu(
                pystray.MenuItem("Open Control Panel", self.open_control_panel),
                pystray.MenuItem("Check Status", self.check_status),
                pystray.MenuItem("Manage Whitelist", self.open_whitelist_manager),
                pystray.MenuItem("Exit", self.exit)
            )
        )
    
    def open_control_panel(self, icon, item):
        """Open the proc-wolf control panel"""
        try:
            # Find the ProcWolfCLI executable
            cli_exe = "ProcWolfCLI.exe"
            if not os.path.exists(cli_exe):
                cli_exe = os.path.join(os.path.dirname(sys.executable), "ProcWolfCLI.exe")
            if not os.path.exists(cli_exe):
                cli_exe = "proc_wolf_full_4-0.py"
                
            # Use subprocess to open it with a new console window
            subprocess.Popen(
                [cli_exe, "list", "--assess"] if not cli_exe.endswith(".py") else [sys.executable, cli_exe, "list", "--assess"],
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
        except Exception as e:
            logging.error(f"Error opening control panel: {e}")
            self.show_notification("Error", f"Could not open control panel: {e}")
    
    def check_status(self, icon, item):
        """Check the status of the proc-wolf monitor"""
        if self.running and self.monitor_thread and self.monitor_thread.is_alive():
            self.show_notification("Proc-Wolf Status", "Proc-Wolf is running and monitoring your system.")
        else:
            self.show_notification("Proc-Wolf Status", "Proc-Wolf is not monitoring! Click to restart.")
            self.start_monitoring()
            
    def open_whitelist_manager(self, icon, item):
        """Open the whitelist management dialog"""
        try:
            manager = WhitelistManager()
            manager.root.mainloop()
        except Exception as e:
            logging.error(f"Error opening whitelist manager: {e}")
            self.show_notification("Error", f"Could not open whitelist manager: {e}")
    
    def show_notification(self, title, message):
        """Show a notification from the system tray icon"""
        self.icon.notify(message, title)
    
    def start_monitoring(self):
        """Start the process monitoring thread"""
        if self.running and self.monitor_thread and self.monitor_thread.is_alive():
            return
        
        self.running = True
        # *** FIX: Clear the stop event in case of restart ***
        self.stop_event.clear()
        self.monitor_thread = threading.Thread(target=self.monitor_loop)
        self.monitor_thread.daemon = True # Keep as daemon, but we will try to join() on exit
        self.monitor_thread.start()
        logging.info("Monitoring thread started")
    
    def monitor_loop(self):
        """Main monitoring loop"""
        try:
            # Initialize database
            logging.info("Monitoring loop: Initializing database...")
            db = init_database()
            logging.info("Monitoring loop: Database initialized.")
            
            # Start monitoring processes
            # *** FIX: Pass the stop_event to the real monitoring function ***
            monitor_processes(db, stop_event=self.stop_event)
            
        except ConnectionError as e:
            # *** FIX: Handle database connection error gracefully ***
            logging.critical(f"Failed to initialize database: {e}")
            self.show_notification("Proc-Wolf Error", "Failed to start monitoring: Could not open database.")
            self.running = False
        except Exception as e:
            logging.error(f"Error in monitoring loop: {e}")
            self.running = False
        
        logging.info("Monitoring loop has exited.")
    
    def exit(self, icon, item):
        """Exit the application"""
        logging.info("Proc-Wolf background process stopping")
        self.running = False
        
        # *** FIX: Signal the thread to stop and wait for it ***
        if self.stop_event:
            self.stop_event.set()
            
        if self.monitor_thread:
            # Wait for the thread to exit (up to 2 seconds)
            self.monitor_thread.join(timeout=2) 
            
        icon.stop()
        os._exit(0) # Use os._exit for a hard exit if thread is stuck
    
    def run(self):
        """Run the background process"""
        try:
            # Hide console window on Windows
            if os.name == 'nt':
                import win32con
                import win32gui
                try:
                    win32gui.ShowWindow(win32gui.GetForegroundWindow(), win32con.SW_HIDE)
                except Exception as e:
                    logging.warning(f"Could not hide console window: {e}")
            
            # Create and run system tray icon
            self.create_icon()
            
            # Start monitoring in a separate thread
            self.start_monitoring()
            
            # Log that we're running
            logging.info("Proc-Wolf system tray monitor starting")
            
            # Run the icon loop (blocks until icon.stop() is called)
            self.icon.run()
        except Exception as e:
            logging.error(f"Error running background process: {e}")

if __name__ == "__main__":
    try:
        app = ProcWolfBackground()
        app.run()
    except Exception as e:
        logging.error(f"Error in main: {e}")