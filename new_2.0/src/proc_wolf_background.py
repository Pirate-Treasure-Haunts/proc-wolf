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

# Ensure we can import from proc-wolf
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
try:
    from proc_wolf import Database, monitor_processes, init_database
except ImportError:
    print("Error: Could not import from proc_wolf module")
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

class ProcWolfBackground:
    """Background process for proc-wolf with system tray icon"""
    
    def __init__(self):
        self.running = False
        self.monitor_thread = None
        self.icon = None
    
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
        
        # Create the system tray icon
        self.icon = pystray.Icon(
            "proc-wolf",
            image,
            "Proc-Wolf Monitor",
            menu=pystray.Menu(
                pystray.MenuItem("Open Control Panel", self.open_control_panel),
                pystray.MenuItem("Check Status", self.check_status),
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
                cli_exe = "proc_wolf_full_3-0.py"
                
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
    
    def show_notification(self, title, message):
        """Show a notification from the system tray icon"""
        self.icon.notify(message, title)
    
    def start_monitoring(self):
        """Start the process monitoring thread"""
        if self.running and self.monitor_thread and self.monitor_thread.is_alive():
            return
        
        self.running = True
        self.monitor_thread = threading.Thread(target=self.monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        logging.info("Monitoring thread started")
    
    def monitor_loop(self):
        """Main monitoring loop"""
        try:
            # Initialize database
            db = init_database()
            
            # Start monitoring processes
            monitor_processes(db)
        except Exception as e:
            logging.error(f"Error in monitoring loop: {e}")
            self.running = False
    
    def exit(self, icon, item):
        """Exit the application"""
        icon.stop()
        self.running = False
        logging.info("Proc-Wolf background process stopping")
        os._exit(0)
    
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