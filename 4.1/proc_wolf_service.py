#!/usr/bin/env python3
"""
proc-wolf-service: Windows service version of proc-wolf (FAST START VERSION)
------------------------------------------------------
Runs proc-wolf as a background Windows service with immediate status reporting
"""

import os
import sys
import time
import logging
import threading
import servicemanager
import win32event
import win32service
import win32serviceutil

# --- 1. CONFIGURATION AND INITIAL SETUP ---

# Ensure we can import from proc-wolf
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

# Import proc_wolf in a way that works with PyInstaller
try:
    from proc_wolf import Database, monitor_processes, init_database
except ImportError:
    # If running as a frozen exe, try this approach
    try:
        if hasattr(sys, '_MEIPASS'):
            # PyInstaller creates a temp folder and stores path in _MEIPASS
            base_path = sys._MEIPASS
        else:
            base_path = os.path.abspath(".")
        
        sys.path.insert(0, base_path)
        
        # Try a direct import of the code
        from proc_wolf import Database, monitor_processes, init_database
    except ImportError as e:
        # Last resort - inline the essential functions
        print(f"Failed to import proc_wolf: {e}")
        sys.exit(1)

# Configure logging to a file in a standard location
log_dir = os.path.join(os.environ.get('PROGRAMDATA', r'C:\ProgramData'), 'proc-wolf')
log_file = os.path.join(log_dir, 'proc-wolf-service.log')
os.makedirs(log_dir, exist_ok=True)

# Use basicConfig for the service log file
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename=log_file,
    filemode='a'
)

# --- 2. SERVICE CLASS DEFINITION ---

class ProcWolfService(win32serviceutil.ServiceFramework):
    """Windows Service Implementation for Proc-Wolf with FAST startup."""
    
    _svc_name_ = "ProcWolfService"
    _svc_display_name_ = "Proc-Wolf Advanced Process Monitor"
    _svc_description_ = "Monitors and protects against suspicious process activity."
    
    def __init__(self, args):
        """Constructor of the service"""
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.is_running = False
        self.monitor_thread = None

    def SvcStop(self):
        """Called when the service is asked to stop"""
        # Tell Windows we're stopping
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        
        # Signal the main loop to exit
        win32event.SetEvent(self.hWaitStop)
        self.is_running = False
        
        logging.info("Service stop signal received.")
        
        # Wait for monitor thread to finish (max 5 seconds)
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5.0)
        
        # Log to event log
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STOPPED,
            (self._svc_name_, '')
        )
        
        # Report stopped
        self.ReportServiceStatus(win32service.SERVICE_STOPPED)

    def SvcDoRun(self):
        """Called when the service is starting"""
        try:
            # CRITICAL: Report RUNNING status IMMEDIATELY
            # This prevents the timeout error
            self.ReportServiceStatus(win32service.SERVICE_START_PENDING)
            
            # Report running BEFORE doing any heavy initialization
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            
            # Log success
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, '')
            )
            
            logging.info("Service reported RUNNING status to Windows SCM")
            self.is_running = True
            
            # Now do the actual work in a separate thread
            # This allows the service to respond to Windows immediately
            self.monitor_thread = threading.Thread(target=self.run_monitor, daemon=True)
            self.monitor_thread.start()
            
            # Main thread just waits for stop signal
            # This keeps the service responsive to Windows
            win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)
            
        except Exception as e:
            logging.error(f"Failed in SvcDoRun: {e}")
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_ERROR_TYPE,
                servicemanager.PYS_SERVICE_STARTING,
                (str(e),)
            )
            self.SvcStop()
    
    def run_monitor(self):
        """Run the actual monitoring in a separate thread"""
        try:
            logging.info("Starting monitor thread...")
            
            # Initialize database (this might take a few seconds)
            logging.info("Initializing database...")
            db = init_database()
            logging.info("Database initialized successfully.")
            
            # Run the monitoring loop
            logging.info("Starting proc_wolf.monitor_processes...")
            monitor_processes(db, self.hWaitStop)
            logging.info("proc_wolf.monitor_processes has exited.")
            
        except Exception as e:
            logging.error(f"Critical error in monitor thread: {e}")
            # Don't stop the service, just log the error
            # The service can be restarted by Windows if needed

# --- 3. EXECUTION HANDLER ---

if __name__ == '__main__':
    if len(sys.argv) == 1:
        # Service is being started by SCM
        try:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(ProcWolfService)
            servicemanager.StartServiceCtrlDispatcher()
        except Exception as e:
            # If running directly, show usage
            print("ProcWolf Service cannot be run directly.")
            print("To install: ProcWolfService.exe --startup auto install")
            print("To start: net start ProcWolfService")
            print("To stop: net stop ProcWolfService")
            print("To remove: ProcWolfService.exe remove")
    else:
        # Handle command line arguments
        win32serviceutil.HandleCommandLine(ProcWolfService)