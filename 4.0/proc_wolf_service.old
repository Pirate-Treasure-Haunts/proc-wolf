#!/usr/bin/env python3
"""
proc-wolf-service: Windows service version of proc-wolf
------------------------------------------------------
Runs proc-wolf as a background Windows service
"""

import os
import sys
import time
import logging
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

# Also log to Windows Event Log during setup/initialization failures
# This uses the Windows-native logging mechanism
def log_and_exit(message, error_type=servicemanager.EVENTLOG_ERROR_TYPE):
    """Log a message to the service file and the Windows Event Log, then exit."""
    logging.error(message)
    try:
        servicemanager.LogMsg(error_type, servicemanager.PYS_SERVICE_STARTING, (message,))
    except Exception as e:
        logging.error(f"Failed to log to Event Log: {e}")

# --- 2. SERVICE CLASS DEFINITION ---

class ProcWolfService(win32serviceutil.ServiceFramework):
    """Windows Service Implementation for Proc-Wolf."""
    
    _svc_name_ = "ProcWolfService"
    _svc_display_name_ = "Proc-Wolf Advanced Process Monitor"
    _svc_description_ = "Monitors and protects against suspicious process activity."
    
    def __init__(self, args):
        """Constructor of the service"""
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.is_running = False

    def SvcStop(self):
        """Called when the service is asked to stop"""
        # Tell win32service that we are in the process of stopping
        # FIX: Use the framework's ReportServiceStatus helper method
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        
        # Signal the main loop (in SvcDoRun) to exit
        win32event.SetEvent(self.hWaitStop)
        self.is_running = False
        
        logging.info("Service stop signal received.")
        
        # Log to event log
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STOPPED,
            (self._svc_name_, '')
        )
        
        # Set final status 
        # FIX: Use the framework's ReportServiceStatus helper method
        self.ReportServiceStatus(win32service.SERVICE_STOPPED)

    def SvcDoRun(self):
        """Called when the service is starting"""
        # --- START FIX FOR INSTALL.BAT TIMEOUT ISSUE & DEBUG ERROR ---
        try:
            # 1. Report that we are in the process of starting
            # FIX: Use the framework's ReportServiceStatus helper method
            self.ReportServiceStatus(win32service.SERVICE_START_PENDING)
            
            # 2. Immediately report SERVICE_RUNNING status. This is CRITICAL to stop the SCM from timing out.
            # FIX: Use the framework's ReportServiceStatus helper method
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)

            # Log the success for the Windows Event Log
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, '')
            )
            logging.info(f"Service is now running (Status Reported).")
        except Exception as e:
            # Use the standalone log_and_exit function (as fixed in the last step)
            log_and_exit(f"Failed to report SERVICE_RUNNING status: {e}", servicemanager.EVENTLOG_ERROR_TYPE)
            return
        # --- END FIX ---

        self.is_running = True
        
        # Initialize the database and get the object
        logging.info("Initializing database...")
        try:
            db = init_database()
            logging.info("Database initialized successfully.")
        except Exception as e:
            logging.error(f"Failed to initialize database: {e}")
            log_and_exit(f"Failed to initialize database: {e}", servicemanager.EVENTLOG_ERROR_TYPE)
            self.SvcStop() # Stop service on failure
            return

        # Call the main monitoring loop from proc_wolf
        logging.info("Calling proc_wolf.monitor_processes with service stop_event")
        
        try:
            # Pass the stop event to the monitoring function to allow graceful exit
            monitor_processes(db, self.hWaitStop)
        except Exception as e:
            # A crash in the monitor loop itself
            logging.error(f"Critical error in monitor_processes loop: {e}")
            log_and_exit(f"Critical error in monitor_processes loop: {e}", servicemanager.EVENTLOG_ERROR_TYPE)
            self.SvcStop() 
            
        logging.info("proc_wolf.monitor_processes has exited.")

# --- 4. EXECUTION HANDLER ---

if __name__ == '__main__':
    # win32serviceutil.HandleCommandLine handles both direct execution (for usage print)
    # and service dispatch (when called by SCM)
    
    if len(sys.argv) == 1:
        # User ran the EXE directly without arguments (e.g., ProcWolfService.exe)
        # We need to manually initialize to handle the error output
        try:
            # Handle direct execution - explain how to use
            print("ProcWolf Service cannot be run directly.")
            print("To install the service, run: ProcWolfService.exe --startup auto install")
            print("To start the service, run: ProcWolfService.exe start")
            print("To stop the service, run: ProcWolfService.exe stop")
            print("To remove the service, run: ProcWolfService.exe remove")
        except Exception:
            # If stdout/stderr is closed (as when run by SCM), initialize and dispatch
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(ProcWolfService)
            servicemanager.StartServiceCtrlDispatcher()
    else:
        # Handle command line arguments (--startup auto install, start, stop, remove)
        win32serviceutil.HandleCommandLine(ProcWolfService)