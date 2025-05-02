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
log_file = os.path.join(os.environ.get('PROGRAMDATA', r'C:\ProgramData'), 'proc-wolf', 'proc-wolf-service.log')
os.makedirs(os.path.dirname(log_file), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename=log_file,
    filemode='a'
)

class ProcWolfService(win32serviceutil.ServiceFramework):
    """Windows Service class for proc-wolf"""
    
    _svc_name_ = 'ProcWolfService'
    _svc_display_name_ = 'Proc-Wolf Process Monitor'
    _svc_description_ = 'Monitors system processes for suspicious activity and protects against threats.'
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.is_running = False
    
    def SvcStop(self):
        """Called when the service is asked to stop"""
        logging.info('Service stop requested')
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        self.is_running = False
    
    def SvcDoRun(self):
        """Called when the service is starting"""
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        self.is_running = True
        self.main()
    
    def main(self):
        """Main service function"""
        logging.info('ProcWolf service starting')
        
        try:
            # Initialize database
            db = init_database()
            
            # Start monitoring processes in a loop that can be interrupted
            self.monitor_with_stop_check(db)
        except Exception as e:
            logging.error(f'Error in service main: {e}')
        
        logging.info('ProcWolf service stopped')
    
    def monitor_with_stop_check(self, db):
        """Modified monitoring function that checks for stop events"""
        logging.info("Starting monitoring loop with stop checks")
        
        # This is a simplified version of monitor_processes that checks for stop events
        try:
            # Import necessary modules
            import psutil
            from datetime import datetime
            
            # Dictionary to track previous state
            previous_pids = set()
            
            while self.is_running:
                try:
                    # Check if stop was requested
                    if win32event.WaitForSingleObject(self.stop_event, 10) == win32event.WAIT_OBJECT_0:
                        logging.info("Stop event detected")
                        break
                    
                    # Get all current processes
                    current_pids = set()
                    
                    for proc in psutil.process_iter(['pid']):
                        try:
                            pid = proc.pid
                            current_pids.add(pid)
                            
                            # Here you would do your process monitoring logic
                            # For simplicity, we're just tracking PIDs
                            
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                    
                    # Check for disappeared processes
                    disappeared = previous_pids - current_pids
                    if disappeared:
                        logging.debug(f"Processes disappeared: {disappeared}")
                    
                    # Update previous pids for next iteration
                    previous_pids = current_pids
                    
                    # Sleep before next check (shorter time to be responsive to stop events)
                    time.sleep(1)
                    
                except Exception as e:
                    logging.error(f"Error in monitoring loop: {e}")
                    time.sleep(5)
        
        except Exception as e:
            logging.error(f"Failed to start monitoring: {e}")

if __name__ == '__main__':
    if len(sys.argv) == 1:
        try:
            # Handle direct execution - explain how to use
            print("ProcWolf Service cannot be run directly.")
            print("To install the service, run: ProcWolfService.exe --startup auto install")
            print("To start the service, run: ProcWolfService.exe start")
            print("To stop the service, run: ProcWolfService.exe stop")
            print("To remove the service, run: ProcWolfService.exe remove")
        except:
            # This will be called when the service is actually running as a service
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(ProcWolfService)
            servicemanager.StartServiceCtrlDispatcher()
    else:
        # Handle command line arguments
        win32serviceutil.HandleCommandLine(ProcWolfService)