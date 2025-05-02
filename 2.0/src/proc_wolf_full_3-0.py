#!/usr/bin/env python3
"""
proc-wolf CLI: Command-line interface for proc-wolf process management
--------------------------------------------------------------------
Provides direct control over proc-wolf features including manual threat assessment,
process investigation, and nuke mode operations.
"""

import os
import sys
import argparse
import logging
import time
import sqlite3
import psutil
from datetime import datetime
from tabulate import tabulate

# Ensure we can import from proc-wolf
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from proc_wolf import (
    Database, get_process_info, evaluate_threat_level, 
    kill_process, prevent_resurrection, nuke_process,
    THREAT_LEVEL, ACTION_LEVEL, DB_FILE, is_admin
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='proc-wolf-cli.log',
    filemode='a'
)

# Console handler for immediate feedback
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)

def list_processes(args):
    """List processes with optional filtering"""
    try:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'username', 'cpu_percent']):
            try:
                # Get basic process info
                process_info = {
                    'pid': proc.pid,
                    'name': proc.name(),
                    'exe': proc.exe() if hasattr(proc, 'exe') else 'Access Denied',
                    'username': proc.username() if hasattr(proc, 'username') else 'Unknown',
                    'cpu_percent': proc.cpu_percent(interval=0.1)
                }
                
                # Apply name filter if specified
                if args.filter and args.filter.lower() not in process_info['name'].lower():
                    continue
                
                # Get threat assessment if requested
                if args.assess:
                    full_info = get_process_info(proc)
                    if full_info:
                        process_info['threat_level'] = full_info['threat_level']
                        process_info['threat'] = THREAT_LEVEL[full_info['threat_level']]
                    else:
                        process_info['threat_level'] = 'Error'
                        process_info['threat'] = 'Error'
                
                processes.append(process_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        # Sort processes by name or other criteria if specified
        if args.sort == 'cpu':
            processes.sort(key=lambda p: p['cpu_percent'], reverse=True)
        elif args.sort == 'threat' and args.assess:
            processes.sort(key=lambda p: p['threat_level'] if isinstance(p['threat_level'], int) else -1, reverse=True)
        else:
            processes.sort(key=lambda p: p['name'].lower())
        
        # Format for display
        if args.assess:
            headers = ['PID', 'Name', 'Path', 'User', 'CPU%', 'Threat']
            rows = [[p['pid'], p['name'], p['exe'], p['username'], f"{p['cpu_percent']:.1f}", p['threat']] 
                   for p in processes]
        else:
            headers = ['PID', 'Name', 'Path', 'User', 'CPU%']
            rows = [[p['pid'], p['name'], p['exe'], p['username'], f"{p['cpu_percent']:.1f}"] 
                   for p in processes]
        
        # Limit output if requested
        if args.limit > 0:
            rows = rows[:args.limit]
            
        print(tabulate(rows, headers=headers, tablefmt="grid"))
        print(f"\nTotal processes: {len(rows)}{' (limited output)' if args.limit > 0 and args.limit < len(processes) else ''}")
    
    except Exception as e:
        logging.error(f"Error listing processes: {e}")
        print(f"Error: {e}")

def kill_proc(args):
    """Kill a process by PID or name"""
    try:
        if args.pid:
            # Kill by PID
            try:
                pid = int(args.pid)
                proc = psutil.Process(pid)
                name = proc.name()
                
                if args.force:
                    result = kill_process(pid, force=True)
                    action = "Force killed"
                else:
                    result = kill_process(pid, force=False)
                    action = "Terminated"
                
                if result:
                    print(f"{action} process: {name} (PID: {pid})")
                else:
                    print(f"Failed to kill process: {name} (PID: {pid})")
            except psutil.NoSuchProcess:
                print(f"Error: No process found with PID {args.pid}")
            except Exception as e:
                print(f"Error killing process with PID {args.pid}: {e}")
        
        elif args.name:
            # Kill by name
            killed = 0
            failed = 0
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if args.name.lower() in proc.name().lower():
                        pid = proc.pid
                        name = proc.name()
                        
                        if args.force:
                            result = kill_process(pid, force=True)
                            action = "Force killed"
                        else:
                            result = kill_process(pid, force=False)
                            action = "Terminated"
                        
                        if result:
                            print(f"{action} process: {name} (PID: {pid})")
                            killed += 1
                        else:
                            print(f"Failed to kill process: {name} (PID: {pid})")
                            failed += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if killed == 0 and failed == 0:
                print(f"No processes found matching: {args.name}")
            else:
                print(f"\nSummary: {killed} processes killed, {failed} failed")
        
        else:
            print("Error: You must specify either --pid or --name")
    
    except Exception as e:
        logging.error(f"Error in kill_proc: {e}")
        print(f"Error: {e}")

def assess_threat(args):
    """Perform detailed threat assessment on a process"""
    try:
        if args.pid:
            # Assess by PID
            try:
                pid = int(args.pid)
                proc = psutil.Process(pid)
                process_info = get_process_info(proc)
                
                if process_info:
                    display_threat_assessment(process_info)
                else:
                    print(f"Error: Could not assess process with PID {pid}")
            except psutil.NoSuchProcess:
                print(f"Error: No process found with PID {args.pid}")
            except Exception as e:
                print(f"Error assessing process with PID {args.pid}: {e}")
        
        elif args.name:
            # Assess by name
            found = False
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if args.name.lower() in proc.name().lower():
                        found = True
                        process_info = get_process_info(proc)
                        
                        if process_info:
                            display_threat_assessment(process_info)
                            print("\n" + "-" * 80 + "\n")  # Separator between multiple processes
                        else:
                            print(f"Error: Could not assess process {proc.name()} (PID: {proc.pid})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if not found:
                print(f"No processes found matching: {args.name}")
        
        else:
            print("Error: You must specify either --pid or --name")
    
    except Exception as e:
        logging.error(f"Error in assess_threat: {e}")
        print(f"Error: {e}")

def display_threat_assessment(process_info):
    """Display detailed threat assessment for a process"""
    print("\n" + "=" * 80)
    print(f"THREAT ASSESSMENT: {process_info['name']} (PID: {process_info['pid']})")
    print("=" * 80)
    
    # Basic Information
    print("\n[Basic Information]")
    print(f"Process Name: {process_info['name']}")
    print(f"Process ID: {process_info['pid']}")
    print(f"Executable Path: {process_info['path'] or 'Unknown'}")
    print(f"Command Line: {process_info['cmd_line'] or 'Unknown'}")
    
    # Security Information
    print("\n[Security Information]")
    print(f"File Hash: {process_info['hash'] or 'Unknown'}")
    print(f"Digital Signature: {process_info['digital_signature'] or 'Not signed'}")
    print(f"Elevated Privileges: {'Yes' if process_info['elevated'] else 'No'}")
    
    # Threat Assessment
    print("\n[Threat Assessment]")
    print(f"Threat Level: {THREAT_LEVEL[process_info['threat_level']]}")
    print(f"Trusted Process: {'Yes' if process_info['trusted'] else 'No'}")
    
    # Suspicious Indicators
    print("\n[Suspicious Indicators]")
    
    indicators = []
    
    # Check name
    from proc_wolf import is_suspicious_name
    if is_suspicious_name(process_info['name']):
        indicators.append("Process name matches suspicious patterns")
    
    # Check location
    from proc_wolf import is_suspicious_location
    if process_info['path'] and is_suspicious_location(process_info['path']):
        indicators.append(f"Process is running from suspicious location: {process_info['path']}")
    
    # Check behavioral flags
    if process_info['suspicious_behavior']:
        for behavior in process_info['suspicious_behavior']:
            indicators.append(f"Suspicious behavior: {behavior}")
    
    # Display indicators or lack thereof
    if indicators:
        for indicator in indicators:
            print(f"⚠️ {indicator}")
    else:
        print("No suspicious indicators detected")
    
    # Recommended Action
    print("\n[Recommended Action]")
    
    # Get action level based on threat level
    from proc_wolf import get_action_level
    action_level = get_action_level(process_info['threat_level'], 0)
    
    print(f"Recommended action: {ACTION_LEVEL[action_level]}")
    
    if action_level == 0:
        print("This process appears to be safe and should be left alone.")
    elif action_level == 1:
        print("This process should be monitored for suspicious behavior.")
    elif action_level == 2:
        print("Consider terminating this process if not needed.")
    elif action_level == 3:
        print("This process should be terminated as soon as possible.")
    elif action_level == 4:
        print("This process should be forcibly terminated and prevented from restarting.")
    elif action_level == 5:
        print("This process should be completely removed from the system (NUKE mode).")

def nuke_cmd(args):
    """Execute nuke command on a process"""
    if not is_admin():
        print("Error: Nuke mode requires administrator privileges")
        return
        
    try:
        if args.pid:
            # Nuke by PID
            try:
                pid = int(args.pid)
                proc = psutil.Process(pid)
                name = proc.name()
                path = proc.exe() if hasattr(proc, 'exe') else None
                
                if args.force or confirm_nuke(name, pid):
                    print(f"Initiating NUKE sequence for {name} (PID: {pid})...")
                    result = nuke_process(pid, name, path)
                    
                    if result:
                        print(f"Successfully nuked process: {name} (PID: {pid})")
                    else:
                        print(f"Failed to nuke process: {name} (PID: {pid})")
                else:
                    print("Nuke operation cancelled")
            except psutil.NoSuchProcess:
                print(f"Error: No process found with PID {args.pid}")
            except Exception as e:
                print(f"Error nuking process with PID {args.pid}: {e}")
        
        elif args.name:
            # Nuke by name
            found = False
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if args.name.lower() in proc.name().lower():
                        found = True
                        pid = proc.pid
                        name = proc.name()
                        path = proc.exe() if hasattr(proc, 'exe') else None
                        
                        if args.force or confirm_nuke(name, pid):
                            print(f"Initiating NUKE sequence for {name} (PID: {pid})...")
                            result = nuke_process(pid, name, path)
                            
                            if result:
                                print(f"Successfully nuked process: {name} (PID: {pid})")
                            else:
                                print(f"Failed to nuke process: {name} (PID: {pid})")
                        else:
                            print(f"Nuke operation cancelled for {name} (PID: {pid})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if not found:
                print(f"No processes found matching: {args.name}")
        
        else:
            print("Error: You must specify either --pid or --name")
    
    except Exception as e:
        logging.error(f"Error in nuke_cmd: {e}")
        print(f"Error: {e}")

def confirm_nuke(process_name, pid):
    """Confirm nuke operation with user"""
    print("\n" + "!" * 80)
    print("WARNING: NUKE MODE WILL COMPLETELY REMOVE ALL TRACES OF THIS PROCESS")
    print("This includes files, registry entries, and services associated with it.")
    print("!" * 80)
    print(f"\nTarget: {process_name} (PID: {pid})")
    
    confirmation = input("\nAre you ABSOLUTELY SURE you want to proceed? (type 'NUKE' to confirm): ")
    return confirmation == "NUKE"

def history_cmd(args):
    """Display process history from database"""
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        if args.pid:
            # Try to find process ID in database
            cursor.execute(
                """
                SELECT p.*, COUNT(r.id) as resurrections 
                FROM process_history p
                LEFT JOIN resurrections r ON p.id = r.process_id
                WHERE p.id = ?
                GROUP BY p.id
                """,
                (args.pid,)
            )
            
            row = cursor.fetchone()
            if row:
                display_process_history(dict(row))
            else:
                print(f"No history found for process ID {args.pid}")
        
        elif args.name:
            # Find processes by name
            cursor.execute(
                """
                SELECT p.*, COUNT(r.id) as resurrections 
                FROM process_history p
                LEFT JOIN resurrections r ON p.id = r.process_id
                WHERE p.name LIKE ?
                GROUP BY p.id
                ORDER BY p.last_seen DESC
                """,
                (f"%{args.name}%",)
            )
            
            rows = cursor.fetchall()
            if rows:
                for row in rows:
                    display_process_history(dict(row))
                    print("\n" + "-" * 80 + "\n")  # Separator
                print(f"Found {len(rows)} matching processes")
            else:
                print(f"No history found for processes matching '{args.name}'")
        
        elif args.nuked:
            # Show nuked processes
            cursor.execute(
                """
                SELECT n.*, p.name as process_name
                FROM nuked_processes n
                LEFT JOIN process_history p ON n.process_id = p.id
                ORDER BY n.timestamp DESC
                """
            )
            
            rows = cursor.fetchall()
            if rows:
                print("\n" + "=" * 80)
                print("NUKED PROCESSES HISTORY")
                print("=" * 80 + "\n")
                
                headers = ['ID', 'Process', 'Timestamp', 'Artifacts Removed', 'Registry Keys', 'Service Removed', 'Success']
                table_rows = []
                
                for row in rows:
                    row_dict = dict(row)
                    table_rows.append([
                        row_dict['id'],
                        row_dict['name'],
                        row_dict['timestamp'],
                        row_dict['artifacts_removed'],
                        row_dict['registry_keys_removed'],
                        'Yes' if row_dict['service_removed'] else 'No',
                        'Success' if row_dict['success'] else 'Failed'
                    ])
                
                print(tabulate(table_rows, headers=headers, tablefmt="grid"))
                print(f"\nTotal: {len(rows)} nuked processes")
            else:
                print("No nuked processes found in history")
        
        else:
            # Default: show most recent processes
            limit = args.limit if args.limit > 0 else 10
            cursor.execute(
                """
                SELECT p.*, COUNT(r.id) as resurrections 
                FROM process_history p
                LEFT JOIN resurrections r ON p.id = r.process_id
                GROUP BY p.id
                ORDER BY p.last_seen DESC
                LIMIT ?
                """,
                (limit,)
            )
            
            rows = cursor.fetchall()
            if rows:
                print("\n" + "=" * 80)
                print("RECENT PROCESS HISTORY")
                print("=" * 80 + "\n")
                
                headers = ['ID', 'Name', 'Path', 'First Seen', 'Last Seen', 'Threat', 'Kills', 'Resurrections']
                table_rows = []
                
                for row in rows:
                    row_dict = dict(row)
                    table_rows.append([
                        row_dict['id'],
                        row_dict['name'],
                        row_dict['path'] or 'Unknown',
                        row_dict['first_seen'],
                        row_dict['last_seen'],
                        THREAT_LEVEL[row_dict['threat_level']],
                        row_dict['times_killed'],
                        row_dict['resurrections']
                    ])
                
                print(tabulate(table_rows, headers=headers, tablefmt="grid"))
                print(f"\nShowing {len(rows)} most recent processes")
            else:
                print("No process history found")
        
        conn.close()
    
    except Exception as e:
        logging.error(f"Error in history_cmd: {e}")
        print(f"Error: {e}")

def display_process_history(row):
    """Display detailed process history"""
    print("\n" + "=" * 80)
    print(f"PROCESS HISTORY: {row['name']} (ID: {row['id']})")
    print("=" * 80)
    
    # Basic Information
    print("\n[Basic Information]")
    print(f"Name: {row['name']}")
    print(f"Path: {row['path'] or 'Unknown'}")
    print(f"Command Line: {row['cmd_line'] or 'Unknown'}")
    print(f"File Hash: {row['hash'] or 'Unknown'}")
    
    # Timing Information
    print("\n[Timing Information]")
    print(f"First Seen: {row['first_seen']}")
    print(f"Last Seen: {row['last_seen']}")
    
    # Security Information
    print("\n[Security Information]")
    print(f"Digital Signature: {row['digital_signature'] or 'Not signed'}")
    print(f"Threat Level: {THREAT_LEVEL[row['threat_level']]}")
    print(f"Trusted: {'Yes' if row['trusted'] else 'No'}")
    
    # Activity Information
    print("\n[Activity Information]")
    print(f"Times Killed: {row['times_killed']}")
    print(f"Resurrections: {row.get('resurrections', 0)}")
    
    # Resurrection Details
    if row.get('resurrections', 0) > 0:
        try:
            conn = sqlite3.connect(DB_FILE)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute(
                """
                SELECT * FROM resurrections
                WHERE process_id = ?
                ORDER BY timestamp
                """,
                (row['id'],)
            )
            
            res_rows = cursor.fetchall()
            
            print("\n[Resurrection History]")
            for i, res in enumerate(res_rows, 1):
                res_dict = dict(res)
                print(f"{i}. {res_dict['timestamp']} - {res_dict['kill_method']}")
            
            conn.close()
        except Exception as e:
            print(f"Error retrieving resurrection history: {e}")

def monitor_cmd(args):
    """Monitor specific processes in real-time"""
    try:
        target_pids = []
        target_names = []
        
        if args.pid:
            target_pids.append(int(args.pid))
        elif args.name:
            target_names.append(args.name.lower())
        
        # Fixed line to handle the case when both args.pid and args.name are None
        if args.pid:
            monitoring_target = f"PID: {args.pid}"
        elif args.name:
            monitoring_target = f"Name: {args.name}"
        else:
            monitoring_target = "all processes"
            
        print(f"Starting focused monitoring on {monitoring_target}")
        print("Press Ctrl+C to stop monitoring")
        print("\nWaiting for activity...")
        
        # Initialize state
        last_state = {}
        
        try:
            while True:
                current_state = {}
                
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                    try:
                        pid = proc.pid
                        name = proc.name()
                        
                        # Filter by specified PID or name
                        if target_pids and pid not in target_pids:
                            continue
                        if target_names and not any(target.lower() in name.lower() for target in target_names):
                            continue
                        
                        # Store process state
                        current_state[pid] = {
                            'name': name,
                            'cpu_percent': proc.cpu_percent(interval=None),
                            'memory_percent': proc.memory_percent(),
                            'status': proc.status(),
                            'connections': len(proc.connections()) if hasattr(proc, 'connections') else 0,
                            'threads': proc.num_threads() if hasattr(proc, 'num_threads') else 0
                        }
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # Compare with previous state and report changes
                for pid, info in current_state.items():
                    if pid not in last_state:
                        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] NEW PROCESS: {info['name']} (PID: {pid})")
                        print(f"  CPU: {info['cpu_percent']:.1f}% | Memory: {info['memory_percent']:.1f}% | Status: {info['status']}")
                    else:
                        # Check for significant changes
                        old_info = last_state[pid]
                        if (abs(info['cpu_percent'] - old_info['cpu_percent']) > 10 or
                            abs(info['memory_percent'] - old_info['memory_percent']) > 2 or
                            info['status'] != old_info['status'] or
                            info['connections'] != old_info['connections']):
                            
                            print(f"\n[{datetime.now().strftime('%H:%M:%S')}] ACTIVITY: {info['name']} (PID: {pid})")
                            
                            if abs(info['cpu_percent'] - old_info['cpu_percent']) > 10:
                                print(f"  CPU: {old_info['cpu_percent']:.1f}% → {info['cpu_percent']:.1f}%")
                            
                            if abs(info['memory_percent'] - old_info['memory_percent']) > 2:
                                print(f"  Memory: {old_info['memory_percent']:.1f}% → {info['memory_percent']:.1f}%")
                            
                            if info['status'] != old_info['status']:
                                print(f"  Status: {old_info['status']} → {info['status']}")
                            
                            if info['connections'] != old_info['connections']:
                                print(f"  Connections: {old_info['connections']} → {info['connections']}")
                
                # Check for terminated processes
                for pid, info in last_state.items():
                    if pid not in current_state:
                        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] TERMINATED: {info['name']} (PID: {pid})")
                
                # Update last state
                last_state = current_state
                
                # If no matching processes found
                if not current_state and (target_pids or target_names):
                    if target_pids:
                        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] No process with PID {target_pids[0]} found")
                    elif target_names:
                        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] No process matching '{target_names[0]}' found")
                
                time.sleep(2)  # Refresh interval
        
        except KeyboardInterrupt:
            print("\nMonitoring stopped")
    
    except Exception as e:
        logging.error(f"Error in monitor_cmd: {e}")
        print(f"Error: {e}")

def quarantine_cmd(args):
    """List or restore quarantined files"""
    quarantine_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine")
    
    try:
        if not os.path.exists(quarantine_dir) or not os.listdir(quarantine_dir):
            print("No files in quarantine")
            return
        
        quarantined_files = sorted(os.listdir(quarantine_dir))
        
        if args.list or (not args.restore and not args.delete):
            # List quarantined files
            print("\n" + "=" * 80)
            print("QUARANTINED FILES")
            print("=" * 80 + "\n")
            
            headers = ['ID', 'Filename', 'Original Name', 'Quarantine Date', 'Type']
            rows = []
            
            for i, filename in enumerate(quarantined_files, 1):
                # Parse original name and timestamp from filename
                parts = filename.split('.')
                original_name = '.'.join(parts[:-2]) if len(parts) >= 3 else filename
                
                try:
                    timestamp = int(parts[-2]) if len(parts) >= 2 else 0
                    quarantine_date = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                except (ValueError, IndexError):
                    quarantine_date = 'Unknown'
                
                # Determine quarantine type
                if filename.endswith('.quarantine'):
                    q_type = 'Standard'
                elif filename.endswith('.nuked'):
                    q_type = 'Nuked'
                else:
                    q_type = 'Unknown'
                
                rows.append([i, filename, original_name, quarantine_date, q_type])
            
            print(tabulate(rows, headers=headers, tablefmt="grid"))
        
        elif args.restore:
            # Restore a quarantined file
            try:
                file_id = int(args.restore)
                if 1 <= file_id <= len(quarantined_files):
                    filename = quarantined_files[file_id - 1]
                    
                    # Extract original name
                    parts = filename.split('.')
                    original_name = '.'.join(parts[:-2]) if len(parts) >= 3 else filename
                    
                    # Ask for confirmation
                    print(f"You are about to restore: {filename}")
                    print(f"This file was quarantined for a reason and may be malicious!")
                    confirmation = input("Are you sure you want to restore this file? (y/N): ")
                    
                    if confirmation.lower() == 'y':
                        # Determine restore location
                        restore_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "restored")
                        if not os.path.exists(restore_dir):
                            os.makedirs(restore_dir)
                        
                        # Copy to restore location (don't move directly to original location for safety)
                        src_path = os.path.join(quarantine_dir, filename)
                        dst_path = os.path.join(restore_dir, original_name)
                        
                        shutil.copy2(src_path, dst_path)
                        print(f"File restored to: {dst_path}")
                        print("For safety, the original quarantined file has been preserved.")
                    else:
                        print("Restore operation cancelled")
                else:
                    print(f"Error: No quarantined file with ID {file_id}")
            except ValueError:
                print("Error: Restore ID must be a number")
        
        elif args.delete:
            # Delete a quarantined file
            try:
                file_id = int(args.delete)
                if 1 <= file_id <= len(quarantined_files):
                    filename = quarantined_files[file_id - 1]
                    
                    # Ask for confirmation
                    confirmation = input(f"Are you sure you want to permanently delete '{filename}'? (y/N): ")
                    
                    if confirmation.lower() == 'y':
                        os.remove(os.path.join(quarantine_dir, filename))
                        print(f"File '{filename}' has been permanently deleted from quarantine")
                    else:
                        print("Delete operation cancelled")
                else:
                    print(f"Error: No quarantined file with ID {file_id}")
            except ValueError:
                print("Error: Delete ID must be a number")
    
    except Exception as e:
        logging.error(f"Error in quarantine_cmd: {e}")
        print(f"Error: {e}")

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(description="proc-wolf Command Line Interface")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # List processes command
    list_parser = subparsers.add_parser("list", help="List processes")
    list_parser.add_argument("-f", "--filter", help="Filter processes by name")
    list_parser.add_argument("-s", "--sort", choices=["name", "cpu", "threat"], default="name", 
                            help="Sort processes by field")
    list_parser.add_argument("-l", "--limit", type=int, default=0, 
                            help="Limit number of processes displayed")
    list_parser.add_argument("-a", "--assess", action="store_true", 
                            help="Include threat assessment")
    
    # Kill process command
    kill_parser = subparsers.add_parser("kill", help="Kill a process")
    kill_parser.add_argument("-p", "--pid", help="Process ID to kill")
    kill_parser.add_argument("-n", "--name", help="Process name to kill")
    kill_parser.add_argument("-f", "--force", action="store_true", 
                            help="Force kill the process")
    
    # Assess threat command
    assess_parser = subparsers.add_parser("assess", help="Assess process threat level")
    assess_parser.add_argument("-p", "--pid", help="Process ID to assess")
    assess_parser.add_argument("-n", "--name", help="Process name to assess")
    
    # Nuke command
    nuke_parser = subparsers.add_parser("nuke", help="Complete removal of a process")
    nuke_parser.add_argument("-p", "--pid", help="Process ID to nuke")
    nuke_parser.add_argument("-n", "--name", help="Process name to nuke")
    nuke_parser.add_argument("-f", "--force", action="store_true", 
                            help="Skip confirmation")
    
    # History command
    history_parser = subparsers.add_parser("history", help="View process history")
    history_parser.add_argument("-p", "--pid", help="Get history for specific process ID")
    history_parser.add_argument("-n", "--name", help="Get history for processes matching name")
    history_parser.add_argument("-l", "--limit", type=int, default=10, 
                               help="Limit number of processes displayed")
    history_parser.add_argument("--nuked", action="store_true", 
                               help="Show history of nuked processes")
    
    # Monitor command
    monitor_parser = subparsers.add_parser("monitor", help="Monitor processes in real-time")
    monitor_parser.add_argument("-p", "--pid", type=int, help="Process ID to monitor")
    monitor_parser.add_argument("-n", "--name", help="Process name to monitor")
    
    # Quarantine command
    quarantine_parser = subparsers.add_parser("quarantine", help="Manage quarantined files")
    quarantine_parser.add_argument("-l", "--list", action="store_true", 
                                  help="List quarantined files")
    quarantine_parser.add_argument("-r", "--restore", help="Restore file by ID")
    quarantine_parser.add_argument("-d", "--delete", help="Delete file by ID")
    
    args = parser.parse_args()
    
    # Check for administrator privileges if necessary
    if args.command in ["kill", "nuke"] and not is_admin():
        print("Warning: Some operations require administrator privileges")
    
    # Execute command
    if args.command == "list":
        list_processes(args)
    elif args.command == "kill":
        kill_proc(args)
    elif args.command == "assess":
        assess_threat(args)
    elif args.command == "nuke":
        nuke_cmd(args)
    elif args.command == "history":
        history_cmd(args)
    elif args.command == "monitor":
        monitor_cmd(args)
    elif args.command == "quarantine":
        quarantine_cmd(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()