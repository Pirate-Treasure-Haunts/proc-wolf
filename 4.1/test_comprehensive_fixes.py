#!/usr/bin/env python3
"""
Test script to verify proc_wolf v3.1.0 fixes
Tests comprehensive Windows process recognition
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from proc_wolf import (
    is_whitelisted,
    evaluate_threat_level,
    get_action_level,
    init_database,
    VERSION
)

try:
    from windows_processes import get_all_whitelisted_processes
    has_windows_module = True
except:
    has_windows_module = False

def test_critical_processes():
    """Test that critical Windows processes are properly whitelisted"""
    print("=" * 70)
    print("CRITICAL WINDOWS PROCESS TEST")
    print("=" * 70)
    
    critical_processes = [
        ('System Idle Process', 0, "Core Windows"),
        ('System', 4, "Core Windows"),
        ('MemCompression', 2772, "Memory Compression"),
        ('spoolsv.exe', 3796, "Print Spooler"),
        ('LsaIso.exe', 1348, "Credential Guard"),
        ('wlanext.exe', 6744, "WiFi Service"),
        ('WUDFHost.exe', 1572, "Driver Foundation"),
        ('MsMpEng.exe', 0, "Windows Defender"),
        ('NisSrv.exe', 0, "Network Inspection"),
        ('ctfmon.exe', 5140, "Text Input"),
        ('sihost.exe', 9304, "Shell Infrastructure"),
        ('dasHost.exe', 8212, "Device Association"),
        ('igfxEM.exe', 7964, "Intel Graphics"),
        ('ibmpmsvc.exe', 4312, "IBM Power Management"),
        ('LITSSvc.exe', 4336, "Lenovo IT Support"),
    ]
    
    all_pass = True
    for proc_name, pid, description in critical_processes:
        # Test with mock process info
        proc_info = {
            'pid': pid if pid else 1234,
            'name': proc_name,
            'path': f'C:\\Windows\\System32\\{proc_name}' if proc_name else '',
            'signed': True,
            'trusted': is_whitelisted(proc_name, f'C:\\Windows\\System32\\{proc_name}')
        }
        
        threat_level = evaluate_threat_level(proc_info)
        is_safe = threat_level == 0
        
        status = "✓ SAFE" if is_safe else f"✗ THREAT LEVEL {threat_level}"
        print(f"{proc_name:30} ({description:20}): {status}")
        
        if not is_safe:
            all_pass = False
    
    print(f"\nTest Result: {'PASSED ✓' if all_pass else 'FAILED ✗'}")
    return all_pass

def test_legitimate_software():
    """Test that legitimate third-party software is recognized"""
    print("\n" + "=" * 70)
    print("LEGITIMATE SOFTWARE TEST")
    print("=" * 70)
    
    legitimate_apps = [
        ('vivaldi.exe', 'Vivaldi Browser'),
        ('Dropbox.exe', 'Dropbox'),
        ('ProtonVPN.exe', 'ProtonVPN'),
        ('ProtonVPNService.exe', 'ProtonVPN Service'),
        ('OneDrive.exe', 'OneDrive'),
        ('Discord.exe', 'Discord'),
        ('ProcWolf.exe', 'Proc-Wolf Itself!'),
        ('ProcWolfService.exe', 'Proc-Wolf Service'),
    ]
    
    all_pass = True
    for app_name, description in legitimate_apps:
        # Test with typical program files path
        path = f'C:\\Program Files\\{app_name.replace(".exe", "")}\\{app_name}'
        
        proc_info = {
            'pid': 5000,
            'name': app_name,
            'path': path,
            'signed': False,  # Many apps aren't signed
            'trusted': is_whitelisted(app_name, path)
        }
        
        threat_level = evaluate_threat_level(proc_info)
        action = get_action_level(threat_level, 0)  # First warning
        
        is_safe = threat_level <= 1 and action == 0  # LOW threat or less, MONITOR action
        
        status = f"✓ Threat={threat_level}, Action={action}" if is_safe else f"✗ Threat={threat_level}, Action={action}"
        print(f"{app_name:25} ({description:20}): {status}")
        
        if not is_safe:
            all_pass = False
    
    print(f"\nTest Result: {'PASSED ✓' if all_pass else 'FAILED ✗'}")
    return all_pass

def test_action_levels():
    """Test that action levels are conservative"""
    print("\n" + "=" * 70)
    print("ACTION LEVEL CONSERVATISM TEST")
    print("=" * 70)
    
    test_cases = [
        (0, 0, 0, "TRUSTED, no warnings"),      # Should always be MONITOR
        (1, 0, 0, "LOW threat, no warnings"),    # Should be MONITOR
        (1, 10, 0, "LOW threat, 10 warnings"),   # Should still be MONITOR
        (2, 5, 0, "MEDIUM threat, 5 warnings"),  # Should be MONITOR (needs 10+)
        (2, 15, 1, "MEDIUM threat, 15 warnings"), # Should be WARN
        (2, 25, 2, "MEDIUM threat, 25 warnings"), # Should be KILL
        (3, 2, 1, "HIGH threat, 2 warnings"),    # Should be WARN
        (4, 1, 2, "CRITICAL threat, 1 warning"), # Should be KILL (not NUKE)
    ]
    
    all_pass = True
    for threat_level, warnings, expected_action, description in test_cases:
        actual_action = get_action_level(threat_level, warnings)
        passed = actual_action == expected_action
        
        actions = ["MONITOR", "WARN", "KILL", "QUARANTINE", "NUKE"]
        status = "✓" if passed else "✗"
        print(f"{status} {description:35} -> Expected: {actions[expected_action]:10} Got: {actions[actual_action]}")
        
        if not passed:
            all_pass = False
    
    print(f"\nTest Result: {'PASSED ✓' if all_pass else 'FAILED ✗'}")
    return all_pass

def test_database_init():
    """Test database initialization with schema migration"""
    print("\n" + "=" * 70)
    print("DATABASE INITIALIZATION TEST")
    print("=" * 70)
    
    try:
        print("Initializing database...")
        db = init_database()
        
        # Test some specific processes
        test_procs = [
            'ProcWolfService.exe',
            'vivaldi.exe',
            'MemCompression',
            'MsMpEng.exe',
            'Dropbox.exe'
        ]
        
        print("\nChecking whitelist status:")
        for proc in test_procs:
            whitelisted = db.is_whitelisted(proc)
            status = "✓ WHITELISTED" if whitelisted else "✗ NOT WHITELISTED"
            print(f"  {proc:25}: {status}")
        
        # Get stats
        whitelist = db.get_whitelist()
        print(f"\nDatabase contains {len(whitelist)} whitelisted entries")
        
        # Test database schema (times_seen column)
        cursor = db.conn.cursor()
        try:
            cursor.execute("SELECT times_seen FROM process_history LIMIT 1")
            print("✓ Database schema includes 'times_seen' column")
            schema_ok = True
        except:
            print("✗ Database schema missing 'times_seen' column")
            schema_ok = False
        
        db.close()
        
        print(f"\nTest Result: {'PASSED ✓' if schema_ok else 'FAILED ✗'}")
        return schema_ok
        
    except Exception as e:
        print(f"✗ Database test FAILED: {e}")
        return False

def main():
    print("\n" + "=" * 70)
    print(f"PROC-WOLF v{VERSION} COMPREHENSIVE FIX VERIFICATION")
    print("=" * 70)
    
    print(f"\nWindows process module available: {'YES ✓' if has_windows_module else 'NO (using fallback)'}")
    
    # Run all tests
    results = []
    results.append(("Critical Windows Processes", test_critical_processes()))
    results.append(("Legitimate Software", test_legitimate_software()))
    results.append(("Conservative Action Levels", test_action_levels()))
    results.append(("Database Initialization", test_database_init()))
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    all_passed = True
    for test_name, passed in results:
        status = "✓ PASSED" if passed else "✗ FAILED"
        print(f"{test_name:30}: {status}")
        if not passed:
            all_passed = False
    
    print("\n" + "=" * 70)
    if all_passed:
        print("ALL TESTS PASSED! ✓")
        print("\nThe service is now SAFE to run:")
        print("• Windows system processes are protected")
        print("• Legitimate software won't be killed")
        print("• Action levels are very conservative")
        print("• Proc-Wolf won't attack itself")
        print("• Database schema is correct")
    else:
        print("SOME TESTS FAILED! ✗")
        print("\nDO NOT run the service until all tests pass!")
    print("=" * 70)

if __name__ == "__main__":
    main()
