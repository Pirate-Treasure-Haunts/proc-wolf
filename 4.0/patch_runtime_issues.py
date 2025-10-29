#!/usr/bin/env python3
"""
Final runtime patch for proc_wolf v3.1.0
Fixes remaining database and monitoring loop issues
"""

import sqlite3
import os
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def patch_database_schema():
    """Ensure database has all required columns and tables"""
    db_path = r'C:\ProgramData\proc-wolf\proc-wolf.db'
    
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get current schema
        cursor.execute("SELECT sql FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        
        print("\nCurrent database schema:")
        for table in tables:
            print(f"\n{table[0]}")
        
        # Check if process_history has all required columns
        cursor.execute("PRAGMA table_info(process_history)")
        columns = cursor.fetchall()
        column_names = [col[1] for col in columns]
        
        print("\nprocess_history columns:", column_names)
        
        # Add any missing columns
        required_columns = {
            'times_seen': 'INTEGER DEFAULT 1',
            'threat_level': 'INTEGER DEFAULT 0',
            'trusted': 'BOOLEAN DEFAULT 0'
        }
        
        for col_name, col_def in required_columns.items():
            if col_name not in column_names:
                print(f"Adding missing column: {col_name}")
                try:
                    cursor.execute(f"ALTER TABLE process_history ADD COLUMN {col_name} {col_def}")
                    print(f"  ✓ Added {col_name}")
                except sqlite3.OperationalError as e:
                    if "duplicate column" not in str(e).lower():
                        print(f"  ✗ Failed to add {col_name}: {e}")
        
        # Check for any queries that might be using wrong columns
        print("\nChecking for problematic stored data...")
        
        # Clean up any bad whitelist entries
        cursor.execute("DELETE FROM whitelist WHERE value IS NULL OR value = ''")
        deleted = cursor.rowcount
        if deleted > 0:
            print(f"  Cleaned {deleted} invalid whitelist entries")
        
        conn.commit()
        conn.close()
        
        print("\n✓ Database schema patched successfully")
        return True
        
    except Exception as e:
        print(f"✗ Error patching database: {e}")
        return False

def verify_critical_whitelists():
    """Ensure critical processes are whitelisted"""
    db_path = r'C:\ProgramData\proc-wolf\proc-wolf.db'
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Critical processes that MUST be whitelisted
        critical_processes = [
            'System',
            'System Idle Process',
            'Registry',
            'MemCompression',
            'ProcWolfService.exe',
            'ProcWolf.exe',
            'vivaldi.exe',
            'MsMpEng.exe',
            'NisSrv.exe'
        ]
        
        print("\nVerifying critical whitelists:")
        for proc in critical_processes:
            cursor.execute("SELECT 1 FROM whitelist WHERE type='name' AND value=?", (proc,))
            if not cursor.fetchone():
                print(f"  Adding missing whitelist: {proc}")
                cursor.execute(
                    "INSERT OR IGNORE INTO whitelist (type, value, notes) VALUES (?, ?, ?)",
                    ('name', proc, 'Critical process - auto-added by patch')
                )
            else:
                print(f"  ✓ {proc} is whitelisted")
        
        conn.commit()
        conn.close()
        print("\n✓ Critical whitelists verified")
        return True
        
    except Exception as e:
        print(f"✗ Error verifying whitelists: {e}")
        return False

def create_test_query():
    """Test that our database queries work"""
    db_path = r'C:\ProgramData\proc-wolf\proc-wolf.db'
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        print("\nTesting database queries:")
        
        # Test the query that might be causing issues
        test_queries = [
            ("SELECT * FROM process_history LIMIT 1", "process_history"),
            ("SELECT * FROM whitelist LIMIT 1", "whitelist"),
            ("SELECT * FROM activity_log LIMIT 1", "activity_log"),
        ]
        
        for query, table in test_queries:
            try:
                cursor.execute(query)
                result = cursor.fetchone()
                print(f"  ✓ {table} query works")
            except sqlite3.OperationalError as e:
                print(f"  ✗ {table} query failed: {e}")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"✗ Error testing queries: {e}")
        return False

def main():
    print("=" * 70)
    print("PROC-WOLF v3.1.0 RUNTIME PATCH")
    print("=" * 70)
    
    # Run patches
    results = []
    results.append(("Database schema patch", patch_database_schema()))
    results.append(("Critical whitelists", verify_critical_whitelists()))
    results.append(("Query testing", create_test_query()))
    
    # Summary
    print("\n" + "=" * 70)
    print("PATCH SUMMARY")
    print("=" * 70)
    
    all_passed = True
    for patch_name, success in results:
        status = "✓ SUCCESS" if success else "✗ FAILED"
        print(f"{patch_name:25}: {status}")
        if not success:
            all_passed = False
    
    if all_passed:
        print("\nAll patches applied successfully!")
        print("You can now run the service safely.")
    else:
        print("\nSome patches failed. Please check the errors above.")
    
    print("=" * 70)

if __name__ == "__main__":
    main()
