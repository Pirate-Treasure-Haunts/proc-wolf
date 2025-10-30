#!/usr/bin/env python3
"""
Database Migration Script for proc_wolf
Fixes schema mismatch between old and new versions
"""

import sqlite3
import os
import shutil
from datetime import datetime

def backup_database(db_path):
    """Create a backup before migration"""
    backup_path = db_path + f'.backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
    shutil.copy2(db_path, backup_path)
    print(f"✓ Database backed up to: {backup_path}")
    return backup_path

def migrate_database():
    """Migrate the old database schema to the new one"""
    db_path = r'C:\ProgramData\proc-wolf\proc-wolf.db'
    
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        return False
    
    # Backup first
    backup_path = backup_database(db_path)
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        print("\n" + "=" * 70)
        print("DATABASE MIGRATION")
        print("=" * 70)
        
        # Check current schema
        cursor.execute("PRAGMA table_info(process_history)")
        columns = cursor.fetchall()
        column_names = [col[1] for col in columns]
        
        print(f"\nCurrent columns: {column_names}")
        
        if 'pid' not in column_names:
            print("\nMigrating process_history table to new schema...")
            
            # Step 1: Rename old table
            cursor.execute("ALTER TABLE process_history RENAME TO process_history_old")
            print("  ✓ Renamed old table")
            
            # Step 2: Create new table with correct schema
            cursor.execute("""
                CREATE TABLE process_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pid INTEGER,
                    name TEXT,
                    path TEXT,
                    command_line TEXT,
                    hash TEXT,
                    parent_pid INTEGER,
                    username TEXT,
                    create_time REAL,
                    threat_level INTEGER,
                    trusted BOOLEAN,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    times_seen INTEGER DEFAULT 1,
                    UNIQUE(pid, name, path)
                )
            """)
            print("  ✓ Created new table with correct schema")
            
            # Step 3: Migrate data from old table
            cursor.execute("""
                INSERT INTO process_history 
                (name, path, command_line, hash, threat_level, trusted, first_seen, last_seen, times_seen)
                SELECT 
                    name, 
                    path, 
                    cmd_line as command_line,
                    hash,
                    threat_level,
                    trusted,
                    first_seen,
                    last_seen,
                    times_seen
                FROM process_history_old
            """)
            migrated_rows = cursor.rowcount
            print(f"  ✓ Migrated {migrated_rows} rows from old table")
            
            # Step 4: Drop old table
            cursor.execute("DROP TABLE process_history_old")
            print("  ✓ Removed old table")
            
            # Step 5: Also check and update other tables if needed
            
            # Fix resurrections table if it exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='resurrections'")
            if cursor.fetchone():
                print("\nMigrating resurrections table...")
                cursor.execute("ALTER TABLE resurrections RENAME TO resurrections_old")
                # The new schema doesn't use resurrections table, so we can just drop it
                cursor.execute("DROP TABLE resurrections_old")
                print("  ✓ Removed obsolete resurrections table")
            
            # Fix nuked_processes table if it exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='nuked_processes'")
            if cursor.fetchone():
                print("\nMigrating nuked_processes table...")
                # Rename to match new schema name
                cursor.execute("ALTER TABLE nuked_processes RENAME TO nuke_operations_old")
                
                # Ensure nuke_operations table exists with correct schema
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS nuke_operations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        process_id INTEGER,
                        process_name TEXT,
                        process_path TEXT,
                        artifacts_removed INTEGER,
                        registry_keys_removed INTEGER,
                        service_removed BOOLEAN,
                        success BOOLEAN,
                        FOREIGN KEY (process_id) REFERENCES process_history(id)
                    )
                """)
                
                # Migrate data
                cursor.execute("""
                    INSERT OR IGNORE INTO nuke_operations 
                    (timestamp, process_id, process_name, process_path, 
                     artifacts_removed, registry_keys_removed, service_removed, success)
                    SELECT 
                        timestamp, process_id, name, path,
                        artifacts_removed, registry_keys_removed, service_removed, success
                    FROM nuke_operations_old
                """)
                
                cursor.execute("DROP TABLE nuke_operations_old")
                print("  ✓ Migrated nuke operations table")
            
            conn.commit()
            print("\n✓ DATABASE MIGRATION COMPLETE!")
            print(f"  Old database backed up to: {backup_path}")
            print("  New schema is ready for use")
            
        else:
            print("\n✓ Database already has correct schema (pid column exists)")
        
        # Verify final schema
        print("\nVerifying final schema:")
        cursor.execute("PRAGMA table_info(process_history)")
        columns = cursor.fetchall()
        column_names = [col[1] for col in columns]
        print(f"  Columns: {column_names}")
        
        if 'pid' in column_names:
            print("  ✓ Schema verification PASSED")
        else:
            print("  ✗ Schema verification FAILED")
            return False
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"\n✗ Migration failed: {e}")
        print(f"  Restore from backup if needed: {backup_path}")
        return False

def verify_migration():
    """Test that the migration worked"""
    db_path = r'C:\ProgramData\proc-wolf\proc-wolf.db'
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        print("\n" + "=" * 70)
        print("VERIFICATION")
        print("=" * 70)
        
        # Test insert with new schema
        test_data = (
            1234,  # pid
            'test_process.exe',  # name
            'C:\\test\\test.exe',  # path
            'test.exe --test',  # command_line
            'abc123',  # hash
            1000,  # parent_pid
            'test_user',  # username
            123456789.0,  # create_time
            0,  # threat_level
            1  # trusted
        )
        
        cursor.execute("""
            INSERT OR REPLACE INTO process_history 
            (pid, name, path, command_line, hash, parent_pid, username, 
             create_time, threat_level, trusted)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, test_data)
        
        # Test select
        cursor.execute("SELECT * FROM process_history WHERE pid = 1234")
        result = cursor.fetchone()
        
        if result:
            print("  ✓ Test insert/select successful")
            
            # Clean up test data
            cursor.execute("DELETE FROM process_history WHERE pid = 1234")
            conn.commit()
            print("  ✓ Test data cleaned up")
        else:
            print("  ✗ Test insert/select failed")
            return False
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"  ✗ Verification failed: {e}")
        return False

def main():
    print("=" * 70)
    print("PROC-WOLF DATABASE MIGRATION SCRIPT")
    print("=" * 70)
    print("\nThis will migrate your database from the old schema to the new one.")
    print("A backup will be created automatically.")
    
    response = input("\nProceed with migration? (yes/no): ")
    if response.lower() != 'yes':
        print("Migration cancelled.")
        return
    
    # Run migration
    if migrate_database():
        # Verify it worked
        if verify_migration():
            print("\n" + "=" * 70)
            print("SUCCESS!")
            print("=" * 70)
            print("\nYour database has been successfully migrated.")
            print("The service should now run without database errors.")
            print("\nYou can now:")
            print("1. Rebuild the service: python build_exe.py")
            print("2. Run in debug mode: .\\ProcWolfService.exe debug")
            print("3. Install the service: .\\install.bat")
        else:
            print("\n⚠️ Migration completed but verification failed.")
            print("Check the logs and restore from backup if needed.")
    else:
        print("\n✗ Migration failed. Your original database is unchanged.")
        print("A backup was created if you need to restore.")

if __name__ == "__main__":
    main()
