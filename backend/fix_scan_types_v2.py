import sqlite3

def fix_types_to_uppercase():
    print("=== Fixing Scan Types to Uppercase (Names) ===")
    conn = sqlite3.connect('matrix.db')
    cursor = conn.cursor()
    
    # Check what we have
    cursor.execute("SELECT scan_type, COUNT(*) FROM scans GROUP BY scan_type")
    print("Current distribution:", cursor.fetchall())
    
    # Update lowercase to uppercase
    print("Updating 'github_sast' -> 'GITHUB_SAST'...")
    cursor.execute("UPDATE scans SET scan_type='GITHUB_SAST' WHERE scan_type='github_sast'")
    conn.commit()
    print(f"Updated {cursor.rowcount} rows.")
    
    # Update 'full' to 'FULL' just in case
    cursor.execute("UPDATE scans SET scan_type='FULL' WHERE scan_type='full'")
    conn.commit()
    
    # Check result
    cursor.execute("SELECT scan_type, COUNT(*) FROM scans GROUP BY scan_type")
    print("New distribution:", cursor.fetchall())
    
    conn.close()

if __name__ == "__main__":
    fix_types_to_uppercase()
