import sqlite3

def check_tables():
    db_file = 'matrix.db'
    print(f"\n--- Checking {db_file} ---")
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        tables = cursor.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        print(f"Tables: {tables}")
        
        if ('scans',) in tables or ('scans',) in [t for t in tables]:
            scan = cursor.execute("SELECT id, status, created_at, target_url FROM scans ORDER BY created_at DESC LIMIT 1").fetchone()
            print(f"Latest scan: {scan}")
            
        conn.close()
    except Exception as e:
        print(f"Error checking {db_file}: {e}")



if __name__ == "__main__":
    check_tables()
